/*
Threat model for Shield Vault core:

- Attacker controls the relay server: the server sees only ciphertext,
  public keys, encrypted key envelopes, opaque authentication records, and
  operational metadata. It must never receive vault plaintext, master
  passwords, master keys, or unwrapped vault keys.
- Attacker controls the network: all client/server connections must use TLS,
  and peer-to-peer sync must use authenticated encrypted transports such as
  Noise over libp2p.
- Attacker compromises one device: that device's local key material and
  decrypted vault contents may be exposed, but other devices' private keys
  must not be derivable from it.
- Admin removes a user: future epochs are sealed by rekeying, but past data
  the removed user already decrypted cannot be cryptographically erased from
  their memory or backups.
- Weak master password: Argon2id raises the cost of offline guessing but
  cannot compensate for passwords such as "password1". Users need honest
  password-strength guidance.
- Browser extension compromise: this is the highest-risk client surface.
  The extension must minimize permissions, avoid remote code, and enforce a
  strict content security policy.
*/

//! Production crypto engine for Shield Vault.
//!
//! Shipping cryptographic operations use audited crates and must not depend on
//! the educational implementations in `crypto-lab`.

use std::fmt;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use libsodium_rs::crypto_secretstream::xchacha20poly1305::{Key, PullState, PushState, TAG_FINAL};
use libsodium_rs::{ensure_init, random};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, Ristretto255, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub const VAULT_ID_BYTES: usize = 16;
pub const ITEM_ID_BYTES: usize = 16;
pub const SECRETSTREAM_HEADER_BYTES: usize = 24;
pub const VAULT_KEY_BYTES: usize = 32;
pub const KDF_SALT_BYTES: usize = 16;
pub const FORMAT_VERSION_V1: u16 = 1;
pub const ALGO_SUITE_V1: &str =
    "shield_vault.local-vault.v1.argon2id.secretstream-xchacha20poly1305";
pub const KDF_ARGON2ID_V19: &str = "argon2id-v19";

const MAGIC: [u8; 4] = *b"SVLT";
const DEFAULT_KDF_MEMORY_KIB: u32 = 65_536;
const DEFAULT_KDF_PASSES: u32 = 3;
const DEFAULT_KDF_PARALLELISM: u32 = 4;

pub type VaultId = [u8; VAULT_ID_BYTES];
pub type ItemId = [u8; ITEM_ID_BYTES];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    UnsupportedFormat,
    UnsupportedAlgorithm,
    UnsupportedKdf,
    UnsupportedKdfParams,
    InvalidPasswordOrCiphertext,
    InvalidVaultKey,
    VaultMismatch,
    Storage,
    Opaque,
    Serialization,
    Crypto,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultHeaderV1 {
    pub magic: [u8; 4],
    pub format_version: u16,
    pub algo_suite: String,
    pub vault_id: VaultId,
    pub created_at_ms: u64,
    pub kdf: String,
    pub kdf_memory_kib: u32,
    pub kdf_passes: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt: [u8; KDF_SALT_BYTES],
    pub vault_key_envelope_header: [u8; SECRETSTREAM_HEADER_BYTES],
    pub vault_key_envelope_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultItemRecordV1 {
    pub format_version: u16,
    pub algo_suite: String,
    pub vault_id: VaultId,
    pub item_id: ItemId,
    pub item_version: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deleted_at_ms: Option<u64>,
    pub secretstream_header: [u8; SECRETSTREAM_HEADER_BYTES],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustomFieldV1 {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for CustomFieldV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFieldV1")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct VaultItemPayloadV1 {
    pub title: String,
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: String,
    pub custom_fields: Vec<CustomFieldV1>,
    pub totp_secret: Option<String>,
}

impl fmt::Debug for VaultItemPayloadV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultItemPayloadV1")
            .field("title", &self.title)
            .field("username", &"<redacted>")
            .field("password", &"<redacted>")
            .field("urls", &self.urls)
            .field("notes", &"<redacted>")
            .field("custom_fields", &"<redacted>")
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Clone)]
pub struct UnlockedVault {
    header: VaultHeaderV1,
    vault_key: Key,
}

impl UnlockedVault {
    pub fn header(&self) -> &VaultHeaderV1 {
        &self.header
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("header", &self.header)
            .field("vault_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct LocalDbKey([u8; VAULT_KEY_BYTES]);

impl LocalDbKey {
    pub fn generate() -> Result<Self, Error> {
        ensure_init().map_err(|_| Error::Crypto)?;
        let mut bytes = [0u8; VAULT_KEY_BYTES];
        random::fill_bytes(&mut bytes);
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; VAULT_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; VAULT_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for LocalDbKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalDbKey").field(&"<redacted>").finish()
    }
}

pub struct LocalVaultStore {
    conn: Connection,
}

impl fmt::Debug for LocalVaultStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalVaultStore").finish_non_exhaustive()
    }
}

struct ShieldVaultOpaqueSuite;

impl CipherSuite for ShieldVaultOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

pub struct OpaqueRegistrationResult {
    pub password_file: Vec<u8>,
    pub export_key: Vec<u8>,
}

impl fmt::Debug for OpaqueRegistrationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueRegistrationResult")
            .field("password_file", &"<redacted>")
            .field("export_key", &"<redacted>")
            .finish()
    }
}

pub struct OpaqueLoginResult {
    pub client_session_key: Vec<u8>,
    pub server_session_key: Vec<u8>,
}

impl fmt::Debug for OpaqueLoginResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueLoginResult")
            .field("client_session_key", &"<redacted>")
            .field("server_session_key", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct VaultKeyEnvelopeAadV1 {
    context: String,
    algo_suite: String,
    vault_id: VaultId,
    kdf: String,
    kdf_memory_kib: u32,
    kdf_passes: u32,
    kdf_parallelism: u32,
    kdf_salt: [u8; KDF_SALT_BYTES],
}

#[derive(Serialize)]
struct VaultItemAadV1 {
    context: String,
    algo_suite: String,
    vault_id: VaultId,
    item_id: ItemId,
    item_version: u64,
    deleted: bool,
}

pub fn create_vault(
    master_password: &[u8],
    vault_id: VaultId,
    created_at_ms: u64,
) -> Result<UnlockedVault, Error> {
    ensure_init().map_err(|_| Error::Crypto)?;

    let vault_key = Key::generate();
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    random::fill_bytes(&mut kdf_salt);

    let mut header = VaultHeaderV1 {
        magic: MAGIC,
        format_version: FORMAT_VERSION_V1,
        algo_suite: ALGO_SUITE_V1.to_owned(),
        vault_id,
        created_at_ms,
        kdf: KDF_ARGON2ID_V19.to_owned(),
        kdf_memory_kib: DEFAULT_KDF_MEMORY_KIB,
        kdf_passes: DEFAULT_KDF_PASSES,
        kdf_parallelism: DEFAULT_KDF_PARALLELISM,
        kdf_salt,
        vault_key_envelope_header: [0; SECRETSTREAM_HEADER_BYTES],
        vault_key_envelope_ciphertext: Vec::new(),
    };

    let envelope_key = derive_key_encryption_key(master_password, &header)?;
    let envelope_aad = vault_key_envelope_aad_bytes(&header)?;
    let (mut push_state, envelope_header) =
        PushState::init_push(&envelope_key).map_err(|_| Error::Crypto)?;
    let envelope_ciphertext = push_state
        .push(vault_key.as_bytes(), Some(&envelope_aad), TAG_FINAL)
        .map_err(|_| Error::Crypto)?;

    header.vault_key_envelope_header = envelope_header;
    header.vault_key_envelope_ciphertext = envelope_ciphertext;

    Ok(UnlockedVault { header, vault_key })
}

pub fn unlock_vault(
    master_password: &[u8],
    header: &VaultHeaderV1,
) -> Result<UnlockedVault, Error> {
    validate_header(header)?;
    ensure_init().map_err(|_| Error::Crypto)?;

    let envelope_key = derive_key_encryption_key(master_password, header)?;
    let envelope_aad = vault_key_envelope_aad_bytes(header)?;
    let mut pull_state = PullState::init_pull(&header.vault_key_envelope_header, &envelope_key)
        .map_err(|_| Error::InvalidPasswordOrCiphertext)?;
    let (vault_key_bytes, tag) = pull_state
        .pull(&header.vault_key_envelope_ciphertext, Some(&envelope_aad))
        .map_err(|_| Error::InvalidPasswordOrCiphertext)?;

    if tag != TAG_FINAL {
        return Err(Error::InvalidPasswordOrCiphertext);
    }

    let vault_key = Key::from_bytes(&vault_key_bytes).map_err(|_| Error::InvalidVaultKey)?;

    Ok(UnlockedVault {
        header: header.clone(),
        vault_key,
    })
}

pub fn encrypt_item(
    vault: &UnlockedVault,
    item_id: ItemId,
    item_version: u64,
    created_at_ms: u64,
    updated_at_ms: u64,
    deleted_at_ms: Option<u64>,
    payload: &VaultItemPayloadV1,
) -> Result<VaultItemRecordV1, Error> {
    let payload_bytes = bcs::to_bytes(payload).map_err(|_| Error::Serialization)?;
    let deleted = deleted_at_ms.is_some();
    let aad = vault_item_aad_bytes(vault.header.vault_id, item_id, item_version, deleted)?;

    let (mut push_state, secretstream_header) =
        PushState::init_push(&vault.vault_key).map_err(|_| Error::Crypto)?;
    let ciphertext = push_state
        .push(&payload_bytes, Some(&aad), TAG_FINAL)
        .map_err(|_| Error::Crypto)?;

    Ok(VaultItemRecordV1 {
        format_version: FORMAT_VERSION_V1,
        algo_suite: ALGO_SUITE_V1.to_owned(),
        vault_id: vault.header.vault_id,
        item_id,
        item_version,
        created_at_ms,
        updated_at_ms,
        deleted_at_ms,
        secretstream_header,
        ciphertext,
    })
}

pub fn decrypt_item(
    vault: &UnlockedVault,
    record: &VaultItemRecordV1,
) -> Result<VaultItemPayloadV1, Error> {
    validate_item_record(vault, record)?;

    let aad = vault_item_aad_bytes(
        record.vault_id,
        record.item_id,
        record.item_version,
        record.deleted_at_ms.is_some(),
    )?;
    let mut pull_state = PullState::init_pull(&record.secretstream_header, &vault.vault_key)
        .map_err(|_| Error::InvalidPasswordOrCiphertext)?;
    let (payload_bytes, tag) = pull_state
        .pull(&record.ciphertext, Some(&aad))
        .map_err(|_| Error::InvalidPasswordOrCiphertext)?;

    if tag != TAG_FINAL {
        return Err(Error::InvalidPasswordOrCiphertext);
    }

    bcs::from_bytes(&payload_bytes).map_err(|_| Error::Serialization)
}

pub fn opaque_create_server_setup() -> Result<Vec<u8>, Error> {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<ShieldVaultOpaqueSuite>::new(&mut rng);
    Ok(server_setup.serialize().to_vec())
}

pub fn opaque_register(
    password: &[u8],
    credential_identifier: &[u8],
    server_setup_bytes: &[u8],
) -> Result<OpaqueRegistrationResult, Error> {
    let mut rng = OsRng;
    let server_setup = ServerSetup::<ShieldVaultOpaqueSuite>::deserialize(server_setup_bytes)
        .map_err(|_| Error::Opaque)?;
    let client_start = ClientRegistration::<ShieldVaultOpaqueSuite>::start(&mut rng, password)
        .map_err(|_| Error::Opaque)?;
    let server_start = ServerRegistration::<ShieldVaultOpaqueSuite>::start(
        &server_setup,
        client_start.message,
        credential_identifier,
    )
    .map_err(|_| Error::Opaque)?;
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            server_start.message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| Error::Opaque)?;
    let password_file = ServerRegistration::<ShieldVaultOpaqueSuite>::finish(client_finish.message);

    Ok(OpaqueRegistrationResult {
        password_file: password_file.serialize().to_vec(),
        export_key: client_finish.export_key.to_vec(),
    })
}

pub fn opaque_login(
    password: &[u8],
    credential_identifier: &[u8],
    server_setup_bytes: &[u8],
    password_file_bytes: &[u8],
) -> Result<OpaqueLoginResult, Error> {
    let password_file =
        ServerRegistration::<ShieldVaultOpaqueSuite>::deserialize(password_file_bytes)
            .map_err(|_| Error::Opaque)?;
    opaque_login_with_password_file(
        password,
        credential_identifier,
        server_setup_bytes,
        Some(password_file),
    )
}

pub fn opaque_login_missing_account(
    password: &[u8],
    credential_identifier: &[u8],
    server_setup_bytes: &[u8],
) -> Result<OpaqueLoginResult, Error> {
    opaque_login_with_password_file(password, credential_identifier, server_setup_bytes, None)
}

fn opaque_login_with_password_file(
    password: &[u8],
    credential_identifier: &[u8],
    server_setup_bytes: &[u8],
    password_file: Option<ServerRegistration<ShieldVaultOpaqueSuite>>,
) -> Result<OpaqueLoginResult, Error> {
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<ShieldVaultOpaqueSuite>::deserialize(server_setup_bytes)
        .map_err(|_| Error::Opaque)?;
    let client_start = ClientLogin::<ShieldVaultOpaqueSuite>::start(&mut client_rng, password)
        .map_err(|_| Error::Opaque)?;
    let server_start = ServerLogin::start(
        &mut server_rng,
        &server_setup,
        password_file,
        client_start.message,
        credential_identifier,
        ServerLoginParameters::default(),
    )
    .map_err(|_| Error::Opaque)?;
    let client_finish = client_start
        .state
        .finish(
            &mut client_rng,
            password,
            server_start.message,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| Error::Opaque)?;
    let server_finish = server_start
        .state
        .finish(client_finish.message, ServerLoginParameters::default())
        .map_err(|_| Error::Opaque)?;

    Ok(OpaqueLoginResult {
        client_session_key: client_finish.session_key.to_vec(),
        server_session_key: server_finish.session_key.to_vec(),
    })
}

impl LocalVaultStore {
    pub fn open(path: impl AsRef<Path>, key: &LocalDbKey) -> Result<Self, Error> {
        let conn = Connection::open(path).map_err(|_| Error::Storage)?;
        key_sqlcipher_connection(&conn, key)?;
        Ok(Self { conn })
    }

    pub fn init_schema(&self) -> Result<(), Error> {
        self.conn
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS metadata (
                  key TEXT PRIMARY KEY,
                  value BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_headers (
                  vault_id BLOB PRIMARY KEY,
                  format_version INTEGER NOT NULL,
                  header_bcs BLOB NOT NULL,
                  created_at_ms INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS vault_items (
                  vault_id BLOB NOT NULL,
                  item_id BLOB NOT NULL,
                  item_version INTEGER NOT NULL,
                  record_bcs BLOB NOT NULL,
                  updated_at_ms INTEGER NOT NULL,
                  deleted_at_ms INTEGER,
                  PRIMARY KEY (vault_id, item_id, item_version),
                  FOREIGN KEY (vault_id) REFERENCES vault_headers(vault_id)
                );

                CREATE INDEX IF NOT EXISTS vault_items_latest_idx
                  ON vault_items(vault_id, item_id, item_version DESC);
                ",
            )
            .map_err(|_| Error::Storage)
    }

    pub fn put_vault_header(&self, header: &VaultHeaderV1) -> Result<(), Error> {
        let header_bcs = bcs::to_bytes(header).map_err(|_| Error::Serialization)?;
        self.conn
            .execute(
                "
                INSERT OR REPLACE INTO vault_headers
                  (vault_id, format_version, header_bcs, created_at_ms)
                VALUES (?1, ?2, ?3, ?4)
                ",
                params![
                    header.vault_id.as_slice(),
                    i64::from(header.format_version),
                    header_bcs,
                    u64_to_i64(header.created_at_ms)?,
                ],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    pub fn get_vault_header(&self, vault_id: VaultId) -> Result<Option<VaultHeaderV1>, Error> {
        let header_bcs = self
            .conn
            .query_row(
                "SELECT header_bcs FROM vault_headers WHERE vault_id = ?1",
                params![vault_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;

        header_bcs
            .map(|bytes| bcs::from_bytes(&bytes).map_err(|_| Error::Serialization))
            .transpose()
    }

    pub fn put_item_record(&self, record: &VaultItemRecordV1) -> Result<(), Error> {
        let record_bcs = bcs::to_bytes(record).map_err(|_| Error::Serialization)?;
        self.conn
            .execute(
                "
                INSERT OR REPLACE INTO vault_items
                  (vault_id, item_id, item_version, record_bcs, updated_at_ms, deleted_at_ms)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ",
                params![
                    record.vault_id.as_slice(),
                    record.item_id.as_slice(),
                    u64_to_i64(record.item_version)?,
                    record_bcs,
                    u64_to_i64(record.updated_at_ms)?,
                    record.deleted_at_ms.map(u64_to_i64).transpose()?,
                ],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    pub fn get_item_record(
        &self,
        vault_id: VaultId,
        item_id: ItemId,
        item_version: u64,
    ) -> Result<Option<VaultItemRecordV1>, Error> {
        let record_bcs = self
            .conn
            .query_row(
                "
                SELECT record_bcs FROM vault_items
                WHERE vault_id = ?1 AND item_id = ?2 AND item_version = ?3
                ",
                params![
                    vault_id.as_slice(),
                    item_id.as_slice(),
                    u64_to_i64(item_version)?,
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;

        record_bcs
            .map(|bytes| bcs::from_bytes(&bytes).map_err(|_| Error::Serialization))
            .transpose()
    }
}

fn key_sqlcipher_connection(conn: &Connection, key: &LocalDbKey) -> Result<(), Error> {
    let key_hex = hex_encode(key.as_bytes());
    let pragma_key = format!("PRAGMA key = \"x'{key_hex}'\";");

    conn.execute_batch(&pragma_key)
        .map_err(|_| Error::Storage)?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| Error::Storage)?;
    conn.execute_batch(
        "
        PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        ",
    )
    .map_err(|_| Error::Storage)?;

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn u64_to_i64(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::Storage)
}

fn validate_header(header: &VaultHeaderV1) -> Result<(), Error> {
    if header.magic != MAGIC || header.format_version != FORMAT_VERSION_V1 {
        return Err(Error::UnsupportedFormat);
    }
    if header.algo_suite != ALGO_SUITE_V1 {
        return Err(Error::UnsupportedAlgorithm);
    }
    if header.kdf != KDF_ARGON2ID_V19 {
        return Err(Error::UnsupportedKdf);
    }
    if header.kdf_memory_kib != DEFAULT_KDF_MEMORY_KIB
        || header.kdf_passes != DEFAULT_KDF_PASSES
        || header.kdf_parallelism != DEFAULT_KDF_PARALLELISM
    {
        return Err(Error::UnsupportedKdfParams);
    }
    Ok(())
}

fn validate_item_record(vault: &UnlockedVault, record: &VaultItemRecordV1) -> Result<(), Error> {
    if record.format_version != FORMAT_VERSION_V1 {
        return Err(Error::UnsupportedFormat);
    }
    if record.algo_suite != ALGO_SUITE_V1 {
        return Err(Error::UnsupportedAlgorithm);
    }
    if record.vault_id != vault.header.vault_id {
        return Err(Error::VaultMismatch);
    }
    Ok(())
}

fn derive_key_encryption_key(master_password: &[u8], header: &VaultHeaderV1) -> Result<Key, Error> {
    let params = Params::new(
        header.kdf_memory_kib,
        header.kdf_passes,
        header.kdf_parallelism,
        Some(VAULT_KEY_BYTES),
    )
    .map_err(|_| Error::UnsupportedKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; VAULT_KEY_BYTES];

    argon2
        .hash_password_into(master_password, &header.kdf_salt, &mut key_bytes)
        .map_err(|_| Error::UnsupportedKdfParams)?;

    Key::from_bytes(&key_bytes).map_err(|_| Error::InvalidVaultKey)
}

fn vault_key_envelope_aad_bytes(header: &VaultHeaderV1) -> Result<Vec<u8>, Error> {
    let aad = VaultKeyEnvelopeAadV1 {
        context: "shield_vault.vault-key-envelope.v1".to_owned(),
        algo_suite: header.algo_suite.clone(),
        vault_id: header.vault_id,
        kdf: header.kdf.clone(),
        kdf_memory_kib: header.kdf_memory_kib,
        kdf_passes: header.kdf_passes,
        kdf_parallelism: header.kdf_parallelism,
        kdf_salt: header.kdf_salt,
    };

    bcs::to_bytes(&aad).map_err(|_| Error::Serialization)
}

fn vault_item_aad_bytes(
    vault_id: VaultId,
    item_id: ItemId,
    item_version: u64,
    deleted: bool,
) -> Result<Vec<u8>, Error> {
    let aad = VaultItemAadV1 {
        context: "shield_vault.vault-item.v1".to_owned(),
        algo_suite: ALGO_SUITE_V1.to_owned(),
        vault_id,
        item_id,
        item_version,
        deleted,
    };

    bcs::to_bytes(&aad).map_err(|_| Error::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const MASTER_PASSWORD: &[u8] = b"correct horse battery staple for tests";
    const WRONG_PASSWORD: &[u8] = b"wrong password";
    const VAULT_ID: VaultId = [0x11; VAULT_ID_BYTES];
    const ITEM_ID: ItemId = [0x22; ITEM_ID_BYTES];

    fn sample_payload() -> VaultItemPayloadV1 {
        VaultItemPayloadV1 {
            title: "Example Login".to_owned(),
            username: "alice@example.test".to_owned(),
            password: "not-a-real-password".to_owned(),
            urls: vec!["https://example.test/login".to_owned()],
            notes: "private note".to_owned(),
            custom_fields: vec![CustomFieldV1 {
                name: "account number".to_owned(),
                value: "12345".to_owned(),
            }],
            totp_secret: Some("JBSWY3DPEHPK3PXP".to_owned()),
        }
    }

    fn temp_db_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "shield_vault-{label}-{}-{nanos}.db",
            std::process::id()
        ))
    }

    fn sample_store(
        label: &str,
    ) -> (
        std::path::PathBuf,
        LocalDbKey,
        LocalVaultStore,
        UnlockedVault,
    ) {
        let path = temp_db_path(label);
        let key = LocalDbKey::from_bytes([0x42; VAULT_KEY_BYTES]);
        let store = LocalVaultStore::open(&path, &key).expect("open store");
        store.init_schema().expect("init schema");
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        (path, key, store, vault)
    }

    #[test]
    fn creates_and_unlocks_vault() {
        let created = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let unlocked = unlock_vault(MASTER_PASSWORD, created.header()).expect("unlock");

        assert_eq!(unlocked.header(), created.header());
    }

    #[test]
    fn unlock_rejects_wrong_password() {
        let created = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");

        let err = unlock_vault(WRONG_PASSWORD, created.header()).expect_err("wrong password fails");

        assert_eq!(err, Error::InvalidPasswordOrCiphertext);
    }

    #[test]
    fn vault_key_envelope_tampering_fails() {
        let created = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut header = created.header().clone();
        header.vault_key_envelope_ciphertext[0] ^= 1;

        let err = unlock_vault(MASTER_PASSWORD, &header).expect_err("tampering fails");

        assert_eq!(err, Error::InvalidPasswordOrCiphertext);
    }

    #[test]
    fn encrypts_and_decrypts_item_round_trip() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let payload = sample_payload();

        let record = encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &payload).expect("encrypt");
        let decrypted = decrypt_item(&vault, &record).expect("decrypt");

        assert!(decrypted == payload);
    }

    #[test]
    fn item_ciphertext_tampering_fails() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut record =
            encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &sample_payload()).expect("encrypt");
        record.ciphertext[0] ^= 1;

        let err = decrypt_item(&vault, &record).expect_err("tampering fails");

        assert_eq!(err, Error::InvalidPasswordOrCiphertext);
    }

    #[test]
    fn item_aad_tampering_fails() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut record =
            encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &sample_payload()).expect("encrypt");
        record.item_version = 2;

        let err = decrypt_item(&vault, &record).expect_err("AAD tampering fails");

        assert_eq!(err, Error::InvalidPasswordOrCiphertext);
    }

    #[test]
    fn cross_item_replay_fails() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut record =
            encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &sample_payload()).expect("encrypt");
        record.item_id = [0x33; ITEM_ID_BYTES];

        let err = decrypt_item(&vault, &record).expect_err("replay fails");

        assert_eq!(err, Error::InvalidPasswordOrCiphertext);
    }

    #[test]
    fn unsupported_algorithm_fails_closed() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut record =
            encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &sample_payload()).expect("encrypt");
        record.algo_suite = "unsupported".to_owned();

        let err = decrypt_item(&vault, &record).expect_err("unsupported algo fails");

        assert_eq!(err, Error::UnsupportedAlgorithm);
    }

    #[test]
    fn unsupported_header_kdf_params_fail_closed() {
        let created = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let mut header = created.header().clone();
        header.kdf_memory_kib = 8;

        let err = unlock_vault(MASTER_PASSWORD, &header).expect_err("downgrade fails");

        assert_eq!(err, Error::UnsupportedKdfParams);
    }

    #[test]
    fn aad_serialization_has_stable_fixture_bytes() {
        let aad = VaultItemAadV1 {
            context: "c".to_owned(),
            algo_suite: "s".to_owned(),
            vault_id: [1; VAULT_ID_BYTES],
            item_id: [2; ITEM_ID_BYTES],
            item_version: 7,
            deleted: false,
        };
        let mut expected = vec![1, b'c', 1, b's'];
        expected.extend_from_slice(&[1; VAULT_ID_BYTES]);
        expected.extend_from_slice(&[2; ITEM_ID_BYTES]);
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.push(0);

        let actual = bcs::to_bytes(&aad).expect("serialize AAD");

        assert_eq!(actual, expected);
    }

    #[test]
    fn debug_redacts_secret_values() {
        let vault = create_vault(MASTER_PASSWORD, VAULT_ID, 1_700_000_000_000).expect("create");
        let payload = sample_payload();
        let local_db_key = LocalDbKey::from_bytes([0x42; VAULT_KEY_BYTES]);

        let vault_debug = format!("{vault:?}");
        let payload_debug = format!("{payload:?}");
        let key_debug = format!("{local_db_key:?}");

        assert!(vault_debug.contains("vault_key"));
        assert!(vault_debug.contains("<redacted>"));
        assert!(!key_debug.contains("42"));
        assert!(!payload_debug.contains("not-a-real-password"));
        assert!(!payload_debug.contains("JBSWY3DPEHPK3PXP"));
        assert!(payload_debug.contains("<redacted>"));
    }

    #[test]
    fn local_store_opens_with_correct_key_and_initializes_schema_twice() {
        let path = temp_db_path("schema");
        let key = LocalDbKey::from_bytes([0x42; VAULT_KEY_BYTES]);
        let store = LocalVaultStore::open(&path, &key).expect("open store");

        store.init_schema().expect("init schema once");
        store.init_schema().expect("init schema twice");

        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn local_store_rejects_wrong_key() {
        let path = temp_db_path("wrong-key");
        let key = LocalDbKey::from_bytes([0x42; VAULT_KEY_BYTES]);
        let wrong_key = LocalDbKey::from_bytes([0x43; VAULT_KEY_BYTES]);
        let store = LocalVaultStore::open(&path, &key).expect("open store");
        store.init_schema().expect("init schema");
        drop(store);

        let err = LocalVaultStore::open(&path, &wrong_key).expect_err("wrong key fails");

        assert_eq!(err, Error::Storage);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn local_store_round_trips_vault_header_exactly() {
        let (path, _key, store, vault) = sample_store("header");

        store.put_vault_header(vault.header()).expect("put header");
        let loaded = store
            .get_vault_header(VAULT_ID)
            .expect("get header")
            .expect("header exists");

        assert_eq!(
            bcs::to_bytes(&loaded).expect("loaded header BCS"),
            bcs::to_bytes(vault.header()).expect("original header BCS")
        );
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn local_store_round_trips_item_record_exactly() {
        let (path, _key, store, vault) = sample_store("item");
        let record =
            encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &sample_payload()).expect("encrypt");

        store.put_vault_header(vault.header()).expect("put header");
        store.put_item_record(&record).expect("put item");
        let loaded = store
            .get_item_record(VAULT_ID, ITEM_ID, 1)
            .expect("get item")
            .expect("item exists");

        assert_eq!(
            bcs::to_bytes(&loaded).expect("loaded record BCS"),
            bcs::to_bytes(&record).expect("original record BCS")
        );
        drop(store);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn local_store_raw_database_does_not_contain_sample_plaintext() {
        let (path, _key, store, vault) = sample_store("plaintext");
        let payload = sample_payload();
        let record = encrypt_item(&vault, ITEM_ID, 1, 10, 11, None, &payload).expect("encrypt");

        store.put_vault_header(vault.header()).expect("put header");
        store.put_item_record(&record).expect("put item");
        drop(store);

        let db_bytes = fs::read(&path).expect("read encrypted DB bytes");

        assert!(!contains_bytes(&db_bytes, payload.password.as_bytes()));
        assert!(!contains_bytes(&db_bytes, payload.username.as_bytes()));
        assert!(!contains_bytes(&db_bytes, payload.notes.as_bytes()));
        let _ = fs::remove_file(path);
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn opaque_registration_and_login_round_trip() {
        let server_setup = opaque_create_server_setup().expect("server setup");
        let registration =
            opaque_register(b"opaque password", b"alice@example.test", &server_setup)
                .expect("registration");

        let login = opaque_login(
            b"opaque password",
            b"alice@example.test",
            &server_setup,
            &registration.password_file,
        )
        .expect("login");

        assert_eq!(login.client_session_key, login.server_session_key);
        assert!(!registration.password_file.is_empty());
        assert!(!registration.export_key.is_empty());
    }

    #[test]
    fn opaque_login_rejects_wrong_password() {
        let server_setup = opaque_create_server_setup().expect("server setup");
        let registration =
            opaque_register(b"opaque password", b"alice@example.test", &server_setup)
                .expect("registration");

        let err = opaque_login(
            b"wrong opaque password",
            b"alice@example.test",
            &server_setup,
            &registration.password_file,
        )
        .expect_err("wrong password fails");

        assert_eq!(err, Error::Opaque);
    }

    #[test]
    fn opaque_serialized_password_file_remains_usable() {
        let server_setup = opaque_create_server_setup().expect("server setup");
        let registration =
            opaque_register(b"opaque password", b"alice@example.test", &server_setup)
                .expect("registration");
        let stored_password_file = registration.password_file.clone();

        let login = opaque_login(
            b"opaque password",
            b"alice@example.test",
            &server_setup,
            &stored_password_file,
        )
        .expect("login");

        assert_eq!(login.client_session_key, login.server_session_key);
    }

    #[test]
    fn opaque_missing_account_uses_dummy_path_and_fails_generically() {
        let server_setup = opaque_create_server_setup().expect("server setup");

        let err = opaque_login_missing_account(
            b"opaque password",
            b"missing@example.test",
            &server_setup,
        )
        .expect_err("missing account fails generically");

        assert_eq!(err, Error::Opaque);
    }

    #[test]
    fn opaque_debug_redacts_sensitive_outputs() {
        let server_setup = opaque_create_server_setup().expect("server setup");
        let registration =
            opaque_register(b"opaque password", b"alice@example.test", &server_setup)
                .expect("registration");
        let login = opaque_login(
            b"opaque password",
            b"alice@example.test",
            &server_setup,
            &registration.password_file,
        )
        .expect("login");

        let registration_debug = format!("{registration:?}");
        let login_debug = format!("{login:?}");

        assert!(registration_debug.contains("<redacted>"));
        assert!(login_debug.contains("<redacted>"));
        assert!(!registration_debug.contains("opaque password"));
        assert!(!login_debug.contains("opaque password"));
    }
}
