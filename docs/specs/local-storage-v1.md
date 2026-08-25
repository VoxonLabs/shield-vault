# Local Storage V1 Specification

Date checked: 2026-05-09

## Scope

This specification covers local persistence for the Phase 1 single-user vault. It stores the production `/core` V1 vault header and encrypted item records on one device. It intentionally excludes sync logs, relay replication, OPAQUE records, sharing, recovery, and browser-extension storage.

## Guarantee

The local database stores no item plaintext, master password, master key, unwrapped vault key, or recovery material. Vault contents remain encrypted by `/core` item encryption, and SQLCipher provides an additional at-rest protection layer for local metadata, schema, and record blobs.

## Non-Guarantees

- SQLCipher does not protect data after the application unlocks the vault and plaintext is in process memory.
- SQLCipher does not replace `/core` item encryption. It is defense in depth, not the primary zero-knowledge guarantee.
- This milestone does not define cloud sync conflict resolution or rollback protection.
- Local filesystem metadata such as file path, file size, modification time, and backup behavior can still leak usage information.

## Selected Integration

- Crate: `rusqlite`
- Version checked: `0.39.0`
- Feature for implementation: `bundled-sqlcipher-vendored-openssl`
- Underlying binding: `libsqlite3-sys` `0.37.0`
- SQLCipher source: bundled by `libsqlite3-sys`; OpenSSL is vendored through `openssl-sys` to avoid requiring system OpenSSL headers in development and CI.

Use `rusqlite` rather than `sqlx` for the local database because:

- Local vault operations are embedded and synchronous; async database access is not needed yet.
- `rusqlite` exposes explicit SQLCipher build features.
- `sqlx` SQLite support has native-linking caveats and is better reserved for later async relay/server work.
- Keeping local storage sync/blocking avoids introducing an async runtime into `/core`.

## Database Keying

The SQLCipher database key is a separate local database key, not the user's master password and not the vault key.

V1 implementation rule:

1. Generate a random 32-byte `LocalDbKey` when creating the local database.
2. Store `LocalDbKey` through the platform secret store in the desktop layer when that layer exists.
3. In `/core` tests and low-level APIs, accept `LocalDbKey` as injected key material rather than fetching it from the OS.
4. Key SQLCipher with raw-key semantics, not passphrase semantics, to avoid SQLCipher's PBKDF2 being confused with Shield Vault's Argon2id vault unlock.
5. Execute the key operation before any other database read or write.
6. Verify key correctness by reading `sqlite_master` immediately after keying.

Do not store `LocalDbKey` in the database, in project config, or in logs.

## SQLCipher Open Sequence

The implementation should open the database and immediately run:

```sql
PRAGMA key = "x'<64 hex chars of LocalDbKey>'";
SELECT count(*) FROM sqlite_master;
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

`PRAGMA key` must be the first operation that touches the database. The `sqlite_master` read is required because SQLCipher does not report a wrong key until the database is actually read.

Do not use `PRAGMA cipher_plaintext_header_size` in V1. If a future platform requires a plaintext SQLite header, the external salt handling described by SQLCipher must be designed separately.

## Schema

Store canonical BCS blobs produced by `/core`. Duplicate only the minimum metadata needed for lookup and migration.

```sql
CREATE TABLE metadata (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE vault_headers (
  vault_id BLOB PRIMARY KEY,
  format_version INTEGER NOT NULL,
  header_bcs BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE vault_items (
  vault_id BLOB NOT NULL,
  item_id BLOB NOT NULL,
  item_version INTEGER NOT NULL,
  record_bcs BLOB NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  deleted_at_ms INTEGER,
  PRIMARY KEY (vault_id, item_id, item_version),
  FOREIGN KEY (vault_id) REFERENCES vault_headers(vault_id)
);

CREATE INDEX vault_items_latest_idx
  ON vault_items(vault_id, item_id, item_version DESC);
```

The database must not contain decrypted item titles, usernames, passwords, URLs, notes, custom fields, TOTP secrets, master passwords, unwrapped vault keys, or recovery shares.

## Storage Boundaries

- `/core` owns serialization of `VaultHeaderV1` and `VaultItemRecordV1`.
- `/core` owns SQLite connection setup, migrations, and persistence for the local vault store.
- The desktop shell owns platform secret-store integration for `LocalDbKey`.
- The relay and sync layers must not depend on SQLCipher-specific local storage details.

## Tests To Write First

- Opening with the correct `LocalDbKey` succeeds.
- Opening with the wrong `LocalDbKey` fails during `sqlite_master` verification.
- Creating schema twice is idempotent.
- Storing and loading a vault header round trips exact BCS bytes.
- Storing and loading item records round trips exact BCS bytes.
- Raw database bytes do not contain sample item plaintext after insert.
- No API accepts or logs master passwords, vault keys, item plaintext, or local database keys.

## Open Questions

- How the desktop layer should name and rotate `LocalDbKey` entries in Linux Secret Service, macOS Keychain, and Windows Credential Manager.
- Whether WAL mode is acceptable for every target platform after packaging tests confirm encrypted WAL behavior and cleanup.

