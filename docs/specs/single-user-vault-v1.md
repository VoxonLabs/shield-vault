# Single-User Vault V1 Specification

Date checked: 2026-05-09

## Scope

This specification covers the first production `/core` behavior: one local user, one local vault, client-side unlock, and encrypted vault items at rest. It intentionally excludes relay sync, OPAQUE authentication, device bootstrap, sharing, recovery, and browser-extension autofill.

## Key Hierarchy

1. The client generates a random 32-byte `vault_key` when creating a vault.
2. The client derives a 32-byte key-encryption key from the master password with Argon2id.
3. The `vault_key` is encrypted into a local `vault_key_envelope`.
4. Item payloads are encrypted with `vault_key` using libsodium secretstream XChaCha20-Poly1305.

This lets a future password-change flow rewrap the `vault_key` without re-encrypting every item, and it aligns the single-user vault with later shared-vault epochs.

## Algorithms

- `kdf`: `argon2id-v19`
- `kdf_params_v1`: `memory_kib=65536`, `passes=3`, `parallelism=4`, `salt_len=16`, `output_len=32`
- `item_encryption`: `libsodium-secretstream-xchacha20poly1305`
- `vault_key_envelope_encryption`: `libsodium-secretstream-xchacha20poly1305`
- `serialization`: `bcs-v0.2.1`
- `algo_suite`: `shield_vault.local-vault.v1.argon2id.secretstream-xchacha20poly1305`

All V1 structs are serialized with BCS. The Rust type being decoded is part of the application contract; every authenticated object also includes a domain-specific `context` string or fixed version fields to prevent accidental cross-type reuse.

## Vault Header

The vault header is plaintext but authenticated as AAD whenever the vault key envelope is opened.

```text
VaultHeaderV1 {
  magic: "MYPW",
  format_version: 1,
  algo_suite,
  vault_id,
  created_at_ms,
  kdf: "argon2id-v19",
  kdf_memory_kib,
  kdf_passes,
  kdf_parallelism,
  kdf_salt,
  vault_key_envelope_header,
  vault_key_envelope_ciphertext
}
```

The `vault_key_envelope_ciphertext` contains exactly one encrypted 32-byte `vault_key` message with a `TAG_FINAL` secretstream tag.

## Item Record

Each vault item is stored as an encrypted payload plus the minimum plaintext metadata required to identify, version, and authenticate the record.

```text
VaultItemRecordV1 {
  format_version: 1,
  algo_suite,
  vault_id,
  item_id,
  item_version,
  created_at_ms,
  updated_at_ms,
  deleted_at_ms: optional,
  secretstream_header,
  ciphertext
}
```

The ciphertext contains exactly one encrypted payload message with a `TAG_FINAL` secretstream tag. Multi-chunk item payloads are out of scope until large attachments exist.

## Plaintext Item Payload

The encrypted payload is the only place where secret item fields appear.

```text
VaultItemPayloadV1 {
  title,
  username,
  password,
  urls,
  notes,
  custom_fields,
  totp_secret: optional
}
```

The first implementation serializes this payload with BCS before encryption. `custom_fields` must be stored as a `Vec<CustomFieldV1>` with stable application ordering, not as a hash map. JSON is acceptable only for handwritten examples; it is not a canonical storage or AAD encoding.

## AAD Schema

AAD is plaintext authenticated metadata. It must be byte-for-byte identical during encryption and decryption.
AAD bytes are `bcs::to_bytes(...)` of the exact V1 AAD struct. Implementations must never hand-concatenate AAD fields.

### Vault Key Envelope AAD

```text
VaultKeyEnvelopeAadV1 {
  context: "shield_vault.vault-key-envelope.v1",
  algo_suite,
  vault_id,
  kdf,
  kdf_memory_kib,
  kdf_passes,
  kdf_parallelism,
  kdf_salt
}
```

### Item Payload AAD

```text
VaultItemAadV1 {
  context: "shield_vault.vault-item.v1",
  algo_suite,
  vault_id,
  item_id,
  item_version,
  deleted: bool
}
```

Timestamps are not part of item AAD in V1 because clock changes should not make an otherwise valid local item undecryptable. If timestamps later need tamper evidence, they should move into a signed operation log rather than being bolted onto item encryption.

## Failure Behavior

- Unknown `format_version`, `algo_suite`, or `kdf` values fail closed.
- Unsupported KDF parameters fail closed unless an explicit migration path exists.
- Secretstream authentication failure returns a generic decrypt error and never returns partial plaintext.
- Missing `TAG_FINAL` fails closed.
- AAD mismatch fails closed.

## Implementation Test Plan

- Create a vault, unlock it, and decrypt the generated `vault_key`.
- Reject unlock with an incorrect master password.
- Encrypt and decrypt one item round trip.
- Reject item decrypt after changing `vault_id`, `item_id`, `item_version`, `algo_suite`, or ciphertext bytes.
- Reject item decrypt when the final tag is missing or not `TAG_FINAL`.
- Assert stable BCS bytes for representative `VaultKeyEnvelopeAadV1` and `VaultItemAadV1` fixtures.
- Confirm no `shield-vault-core` API returns plaintext in debug formatting for secret wrapper types.

