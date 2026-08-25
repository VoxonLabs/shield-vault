# Core Crypto Crate Choices

Date checked: 2026-05-09

## Phase 1 Guarantee

The production `/core` crate will provide client-side single-user vault encryption and decryption. Given the correct master password and unmodified local vault records, the client can unwrap a local vault key and decrypt vault items. An attacker who only has the local database or relay-side ciphertext should not learn item plaintext without guessing the master password.

## Non-Guarantees

- This phase does not provide multi-device sync, OPAQUE login, sharing, revocation, recovery, audit logs, or browser autofill safety.
- Argon2id raises offline guessing cost but does not make weak passwords strong.
- Local malware, process memory compromise, or a compromised browser extension can still read plaintext after unlock.
- This phase is not a security proof or audit.

## Selected Production Crates

### Password-Based Key Derivation

- Crate: `argon2`
- Version: `0.5.3`
- Source: <https://docs.rs/argon2/latest/argon2/>
- Use: Argon2id v=19 key derivation through `hash_password_into`, not the PHC password-hashing convenience API.
- Parameters for the first desktop implementation: Argon2id, `m=65536` KiB, `t=3`, `p=4`, 128-bit random salt, 256-bit output.

RFC 9106 recommends Argon2id `t=1`, `p=4`, `m=2^21` KiB as the first option and Argon2id `t=3`, `p=4`, `m=2^16` KiB as the second memory-constrained option. The first Shield Vault implementation will use the second recommendation because a 2 GiB unlock cost is too high for the early desktop and future browser/WASM targets. The vault header must store KDF parameters so they can be raised later without changing the encrypted item format.

### Secretstream Encryption

- Crate: `libsodium-rs`
- Version: `0.2.4`
- Source: <https://crates.io/crates/libsodium-rs>
- Underlying binding: `libsodium-sys-stable` `1.24.0`
- Use: `crypto_secretstream::xchacha20poly1305` for vault-key envelopes and item payload encryption.

`libsodium-rs` is a current safe wrapper maintained by the libsodium author and exposes a high-level XChaCha20-Poly1305 secretstream API with AAD support. Prefer it over direct `libsodium-sys-stable` FFI unless the wrapper blocks a required operation.

### Canonical Serialization

- Crate: `bcs`
- Version: `0.2.1`
- Source: <https://crates.io/crates/bcs>
- Support crate: `serde` `1.0.228` with `derive`
- Use: canonical serialization for AAD structs, vault headers, vault key envelopes, item records, and item payloads.

BCS is selected because it is explicitly canonical: each value of a given type has one valid byte representation. That property is useful for AAD, signatures, hashes, and future operation logs. The application must still enforce the expected Rust type and versioned domain string before accepting decoded bytes.

### Rejected Crates

- `sodiumoxide` `0.2.7`: rejected for new production code because RustSec advisory `RUSTSEC-2021-0137` marks it deprecated and unmaintained.
- Direct `libsodium-sys-stable` use: rejected as the default because raw FFI would force `/core` to own a larger unsafe boundary. Keep it as the fallback only if `libsodium-rs` cannot support a required API.
- `bincode`: rejected for new security-sensitive serialization because crates.io now marks the latest release unmaintained and the final `3.0.0` crate intentionally contains only a compiler error.
- `postcard`: acceptable for constrained formats, but BCS better matches this phase because canonical serialization is an explicit design goal.

## Tests To Write First

- Argon2id derives a stable 32-byte key for fixed parameters and salt.
- Vault unlock fails with the wrong password.
- Vault-key envelope tampering fails authentication.
- Item ciphertext tampering fails authentication.
- Item AAD tampering fails authentication.
- AAD serialization is deterministic for fixed V1 structs.
- Cross-item replay fails when ciphertext is paired with another item ID/version AAD.
- Decrypting a record with an unsupported `algo_suite` fails closed.

## Silent Security Failure Risks

- Accidentally using the PHC password-hashing API output as raw key material instead of `hash_password_into`.
- Failing to persist and authenticate KDF parameters, salt, secretstream header, item ID, version, or algorithm suite.
- Reusing a derived key for unrelated purposes without domain separation.
- Treating AAD as confidential; it is authenticated but plaintext metadata.
- Decoding bytes as the wrong BCS type; every serialized object needs an explicit version and domain context.
- Accepting unknown algorithm identifiers or downgraded KDF parameters.
- Logging passwords, derived keys, vault keys, item plaintext, or decrypted URLs during tests or error reporting.

