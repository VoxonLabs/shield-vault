# Research Log

Use this file to keep Shield Vault decisions current and source-backed.

## 2026-05-09 Initial Standards Check

### Sources Checked

- Rust installation: https://www.rust-lang.org/tools/install
- Argon2: RFC 9106, https://datatracker.ietf.org/doc/rfc9106/
- HPKE: RFC 9180, https://www.rfc-editor.org/rfc/rfc9180
- MLS: RFC 9420, https://www.rfc-editor.org/rfc/rfc9420
- OPAQUE: RFC 9807, https://www.rfc-editor.org/rfc/rfc9807
- Tauri v2 prerequisites: https://v2.tauri.app/start/prerequisites

### Current Decisions

- Use Rust stable for the workspace.
- Keep `/crypto-lab` educational and vector-driven.
- Use audited production crates in `/core`; do not ship lab primitives.
- Treat OPAQUE, HPKE, MLS, and Argon2 as standards-backed building blocks.
- Use Tauri v2 later, after core vault functionality is stable.

### Open Research Questions

- Which maintained libsodium binding is best for the production Rust core and WASM target?
- What SQLCipher integration path is safest with `sqlx` and Tauri?
- What metadata should remain plaintext as AAD versus encrypted inside item payloads?
- Should the first recovery MVP split a user root key, a vault recovery key, or an encrypted recovery package?
- What formal model should be written first: vault membership, sync rollback prevention, or recovery ceremony?

## 2026-05-09 Production Core Crypto Crate Check

### Sources Checked

- RustCrypto `argon2` docs, version 0.5.3: https://docs.rs/argon2/latest/argon2/
- RFC 9106 section 4 and section 7.4 parameter recommendations: https://www.rfc-editor.org/rfc/rfc9106.html
- `libsodium-rs` crate, version 0.2.4: https://crates.io/crates/libsodium-rs
- `libsodium-rs` secretstream docs: https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_secretstream/xchacha20poly1305/
- libsodium secretstream documentation: https://download.libsodium.org/doc/secret-key_cryptography/secretstream
- `libsodium-sys-stable` crate, version 1.24.0: https://crates.io/crates/libsodium-sys-stable
- RustSec `RUSTSEC-2021-0137` for `sodiumoxide`: https://rustsec.org/advisories/RUSTSEC-2021-0137.html
- `bcs` crate, version 0.2.1: https://crates.io/crates/bcs
- `postcard` crate, version 1.1.3: https://crates.io/crates/postcard
- `bincode` crate, version 3.0.0 maintenance notice: https://crates.io/crates/bincode
- `serde` crate, version 1.0.228: https://crates.io/crates/serde/1.0.228

### Current Decisions

- Use `argon2` 0.5.3 for production Argon2id key derivation in `/core`.
- Use `hash_password_into` for raw key derivation instead of PHC password-hash strings.
- Use RFC 9106's second recommended Argon2id profile for the first desktop implementation: `m=65536` KiB, `t=3`, `p=4`, 128-bit salt, 256-bit output.
- Use `libsodium-rs` 0.2.4 for XChaCha20-Poly1305 secretstream rather than raw FFI by default.
- Rely on `libsodium-rs`'s `libsodium-sys-stable` 1.24.0 dependency for the underlying maintained libsodium binding.
- Reject `sodiumoxide` for new production code because RustSec marks it deprecated and unmaintained.
- Store a random 32-byte `vault_key` wrapped by an Argon2id-derived key-encryption key instead of deriving item encryption keys directly from the master password.
- Use `bcs` 0.2.1 plus `serde` 1.0.228 for canonical serialization of AAD, vault headers, item records, and item payloads.

### Alternatives Rejected

- `sodiumoxide`: older high-level API, but deprecated and unmaintained.
- Direct `libsodium-sys-stable` FFI for normal `/core` code: maintained, but it would expand the unsafe boundary compared with `libsodium-rs`.
- RFC 9106 first recommended 2 GiB Argon2id profile: stronger default, but too costly for the first desktop implementation and likely impractical for future browser/WASM use.
- Direct item encryption under a password-derived key: simpler, but makes password changes expensive and does not align well with later shared vault epochs.
- `bincode`: latest crate release is an unmaintained notice with a compiler error, so it is unsuitable for new storage formats.
- `postcard`: stable wire format and a good constrained-environment option, but BCS is selected because canonical serialization is an explicit cryptographic design goal.

### Security/Product Risk If Wrong

- If `libsodium-rs` is too immature despite current maintenance, the project may need a narrow internal wrapper over `libsodium-sys-stable`.
- If Argon2id parameters are too weak for target devices, offline database theft becomes cheaper to attack; headers must store parameters so work factors can be increased.
- If AAD is underspecified, ciphertext replay or cross-record substitution bugs could silently pass authentication.
- If BCS types are not domain-separated by context/version, valid bytes for one object type could be accidentally accepted as another.

## 2026-05-09 Educational XChaCha20-Poly1305 Check

### Sources Checked

- RFC 8439, ChaCha20 and Poly1305 for IETF Protocols: https://www.rfc-editor.org/rfc/rfc8439
- XChaCha draft, `draft-arciszewski-xchacha-03`: https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
- libsodium XChaCha20-Poly1305 construction notes: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction

### Current Decisions

- Add `/crypto-lab` educational XChaCha20-Poly1305 as a from-scratch study implementation.
- Cover HChaCha20 with the XChaCha draft test vector.
- Cover AEAD_XChaCha20_Poly1305 encryption/decryption with the XChaCha draft vector.
- Cover standalone Poly1305 with the RFC 8439 vector to keep MAC arithmetic testable apart from encryption.
- Keep the module clearly marked as non-production and separate from `/core`.

### Alternatives Rejected

- Using a production crate inside `/crypto-lab` for these vectors: rejected because the milestone is educational implementation.
- Adding this implementation to `/core`: rejected because production crypto must use audited crates.

### Security/Product Risk If Wrong

- Incorrect counter setup, HChaCha subkey derivation, Poly1305 clamping, or AEAD padding can produce outputs that self-round-trip but fail standard vectors.
- Passing test vectors does not make the lab code constant-time, hardened, audited, or appropriate for real vault encryption.

## 2026-05-09 Production Core Vault Implementation

### Sources Checked

- RustCrypto `argon2` `Argon2::hash_password_into`: https://docs.rs/argon2/latest/argon2/struct.Argon2.html
- RustCrypto `argon2` `Params`: https://docs.rs/argon2/latest/argon2/struct.Params.html
- `libsodium-rs` secretstream `Key`: https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_secretstream/xchacha20poly1305/struct.Key.html
- `libsodium-rs` secretstream `PushState`: https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_secretstream/xchacha20poly1305/struct.PushState.html
- `libsodium-rs` secretstream `PullState`: https://docs.rs/libsodium-rs/latest/libsodium_rs/crypto_secretstream/xchacha20poly1305/struct.PullState.html
- `libsodium-rs` random byte generation: https://docs.rs/libsodium-rs/latest/libsodium_rs/random/fn.fill_bytes.html
- BCS canonical serialization docs: https://docs.rs/bcs/latest/bcs/

### Current Decisions

- Implement `/core` single-user vault create/unlock with a random 32-byte vault key wrapped by an Argon2id-derived key-encryption key.
- Use libsodium secretstream with `TAG_FINAL` for the vault-key envelope and each V1 item payload.
- Use BCS for item payloads and AAD structs; every AAD struct has an explicit context string.
- Keep `UnlockedVault` as the only type that carries the unwrapped vault key; its debug output redacts the key.
- Fail closed on unsupported format version, algorithm suite, KDF name, and downgraded KDF parameters.

### Tests Added

- Vault create/unlock round trip.
- Wrong password rejection.
- Vault-key envelope tampering rejection.
- Item encrypt/decrypt round trip.
- Ciphertext tampering rejection.
- AAD/version tampering rejection.
- Cross-item replay rejection.
- Unsupported algorithm and KDF downgrade rejection.
- Stable BCS fixture for an AAD struct.
- Debug redaction for secret-bearing types.

### Security/Product Risk If Wrong

- If AAD coverage is incomplete, records could be replayed across items or versions without detection.
- If debug formatting leaks secrets, tests and logs could persist plaintext or key material.
- If KDF parameters are accepted too broadly, an attacker could try downgrade attacks against stolen vault headers.

## 2026-05-09 Local Storage Design

### Question

Which Rust SQLite/SQLCipher integration should Shield Vault use for Phase 1 local encrypted storage?

### Sources Checked

- SQLCipher API documentation: https://www.zetetic.net/sqlcipher/sqlcipher-api/
- SQLCipher GitHub repository: https://github.com/sqlcipher/sqlcipher
- `rusqlite` crate, version 0.39.0: https://crates.io/crates/rusqlite
- `libsqlite3-sys` crate, version 0.37.0: https://crates.io/crates/libsqlite3-sys
- `sqlx` crate metadata, stable version 0.8.6: https://crates.io/crates/sqlx
- `sqlx` SQLite docs and native-linking note: https://docs.rs/sqlx/latest/sqlx/sqlite/

### Options Compared

- `rusqlite` with `bundled-sqlcipher`: explicit SQLCipher support, synchronous embedded API, good fit for a local vault database, but less aligned with future async server code.
- `rusqlite` with system `sqlcipher`: smaller build and can use OS packages, but installation and dynamic linking vary across platforms.
- `sqlx` with SQLite: strong async and compile-time query story, but SQLCipher support is not a first-class crate feature and native SQLite linking can be a semver/build hazard.

### Decision

Use `rusqlite` 0.39.0 with `bundled-sqlcipher-vendored-openssl` for the first local storage implementation. Initial implementation with `bundled-sqlcipher` failed in this environment because OpenSSL headers were unavailable, so vendoring OpenSSL is the reproducible default for development and CI. Keep `sqlx` available as a future relay/server database choice rather than forcing async SQLite into `/core`.

### Alternatives Rejected

- `sqlx` for local storage: rejected for now because local vault storage does not need async access and SQLCipher is more explicit through `rusqlite` features.
- System SQLCipher only: rejected as the default because cross-platform desktop packaging should not depend on users installing matching native libraries.
- `bundled-sqlcipher` with system crypto: rejected as the default after local build failure due to missing `openssl/crypto.h`.
- Storing only `/core` encrypted blobs in plaintext SQLite: rejected because SQLCipher provides useful defense in depth for schema and metadata.

### Security/Product Risk If Wrong

- If bundled SQLCipher complicates desktop packaging, release builds may need system SQLCipher or vendored OpenSSL feature selection.
- If SQLCipher key management is mishandled, local metadata and encrypted blobs may be exposed even though item payloads remain `/core` encrypted.
- If WAL or temporary files are misconfigured, local storage could leak operational metadata or stale encrypted pages.

## 2026-05-09 CI Workflow Decision

### Question

Should CI be added now or after more product code exists?

### Sources Checked

- `actions/checkout` releases: https://github.com/actions/checkout/releases
- `dtolnay/rust-toolchain` usage: https://github.com/dtolnay/rust-toolchain
- `Swatinem/rust-cache` releases: https://github.com/Swatinem/rust-cache/releases

### Decision

Add minimal GitHub Actions CI now because `/core` has security-sensitive tests and SQLCipher build dependencies that should stay reproducible. The workflow runs formatting, workspace tests, and clippy on pushes to `main` and pull requests.

### Alternatives Rejected

- Wait until desktop UI exists: rejected because crypto/storage regressions are already meaningful.
- Add deployment/package jobs now: rejected because no deployable product exists yet.

### Risk If Wrong

- CI may need tuning if vendored OpenSSL or SQLCipher builds are too slow on GitHub-hosted runners.
- Future frontend and relay checks must be added when those components become real.

## 2026-05-09 OPAQUE Crate And RFC Check

### Question

Which `opaque-ke` version and feature set should Phase 2 use, and how closely does it match RFC 9807?

### Sources Checked

- `opaque-ke` crate page: https://crates.io/crates/opaque-ke
- `opaque-ke` docs: https://docs.rs/opaque-ke/latest/opaque_ke/
- `opaque-ke` changelog/search result for RFC 9807 sync: https://github.com/facebook/opaque-ke/blob/main/CHANGELOG.md
- RFC 9807: https://www.rfc-editor.org/rfc/rfc9807
- RustSec package lookup for `opaque-ke`: https://rustsec.org/packages/opaque-ke.html

### Options Compared

- `opaque-ke` 4.0.1: latest stable release, based on RFC 9807, MSRV 1.85, audited lineage from earlier versions.
- `opaque-ke` 4.1.0-pre.2: newer pre-release with ML-KEM-related dependency updates and MSRV 1.87, but not needed for the first implementation.
- Older 3.x line: more mature download history, but predates the 4.0 RFC 9807 sync.

### Decision

Use `opaque-ke` 4.0.1 with the `argon2` feature for the first implementation. Use the Ristretto255 / TripleDH / SHA-512 shape from the crate docs and `argon2::Argon2<'static>`, not `ksf::Identity`, for production behavior.

### Alternatives Rejected

- `4.1.0-pre.2`: rejected because it is a pre-release and the project does not need its ML-KEM dependency changes yet.
- `ksf::Identity`: rejected outside tests/examples because the crate docs explicitly say real applications should use a password-stretching KSF such as Argon2.
- Custom OPAQUE implementation: rejected because `/core` must use audited crates for production cryptography.

### Security/Product Risk If Wrong

- If crate API or parameter choices diverge from RFC 9807 expectations, authentication could silently lose interoperability or security properties.
- If the server leaks distinguishable missing-account behavior, OPAQUE can still reveal account existence.
- If OPAQUE session/export keys are confused with vault keys, account authentication and vault encryption boundaries become unsafe.

## 2026-05-09 OPAQUE Flow Spec

### Decision

Document the first OPAQUE registration/login flow before implementation. V1 keeps account authentication separate from vault decryption, treats `opaque-ke` messages as opaque protocol bytes, stores relay-side password files as sensitive hash-equivalent material, and requires dummy login behavior for missing accounts.

### Security/Product Risk If Wrong

- If relay endpoints return early for missing accounts, account enumeration becomes possible.
- If OPAQUE session keys or export keys are wired into vault encryption, authentication compromise could affect vault confidentiality.
- If serialized OPAQUE blobs are not versioned in Shield Vault records, future crate upgrades can break stored accounts without a migration path.

## 2026-05-09 OPAQUE Core Flow Implementation

### Decision

Implement a narrow `/core` OPAQUE wrapper for server setup creation, registration, login, and missing-account dummy login. The implementation returns redacted result types, keeps OPAQUE session/export keys separate from vault keys, and maps failures to generic OPAQUE errors.

### Tests Added

- Registration and login round trip.
- Client/server session key equality.
- Wrong password rejection.
- Serialized password file remains usable.
- Missing-account dummy path fails generically.
- Debug output redacts password files, export keys, and session keys.

### Security/Product Risk If Wrong

- The current wrapper is still in-process; relay persistence and endpoint behavior must preserve the same generic failure and no-plaintext rules.
- OPAQUE test coverage is behavioral, not a full RFC vector suite.

