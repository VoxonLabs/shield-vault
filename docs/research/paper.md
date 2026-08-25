# Shield Vault Research Paper Draft

Working title: **Local-First Zero-Knowledge Team Secret Management With Client-Side Recovery And Verifiable Sharing**

Citation style: use citation keys from `docs/research/references.bib`, for example `[@rfc9106]`.

## Abstract Draft

Team password managers must balance end-to-end confidentiality, administrative recovery, reliable availability, and employee offboarding. Pure peer-to-peer designs improve sovereignty but create availability, metadata, and revocation problems for business users. Shield Vault explores a hybrid architecture: clients remain authoritative for plaintext and keys, relays store only ciphertext and public metadata, and optional peer-to-peer sync improves resilience without becoming the primary trust or availability mechanism. The system separates educational cryptographic implementations from production cryptography, using audited primitives in the shipping core while maintaining a test-vector-driven crypto lab for learning and reproducibility.

## Research Direction

A practical zero-knowledge SMB password manager should optimize for client-side cryptographic authority, auditable key lifecycle events, and reliable encrypted availability rather than pure decentralization.

## Research Contributions To Target

- A clear protocol specification for single-user vault encryption, device identity, vault sharing, revocation, and threshold recovery.
- A rigorous comparison of dumb-relay, self-hosted, and optional P2P sync architectures for encrypted team secret storage.
- A recovery ceremony design that preserves zero-knowledge server guarantees while supporting SMB operational needs.
- A signed, append-only membership and audit model that makes admin actions verifiable without exposing vault contents.
- A test-vector-backed educational crypto lab separate from production crypto.

## Literature And Standards Map

- Argon2 memory-hard password hashing: RFC 9106 [@rfc9106].
- OPAQUE augmented PAKE: RFC 9807 [@rfc9807].
- HPKE key encapsulation and envelope encryption: RFC 9180 [@rfc9180].
- Messaging Layer Security for group key management: RFC 9420 [@rfc9420].
- XChaCha20-Poly1305 secretstream usage through libsodium [@libsodiumSecretstream].
- Local-first software and conflict handling.
- Encrypted sync, append-only logs, and rollback protection.
- Threshold secret sharing and recovery UX.
- Browser extension threat models and autofill risks.

## Current Design Checkpoints

- The first production core will use a random per-vault key wrapped by an Argon2id-derived key-encryption key, rather than using the master-password-derived key directly for items.
- Single-user item encryption will use libsodium secretstream XChaCha20-Poly1305 with explicit AAD binding for vault ID, item ID, item version, and algorithm suite.
- V1 AAD and vault records use canonical BCS serialization so authenticated bytes are reproducible from typed values [@bcsCrate].
- The implementation will prefer maintained high-level Rust bindings over deprecated `sodiumoxide`; current notes select `libsodium-rs` backed by `libsodium-sys-stable`.
- The educational crypto lab now includes vector-backed Argon2id and XChaCha20-Poly1305 work, reinforcing the paper's separation between learning implementations and production crypto dependencies.
- The production core now implements single-user vault create/unlock and item encrypt/decrypt with audited crates, including negative tests for wrong passwords, tampering, AAD mismatch, replay, unsupported algorithms, and KDF downgrade attempts.
- Local storage uses SQLCipher through `rusqlite` for defense-in-depth over already encrypted `/core` records; the SQLCipher database key is separate from the master password and vault key [@sqlcipherApi; @rusqliteCrate].
- Phase 2 account authentication uses `opaque-ke` against RFC 9807 for core registration/login behavior, keeping relay authentication separate from local vault decryption [@rfc9807; @opaqueKeCrate].

## Core Research Questions

1. How can a zero-knowledge password manager support business recovery without giving the server escrowed plaintext or keys?
2. Which metadata must remain visible for sync and admin function, and how can its leakage be minimized and documented honestly?
3. What revocation guarantees are cryptographically possible, and how should the product communicate the gap between future access and past knowledge?
4. When does MLS become worth its complexity compared with per-user HPKE envelopes?
5. Can optional P2P sync improve resilience without degrading reliability, privacy, or supportability?

## Evaluation Plan

- Security analysis against the threat model in `/core/src/lib.rs`.
- Protocol test vectors for every serialized cryptographic object.
- Property tests for serialization, AAD binding, versioning, and key-envelope handling.
- Adversarial tests for rollback, stale epochs, replayed membership events, and revoked devices.
- Usability evaluation of recovery and offboarding flows.

## Non-Claims

- The system is not proven secure merely because it uses standard primitives.
- Revocation cannot erase a secret already learned by a removed member.
- A weak master password remains weak despite Argon2id.
- Browser extension compromise can defeat many client-side guarantees.
- Optional P2P does not eliminate the need for reliable encrypted availability.

## Paper Readiness Checklist

- [ ] Every technical claim has a citation, experiment, or implementation reference.
- [ ] Related work compares against existing zero-knowledge password managers and local-first sync systems.
- [ ] The protocol section matches the implemented wire/storage formats.
- [ ] Evaluation includes tests, attack scenarios, limitations, and reproducibility notes.
- [ ] Limitations are explicit and not hidden in marketing language.
- [ ] References are maintained in `docs/research/references.bib`.
