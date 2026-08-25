# Shield Vault

Shield Vault is a local-first, zero-knowledge, end-to-end encrypted team password manager in active development.

The practical product direction is a self-hostable encrypted relay plus optional P2P/LAN sync. The relay should never receive plaintext, master passwords, master keys, vault keys, or recovery shares.

## Current Status

This repository is in Phase 1: crypto foundation.

Implemented so far:

- Rust workspace with `/core`, `/crypto-lab`, `/relay`, and `/desktop` placeholders.
- `/crypto-lab` educational Argon2id implementation passing the RFC 9106 test vector.
- `/crypto-lab` educational XChaCha20-Poly1305 implementation passing published HChaCha20, Poly1305, and AEAD vectors.
- `/core` single-user vault create/unlock and item encrypt/decrypt using audited crates.
- `/core` SQLCipher-backed local storage for encrypted vault headers and item records.
- `/core` OPAQUE registration/login helpers using `opaque-ke`.
- Production single-user vault, crate choice, and local storage specs under `docs/specs/`.
- Research notes and a paper draft under `docs/research/`.

Not implemented yet:

- Desktop platform secret-store integration for local database keys.
- Relay endpoints and storage for OPAQUE records.
- Relay endpoints.
- Desktop UI.
- Sharing, recovery, sync, browser extension, or admin features.

## Repository Layout

```text
/core        Production Rust crypto engine. Must use audited crates only.
/crypto-lab  Educational primitive implementations with official vectors.
/relay       Future dumb encrypted relay server.
/desktop     Future desktop shell.
/docs        Project workflow, specs, research notes, and quality gates.
```

`/crypto-lab` is for learning only. Production code in `/core` must not import or copy lab cryptography.

## Security Posture

Shield Vault is not production-ready and has not been audited.

Current design rules:

- All encryption and decryption happens client-side.
- Servers and relays store only ciphertext, public keys, OPAQUE records, sync events, and necessary metadata.
- Production crypto uses audited crates.
- Educational crypto remains isolated in `/crypto-lab`.
- Revocation protects future epochs only; it cannot erase secrets already decrypted by a removed user.
- Recovery must be a client-side threshold ceremony, not a server-side password reset.

## Development

Install Rust stable with `rustfmt` and `clippy`. See `docs/setup.md` for the verified local toolchain.

Run the Rust quality gate:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Workflow

Project state is tracked in `docs/progress.md`.

When continuing work:

1. Read `RULES.md`, `plan.md`, `.cursor/rules/`, and `docs/start-workflow.md`.
2. Continue the next incomplete milestone from `docs/progress.md`.
3. Research current official sources before dependency, protocol, crypto, sync, recovery, browser-extension, or paper-claim decisions.
4. Write tests first for crypto-lab and security-sensitive `/core` behavior.
5. Update research notes, paper notes, and progress when a milestone changes them.

## Research Direction

The working research thesis is:

> A practical zero-knowledge SMB password manager should optimize for client-side cryptographic authority, auditable key lifecycle events, and reliable encrypted availability rather than pure decentralization.

See `docs/research/paper.md` and `docs/research/research-log.md` for the evolving paper and source-backed decisions.

## License

The workspace is configured as `MIT OR Apache-2.0`.

