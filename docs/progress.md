# Progress

This file tracks project completion for automated `let's start` sessions.

## Overall

Estimated completion: 15%

Status: Phase 1 crypto foundation is complete for the current scope. The Rust workspace exists, CI is configured, educational Argon2id and XChaCha20-Poly1305 vectors pass, `/core` supports single-user vault create/unlock plus item encrypt/decrypt with audited crates, and SQLCipher-backed local storage is implemented.

## Phase 0 - Project Operating System

Estimated completion: 85%

- [x] Rust workspace scaffolded.
- [x] Rust installed and verified locally.
- [x] Persistent Cursor rules created.
- [x] Human-readable `RULES.md` created.
- [x] `.gitignore` created.
- [x] Research log scaffolded.
- [x] Paper draft scaffolded.
- [x] Start workflow automation rule created.
- [x] Stop-point and anti-overengineering rules created.
- [x] UX, testing, build, and deployment quality gates created.
- [x] Safe git automation rules created.
- [x] Full safe `let's do` automation mode defined.
- [x] Decision research protocol created.
- [x] Documentation discipline and citation rules created.
- [x] Project README created.
- [x] Initialize git repository when the user wants version control enabled.
- [x] Decide whether to add CI now or after `/core` starts.
- [x] Minimal Rust CI workflow added.

## Phase 1 - Crypto Foundation

Estimated completion: 100%

- [x] `/crypto-lab` crate scaffolded.
- [x] Argon2id educational implementation added.
- [x] RFC 9106 Argon2id test vector passes.
- [x] Research and choose production `/core` crypto crate versions.
- [x] Add educational XChaCha20-Poly1305 test vectors in `/crypto-lab`.
- [x] Implement educational XChaCha20-Poly1305 in `/crypto-lab`.
- [x] Specify `/core` single-user vault item format.
- [x] Specify AAD schema and serialization.
- [x] Implement production `/core` single-user encrypt/decrypt using audited crates.
- [x] Add local storage design for SQLite/SQLCipher.
- [x] Implement local storage with SQLite/SQLCipher.

## Phase 2 - OPAQUE Authentication

Estimated completion: 78%

- [x] Research current `opaque-ke` crate version and RFC 9807 compatibility.
- [x] Write OPAQUE registration/login flow spec.
- [x] Add OPAQUE registration/login tests.
- [x] Implement client-side flow in `/core`.
- [ ] Add relay storage for OPAQUE records.

## Phase 3 - Desktop App

Estimated completion: 0%

- [ ] Re-check Tauri v2 prerequisites.
- [ ] Scaffold Tauri + React app.
- [ ] Add unlock UI.
- [ ] Add item list/detail/create/edit/delete UI.
- [ ] Wire UI to `/core` commands.

## Later Phases

- Phase 4 sharing via HPKE: 0%.
- Phase 5 recovery ceremony: 0%.
- Phase 6 sync and optional P2P: 0%.
- Phase 7 browser extension: 0%.
- Phase 8 org admin and audit log: 0%.

## Next Default Milestone

Add relay storage for OPAQUE server setup and password files.

