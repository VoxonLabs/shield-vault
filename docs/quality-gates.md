# Quality Gates

Use these gates before marking a milestone complete.

## Product Experience Gate

- The user-facing flow has a clear happy path, empty state, loading state, error state, and recovery path.
- Security-sensitive actions require deliberate confirmation: share, revoke, recover, export, delete, trust device, rotate key.
- Copy explains guarantees honestly and does not imply impossible protection.
- Failure states tell the user what happened and what to do next without leaking secrets.
- Default behavior is safe: locked, private, least-permission, no surprise network or clipboard behavior.

## Testing Gate

- Unit tests cover core logic and important failure cases.
- Security-sensitive code has negative tests: wrong key, wrong AAD, tampered ciphertext, stale version, replay, revoked identity when applicable.
- Crypto-lab code uses official vectors where available.
- Production crypto code uses audited crates and tests object formats, AAD binding, and serialization compatibility.
- Add property/fuzz tests when parsing, serialization, merge logic, or protocol state machines become non-trivial.

## Build Gate

For Rust work:

```bash
cargo fmt --all
cargo test --workspace
cargo clippy --workspace --all-targets
```

For future frontend work:

```bash
npm run lint
npm run test
npm run build
```

Use the package manager and scripts actually present in the project. Do not invent commands if scripts are missing.

## Deployment Gate

Do not deploy or package a component until:

- Configuration is validated at startup.
- Logs and telemetry are reviewed for plaintext/key leakage.
- Secrets are passed through environment or OS secret stores, not committed files.
- Health checks exist for services.
- Release artifacts are reproducible and, eventually, signed.
- Rollback instructions exist.
- The deployment target and threat model are documented.

## Stop Rule

If a gate fails, fix it if the fix belongs to the same milestone. If the fix expands scope, stop and report the blocker.

