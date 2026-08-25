# Audits

Index of external cryptographic and security audits. Required by `.cursor/rules/audit-trigger.mdc`.

## Triggers

- Protocol design review by an external applied cryptographer before Phase 4 ships.
- Implementation audit of `/core` before tagging `v0.1.0`.
- Browser-extension audit before Phase 7 ships.
- Recovery ceremony review before Phase 5 ships.
- Re-audit after any change to wire format, key derivation, AAD schema, membership log, or revocation semantics.

## Catalog

| Audit | Scope | Auditor | Date | Report Location | Critical | High | Medium | Low | Re-Test Date |
|-------|-------|---------|------|-----------------|----------|------|--------|-----|--------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _0_ | _0_ | _0_ | _0_ | _fill in_ |

## Severity Rules

- Critical and high findings block the release.
- Medium findings require a documented remediation plan.
- Low findings require a tracked issue.

## Pre-Audit Hardening

- Clean clippy with `-D warnings`.
- Every `unsafe` block has a written justification.
- Dependency tree reviewed against RustSec.
- Fuzz harnesses for serialization and AAD parsing.
- Threat model up to date in `core/src/lib.rs` and `docs/research/paper.md`.
