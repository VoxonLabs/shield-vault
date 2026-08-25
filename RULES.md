# Shield Vault Rules

These rules are the durable operating contract for every new coding session.

## Start Command

- When the user says `let's start`, `start`, `continue the build`, or gives no narrower task, read the project docs first and continue the next incomplete milestone from `docs/progress.md`.
- When the user says `let's do`, enter full safe automation mode: continue milestone-by-milestone, use git automation, update research/paper/progress, and stop only for safety stops, blockers, or major decision points.
- The startup docs are `RULES.md`, `plan.md`, `.cursor/rules/*.mdc`, `docs/start-workflow.md`, `docs/engineering-principles.md`, `docs/quality-gates.md`, `docs/git-workflow.md`, `docs/progress.md`, `docs/research/decision-research.md`, `docs/research/research-log.md`, `docs/research/paper.md`, and `docs/research/references.bib`.
- Read or skim `battle.md` when strategic direction, P2P, market positioning, or research claims matter.
- End each work run by updating `docs/progress.md` and reporting phase, completed milestone, percent progress, checks, research updates, paper updates, risks, and next step.
- Stop after one milestone by default unless the trigger is `let's do`.

## Product Direction

- Build a local-first, zero-knowledge, end-to-end encrypted team password manager.
- The practical product is self-hostable encrypted relay plus optional P2P/LAN sync, not a pure public P2P password network.
- The server is a dumb relay and coordinator. It stores ciphertext, public keys, OPAQUE records, sync events, and metadata only.
- P2P is a resilience and local-sync feature. It must not become the primary availability story for SMB users.

## Cryptography Rules

- `/crypto-lab` is for learning. It may implement primitives from RFCs with test vectors.
- `/core` is for shipping. It must use audited crates and must not depend on `/crypto-lab`.
- Never write production cryptographic primitives by hand.
- No plaintext, master passwords, master keys, vault keys, or recovery shares may be logged, persisted unencrypted, or sent over the network.
- Use Argon2id for password KDF, libsodium secretstream/XChaCha20-Poly1305 for item encryption, OPAQUE for password authentication, HPKE for vault-key envelopes, and MLS only when team scale justifies it.
- Revocation protects future epochs only. It cannot erase data already decrypted by a removed user.
- Recovery must be a client-side threshold ceremony, not a server-side password reset.

## Research Freshness

- Before adding dependencies or choosing protocol details, check current official docs, crate status, security advisories, and primary standards.
- For cryptography, prefer RFCs, NIST/FIPS publications, upstream crate docs, audit reports, and peer-reviewed work.
- Record non-trivial research decisions in `docs/research/` with source links and dates.
- Pin exact dependencies in lockfiles after selection, but do not pretend pinned means permanently correct.
- Before important decisions, compare viable options using `docs/research/decision-research.md` and choose the best current practice for this phase.
- If current evidence contradicts the old plan, stop and explain the trade-off before coding.

## Coding Workflow

- Before each phase, state the guarantee, non-guarantees, crate/version choices, test plan, and places where mistakes silently weaken security.
- Write test stubs before implementation for crypto-lab and security-sensitive core behavior.
- Keep changes phase-aligned and small enough to review.
- Run formatting and tests after substantive edits.
- Do not market or document the system as "proven secure"; document assumptions, limits, and audit requirements.

## Engineering Discipline

- Prefer simple, reviewable, phase-aligned code over architecture for future phases.
- Add abstractions only for real duplication, protocol boundaries, or security invariants.
- Make invalid states hard to represent with explicit types and narrow APIs.
- Stop and ask before changing architecture, adding major dependencies, or weakening a guarantee.

## Quality Gates

- User-facing work needs happy, empty, loading, error, and recovery states before it is done.
- Security-sensitive work needs negative tests for tampering, wrong keys, wrong AAD, stale versions, replay, or revoked access when applicable.
- Builds must be reproducible from documented commands and lockfiles.
- Deployment requires config validation, non-secret logs, health checks, rollback notes, and no plaintext leakage in telemetry or crash reports.

## Git Automation

- Git commits, branches, merges, pushes, rebases, resets, and branch deletion require explicit user opt-in for the current run. `let's do` is explicit opt-in for branch, commit, merge, and local cleanup automation.
- When opted in, keep one milestone per branch, run checks before commit/merge, exclude secrets and unrelated user changes, merge only when safe, delete local merged branches, then report remaining git state.
- Pushing, deployment, force-push, and shared-history rewrites require separate explicit authorization or clear project-doc authorization.

## Documentation And Paper

- Do not create docs just to create docs. Each doc change must support the product, preserve a decision, enable automation, or improve the publishable paper.
- Prefer updating existing docs over creating new docs.
- Research paper claims need citations in `docs/research/references.bib` and source context in `docs/research/research-log.md`.
- The end goal is a working product and a publishable paper with evidence, citations, evaluation, and limitations.

