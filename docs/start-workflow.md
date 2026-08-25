# Start Workflow

This is the automation contract for future sessions.

## Trigger

When the user says `let's start`, `start`, `continue`, or asks to proceed without a narrower task, begin the next incomplete phase from `docs/progress.md`.

When the user says `let's do`, enter full safe automation mode. In this mode, continue milestone-by-milestone across phases, use git automation, update research/paper/progress continuously, and stop only for safety stops or external blockers.

## Required Startup Sequence

1. Read the persistent context:
   - `RULES.md`
   - `plan.md`
   - `.cursor/rules/*.mdc`
   - `docs/progress.md`
   - `docs/quality-gates.md`
   - `docs/engineering-principles.md`
   - `docs/git-workflow.md`
   - `docs/research/decision-research.md`
   - `docs/research/research-log.md`
   - `docs/research/paper.md`
   - `docs/research/references.bib`
2. Identify the next incomplete milestone.
3. State before work:
   - Current phase.
   - Cryptographic/product guarantee.
   - What it does not guarantee.
   - Current crates/packages and versions to use.
   - Tests to write first.
   - Latest information that must be checked online using `docs/research/decision-research.md`.
   - Silent failure risks.
4. Work in a loop:
   - Research current sources.
   - Use the decision research protocol before major choices.
   - Update research notes when decisions depend on sources.
   - Write or update tests before implementation where practical.
   - Implement the next milestone.
   - Update paper notes if the work affects the research direction, and add citations to `docs/research/references.bib` for new claims.
   - Do not create or expand docs unless they support the product, preserve a decision, enable automation, or improve the publishable paper.
   - Apply the relevant quality gates from `docs/quality-gates.md`.
   - Run formatting, tests, lints, and builds required by the milestone.
   - If git automation was explicitly requested, follow `docs/git-workflow.md`.
   - Update `docs/progress.md`.
   - Report percent complete and next milestone.

## Stop Points

Stop and report when any of these happens:

- One milestone from `docs/progress.md` is complete, unless running in `let's do` full automation mode.
- Tests, linting, dependency installation, or system packages block progress.
- The next change would alter architecture or expand scope.
- A security trade-off is discovered.
- Current research contradicts the plan.
- Decision research reveals safer or better current practice with major architecture impact.
- The implementation starts needing abstractions for future phases rather than the current milestone.
- Git cannot be made safe because of unrelated dirty files, possible secrets, protected branch uncertainty, or merge conflicts.
- Deployment, push, external services, credentials, paid services, or production infrastructure are required without clear authorization.

By default, do not roll directly into the next milestone. Ask or wait for the next `let's start`.

In `let's do` mode, roll into the next milestone automatically after checks, docs, progress, git commit/merge, and cleanup are complete.

## Full Safe Automation Mode

`let's do` means:

- Read all project docs and relevant strategy notes.
- Work through `docs/progress.md` from the next incomplete milestone onward.
- Research current official sources before security-sensitive or dependency decisions.
- Use the research decision docs when strategy, market positioning, P2P, recovery, or research claims matter.
- Write tests first where practical.
- Implement production-quality code for the current milestone.
- Apply quality gates.
- Run checks and builds.
- Create or use a focused git branch per milestone.
- Commit after checks pass.
- Merge after checks pass when the target branch is clear and safe.
- Delete local merged milestone branches.
- Update `docs/progress.md`, research notes, and paper notes.
- Continue to the next milestone until blocked.

`let's do` does not mean:

- Skip phases.
- Force-push.
- Rewrite shared history.
- Commit secrets or unrelated user changes.
- Deploy to production without deployment target and credential clarity.
- Hide failed checks or security trade-offs.

## End Result

The long-term end result of repeated `let's do` runs is:

- A production-quality local-first, zero-knowledge team password manager.
- `/crypto-lab` remains educational with RFC/vector-backed learning implementations.
- `/core` provides audited-crate production encryption, item formats, key management, recovery, sharing, and sync primitives.
- `/relay` provides a dumb encrypted relay with no plaintext access.
- `/desktop`, `/browser-ext`, and later admin surfaces provide clean user experiences with safety-focused UX.
- Research notes, `docs/research/paper.md`, and `docs/research/references.bib` evolve alongside the implementation.
- Documentation stays lean: no filler docs, no repeated summaries, no notes that do not support the product or paper.
- Every completed milestone is tested, documented, committed, merged, and reflected in `docs/progress.md`.

A single `let's do` run ends when:

- The project reaches the next major human decision point.
- A safety stop is hit.
- External credentials/infrastructure are required.
- The requested runtime budget or environment limits make continuing impractical.
- All tracked milestones are complete.

## Anti-Overengineering Check

Before each implementation step, ask:

- Does this serve the current milestone, or a future phase?
- Can a narrower type, function, or module express the same invariant?
- Is this abstraction justified by real duplication or a security boundary?
- Could this dependency be avoided without making security worse?
- Will a reviewer understand this in one pass?
- Does this make invalid states harder to represent?

## Completion Report Format

Every substantial run should end with:

```text
Phase:
Milestone completed:
Progress:
Checks run:
Builds run:
Quality gates:
Git state:
Research updated:
Paper updated:
Risks / blockers:
Next recommended step:
```

## Default Next Work

If no specific task is given, continue Phase 1 from `docs/progress.md`.
