# Git Workflow

Git automation is available when explicitly requested for the current run. The phrase `let's do` is explicit opt-in for full safe git automation.

## Opt-In Commands

Examples:

- `commit this`
- `auto-git this milestone`
- `let's do`
- `create a branch for this`
- `merge if checks pass`
- `push this branch`

Without explicit opt-in, the agent may inspect git state but must not commit, merge, push, rebase, reset, or delete branches.

In `let's do` mode, the agent should use git automatically for each milestone: branch, commit after checks pass, merge when safe, delete local merged branches, and continue.

## Branch Workflow

For non-trivial milestones:

1. Inspect current git state.
2. Warn about unrelated dirty files.
3. Create a focused branch when requested.
4. Keep one milestone per branch.
5. Run relevant checks before commit or merge.

Branch naming:

- `phase-1-core-vault`
- `phase-1-crypto-lab-xchacha`
- `chore-rules-quality-gates`
- `docs-research-notes`

## Commit Workflow

Before committing:

1. Run `git status`.
2. Review staged and unstaged diffs.
3. Review recent commit style.
4. Exclude secrets, credentials, `.env`, local databases, generated scratch files, and unrelated user changes.
5. Run relevant checks.
6. Commit with a concise message focused on why the change exists.

WIP commits are allowed only if the user explicitly asks for a WIP commit.

## Merge Workflow

Merge only when the user explicitly opted in and checks pass. `let's do` is merge opt-in for local milestone branches.

Before merging:

- Confirm the target branch.
- Ensure the feature branch contains only the intended milestone.
- Run checks.
- Prefer normal merges or fast-forward merges.
- Do not force-push or rewrite shared history unless explicitly requested.
- Push only if the user also requested push/deploy or project docs clearly authorize that remote action.

## Cleanup Workflow

Cleanup after a milestone means:

- Remove temporary scratch files created by the agent.
- Delete local milestone branches after they are safely merged.
- Leave ignored build artifacts alone unless cleanup is explicitly requested.
- Update `docs/progress.md`.
- Update research or paper docs if the milestone changed them.
- Report branches, uncommitted files, and any cleanup intentionally left undone.

