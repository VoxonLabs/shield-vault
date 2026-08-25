# Decision Research Protocol

Use this before important technical, product, crypto, dependency, deployment, or paper-claim decisions.

## When Required

Run decision research before:

- Adding or replacing dependencies.
- Choosing crypto/protocol parameters.
- Designing storage formats, sync behavior, recovery, sharing, or revocation.
- Making browser-extension permission or autofill decisions.
- Making deployment, CI, telemetry, logging, or secret-handling choices.
- Claiming novelty, market position, or research contribution in the paper.

## Source Priority

Prefer sources in this order:

1. Standards: RFCs, NIST/FIPS, IETF drafts, W3C, platform security docs.
2. Upstream docs: crate/package docs, official framework docs, changelogs, migration guides.
3. Security sources: RustSec, CVEs, GitHub advisories, audit reports, maintainer issue trackers.
4. Peer-reviewed or reputable research papers.
5. Mature production examples from respected open-source projects.
6. Blog posts only as supporting context, not the main authority.

## Search Pattern

For each decision:

1. Search the current official source.
2. Search for security advisories and deprecation/maintenance status.
3. Search for best-practice comparisons or production usage.
4. Compare at least two viable options when alternatives exist.
5. Record the decision in `docs/research/research-log.md` if it affects architecture, security, dependencies, or paper claims.

## Decision Template

```markdown
## YYYY-MM-DD Decision Name

### Question

What decision are we making?

### Sources Checked

- Source name, version/date: URL

### Options Compared

- Option A: strengths, weaknesses, security/product risks.
- Option B: strengths, weaknesses, security/product risks.

### Decision

Chosen option and why it is best for the current phase.

### Alternatives Rejected

Why each rejected option is not selected now.

### Risk If Wrong

What breaks if this decision is wrong, and how we can migrate later.
```

## Stop Conditions

Stop and ask the user before coding if:

- Research contradicts the existing plan.
- The safest choice changes architecture or phase order.
- All options are immature, unmaintained, or risky.
- A decision has product/legal/security implications beyond the current milestone.

