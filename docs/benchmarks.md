# Benchmarks

Single source of truth for measured numbers used in the paper, the README, and release notes. Required by `.cursor/rules/benchmarks.mdc`.

## How To Add A Benchmark

1. Decide what is being measured and why the paper or release notes need it.
2. Implement using `criterion` or a documented `cargo bench` setup. Single-shot timings without warmup do not count.
3. Add an entry to the table below with the command to reproduce it.
4. Commit the script that produced any plot to `docs/research/figures/` alongside the figure.
5. Re-run before release tags and before paper submission.

## Required Per Phase

- Phase 1: Argon2id KDF latency at chosen `(m, t, p)`; vault encrypt/decrypt throughput; SQLCipher open/close cost; plaintext-not-present scan.
- Phase 2: OPAQUE registration round-trip; OPAQUE login round-trip; dummy-account login timing parity.
- Phase 3: cold start; unlock latency; item-list render at 1k and 10k items; memory peak.
- Phase 4: HPKE seal/open per recipient; vault rotation cost.
- Phase 5: Shamir share generation; share reconstruction; recovery ceremony end-to-end.
- Phase 6: sync delta latency; conflict resolution cost.
- Phase 7: extension cold start; autofill latency; clipboard clear latency.
- Phase 8: audit log append latency; verifiable log integrity check time.

## Catalog

| Name | What It Measures | Command | Last Result | Hardware | OS | Toolchain | Date |
|------|------------------|---------|-------------|----------|----|-----------|----|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |

## Regression Policy

If a benchmark regresses by more than 20% between runs, stop the autonomous loop, investigate, and record the cause in `docs/research/research-log.md` before continuing.
