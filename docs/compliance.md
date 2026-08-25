# Compliance

Index of regulations the product respects and the data flows that depend on them. Required by `.cursor/rules/compliance-and-regulation.mdc`.

## Regulations Tracked

- GDPR (EU 2016/679)
- NIS-2 (EU 2022/2555)
- UK GDPR
- Swiss FADP
- ISO/IEC 27001 alignment
- SOC 2 readiness
- HIPAA when health data is in scope

## Data Flow Inventory

| Data Category | Lawful Basis | Location Of Processing | Retention Rule | Deletion Mechanism | Visible To Relay | Visible To Client |
|---------------|--------------|------------------------|----------------|--------------------|------------------|-------------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _ciphertext only?_ | _plaintext?_ |

## Subprocessors

| Name | Purpose | Region | DPA Status | Date Added |
|------|---------|--------|------------|------------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |

## Self-Hosting

- Document data residency per deployment.
- Document single-tenant vs multi-tenant relay modes.
- Document operator responsibilities (backup, key management for SQLCipher database key, OPAQUE server setup secret).

## Logging And Telemetry

- Plaintext, key material, item identifiers, and recovery material are forbidden in logs, telemetry, and crash reports.
- Sampling rules and redaction policies live here.

## Pre-Release Checklist

- Each release tag requires a regulatory checklist pass recorded below with date and reviewer.
- Paid releases require an external compliance review.

| Release | Date | Reviewer | Findings | Status |
|---------|------|----------|----------|--------|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
