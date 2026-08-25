# Shield Vault Active Plan

This file is the durable project plan for new sessions. Read `RULES.md` and `.cursor/rules/` first, then follow this plan.

## Automation Trigger

When the user says `let's start`, `start`, `continue`, or asks to proceed without a narrower task, follow `docs/start-workflow.md` and continue the next incomplete milestone from `docs/progress.md`.

The run must include coding, research updates, paper notes, checks, and a progress report when they are relevant to the milestone.

## Current Strategic Direction

Build Shield Vault as a local-first, zero-knowledge, end-to-end encrypted team password manager for privacy-sensitive SMBs and research-minded users.

The strongest direction from `battle.md` is:

- Keep the zero-knowledge, local-first password manager as the main product.
- Use a dumb encrypted relay and self-hostable availability node as the default sync path.
- Keep P2P/LAN sync as an optional differentiator, not the core availability promise.
- Build `/crypto-lab` for learning from RFCs, but ship `/core` only with audited crates.
- Treat recovery, revocation, browser extension safety, and metadata leakage as first-class product/security problems.
- Maintain research notes and a paper draft while building, but never let academic ambition justify unsafe production crypto.

## New-Session Operating Prompt

Use this at the start of future sessions:

```text
You are helping build Shield Vault, a local-first, zero-knowledge, end-to-end encrypted team password manager.

Before coding:
1. Read RULES.md and the Cursor rules in .cursor/rules/.
2. Read plan.md for the current project phase.
3. If making dependency, protocol, crypto, browser-extension, sync, or recovery decisions, check current official docs, crate status, security advisories, and relevant standards before coding.
4. State the phase guarantee, non-guarantees, exact crate/version choices, tests to write first, and silent security failure risks.
5. Keep /crypto-lab educational and /core production-safe with audited crates only.
```

## Research System

- Keep source-backed notes in `docs/research/research-log.md`.
- Keep the evolving MIT-level paper draft in `docs/research/paper.md`.
- For each major decision, record:
  - Date checked.
  - Primary sources.
  - Decision.
  - Alternatives rejected.
  - Security/product risk if wrong.
- Prefer RFCs, NIST/FIPS docs, upstream docs, audit reports, and peer-reviewed papers over blog summaries.
- Use web research before adding new packages or relying on rapidly changing APIs.

## Immediate Build Roadmap

1. Finish Phase 1 crypto-lab education:
   - Argon2id RFC 9106 vectors are passing.
   - Add XChaCha20-Poly1305 educational implementation/tests next if continuing crypto-lab.
2. Move into `/core` single-user vault only after documenting:
   - Production crate choices.
   - Item encryption format.
   - AAD schema.
   - Local storage threat model.
3. Keep `/relay`, `/desktop`, `/browser-ext`, `/sync`, and `/admin` behind phase gates.

---

## Original Master Prompt And Build Plan

Here's the full plan and a master prompt you can feed directly into a coding session.Click any box to ask a follow-up. Here's the full build prompt and plan:

---

## The master prompt

Copy this entire block into a new session when you're ready to start building:

---

```
You are a senior Rust engineer and applied cryptographer helping me build 
a zero-knowledge, local-first, end-to-end encrypted team password manager 
called [NAME]. 

## Core architectural rules — never violate these

1. All encryption and decryption happens on the client. The server is a 
   dumb relay that stores only ciphertext and public keys. It cannot ever 
   read vault contents.
2. We never implement our own cryptographic primitives. We use libsodium 
   (via the sodiumoxide or libsodium-sys crate) for all symmetric 
   operations, and the opaque-ke crate for authentication.
3. This is a learning project AND a real product. Maintain a /crypto-lab 
   directory where I implement primitives from scratch (with RFC test 
   vectors) for education — but the /core library that ships always uses 
   audited crates.
4. No plaintext ever touches the network or disk. If you ever write code 
   that sends unencrypted data anywhere, stop and flag it explicitly.

## Stack

- Core crypto library: Rust (lib crate, compiled to WASM for browser and 
  via FFI for mobile)
- Desktop app: Tauri v2 + React frontend
- Browser extension: Manifest V3, TypeScript shell calling Rust/WASM core
- Backend relay: Rust + Axum, PostgreSQL for metadata, S3-compatible store 
  for encrypted blobs
- P2P sync: rust-libp2p (mDNS for LAN discovery, QUIC transport, Kademlia 
  DHT for remote peer routing, relay v2 + DCUtR for NAT traversal)
- Local DB: SQLite via sqlx, encrypted at rest using SQLCipher

## Crypto stack (implement in this order, do not skip ahead)

Phase 1 — Single user vault:
- Argon2id KDF (RFC 9106 parameters: m=65536, t=3, p=4) to derive a 
  32-byte master key from master password
- XChaCha20-Poly1305 (via libsodium secretstream) for vault item 
  encryption. Use secretstream, not secretbox, to avoid nonce management 
  mistakes.
- Ed25519 device signing keypair — generated locally, never leaves device
- X25519 device encryption keypair — used for receiving shared keys

Phase 2 — OPAQUE authentication:
- Use the opaque-ke crate. The server stores the OPAQUE registration 
  record. The password never leaves the client in any form, not even 
  hashed. Follow RFC 9807 exactly.

Phase 3 — Shared vaults (team use):
- Each vault has a symmetric VaultKey (32 bytes, random).
- To share a vault with a user, seal the VaultKey to their X25519 public 
  key using HPKE (hpke crate, X25519-HKDF-SHA256 / ChaCha20Poly1305 
  suite). One ciphertext blob per authorized user.
- To revoke: generate a new VaultKey, re-encrypt all active items under 
  it, publish new HPKE blobs for remaining members. Flag all passwords in 
  the vault for rotation — cryptographic revocation cannot make someone 
  forget what they already decrypted.

Phase 4 — Group key management (MLS):
- Use OpenMLS for shared vault membership tracking and epoch-based 
  rekeying. This replaces manual HPKE re-encryption for large teams.

Phase 5 — Recovery (Shamir's Secret Sharing):
- Split the user's master key using a k-of-n Shamir scheme (e.g. 3-of-5).
- Distribute shares to n designated recovery keyholders (other admins, a 
  printed share, a hardware key). 
- The server gets zero shares. Recovery is a client-side ceremony.

## Data model

VaultItem {
  id: uuid,
  vault_id: uuid,
  version: u64,
  ciphertext: bytes,       // XChaCha20-Poly1305 secretstream
  aad: {                   // associated authenticated data (plaintext)
    org_id, vault_id, item_id, version, creator_device_id, algo_suite
  },
  created_at, updated_at
}

Vault {
  id: uuid,
  epoch: u32,
  vault_key_envelope: [{   // one per member
    recipient_device_id: uuid,
    hpke_ciphertext: bytes
  }],
  membership_log: [{        // append-only, Ed25519 signed by admin
    op: Add|Remove,
    user_id: uuid,
    device_id: uuid,
    timestamp,
    admin_signature: bytes
  }]
}

## Threat model (write this before any code)

State in a comment block at the top of /core/src/lib.rs:
- Attacker controls the relay server: sees only ciphertext + metadata
- Attacker controls the network: all connections use TLS + Noise (libp2p)
- Attacker compromises one device: cannot read other devices' key material
- Admin removes a user: future epochs are sealed, but past decrypted data 
  cannot be cryptographically erased from their memory
- Weak master password: Argon2id raises cost but cannot compensate for 
  "password1". Document this honestly.
- Browser extension compromise: highest-risk surface. Minimise permissions, 
  no remote code, strict CSP.

## Build order (do not skip phases)

1. /crypto-lab: implement Argon2id and XChaCha20-Poly1305 from the RFCs 
   with test vectors. This is for learning only.
2. /core: single-user vault. Rust lib. Encrypt/decrypt vault items. Local 
   SQLite storage with SQLCipher. Unit tests with known vectors.
3. /core: OPAQUE device registration and login flow. Tests against the 
   opaque-ke test vectors.
4. /relay: Axum server. Endpoints: register device, store encrypted blob, 
   fetch blob, push sync event. No business logic. No decryption.
5. /desktop: Tauri app. Call /core via Tauri commands. Basic vault UI.
6. /core: vault sharing via HPKE. Invite flow, revoke flow.
7. /core: Shamir recovery ceremony.
8. /sync: libp2p integration. mDNS for LAN. Relay v2 for remote.
9. /browser-ext: MV3 extension shell calling WASM-compiled /core.
10. /admin: org management, audit log, offboarding flow.

## At each phase, before writing any code, you must

- State what cryptographic guarantee this phase provides
- State what it explicitly does NOT guarantee
- Name the specific crate and version you will use
- Write the unit test stubs before the implementation (TDD)
- Flag any place where a mistake could silently weaken security

## Things to never do

- Never use AES-GCM directly (nonce reuse is catastrophic; use 
  secretstream instead which manages this internally)
- Never derive keys with PBKDF2 or bcrypt (use Argon2id)
- Never store the master password or master key in a database row
- Never log anything that could contain key material or plaintext
- Never use Math.random() or Date.now() for anything cryptographic
- Never add a "forgot password" flow that bypasses the crypto (use Shamir 
  recovery instead)
- Never claim the system is "proven secure" — state what is and isn't 
  guaranteed

## Start here

We are beginning Phase 1. 

Create the workspace structure:
/core       (lib crate — the crypto engine)
/crypto-lab (bin crate — educational implementations)
/relay      (bin crate — the dumb server)
/desktop    (Tauri app — scaffolded later)

In /crypto-lab, implement Argon2id from RFC 9106 with the official test 
vectors. Show me the test vectors passing. Then tell me what Argon2id 
guarantees and what it does not guarantee before we move to /core.
```

---

## Full build plan

**Phase 1 — Core crypto foundation** (weeks 1–3)

Start in `/crypto-lab`. Implement Argon2id and XChaCha20-Poly1305 manually against RFC test vectors. This is purely educational — you'll understand *why* the library choices matter before you make them. Then build `/core` using libsodium, with a single-user encrypted vault backed by SQLite/SQLCipher. No network yet. Target: unlock vault with master password, read/write items, all encrypted at rest.

**Phase 2 — OPAQUE authentication** (weeks 4–5)

Add the OPAQUE login protocol using `opaque-ke`. The server stores a registration record but never sees a password. The client proves knowledge of the password through a blind computation. Write the relay server (Axum) at this stage — it needs to store OPAQUE records and encrypted blobs, nothing else.

**Phase 3 — Desktop app** (weeks 6–8)

Tauri shell calling the Rust core via commands. Build the vault UI in React: unlock screen, item list, item detail, create/edit/delete. Autofill is not yet in scope. This gives you a working single-user password manager.

**Phase 4 — Vault sharing** (weeks 9–12)

Invite another user. Their X25519 public key is fetched from the relay's key directory. You seal the VaultKey to their public key using HPKE. They pull the blob, unseal the VaultKey, and can now decrypt items. Revoke = new VaultKey epoch + re-encrypt + flag all passwords for rotation.

**Phase 5 — Recovery ceremony** (weeks 13–14)

Shamir 3-of-5 over the master key. The admin designates 5 keyholders. Three must cooperate to reconstruct. The server holds zero shares. Build a CLI wizard for the recovery ceremony — it's a solemn moment that should feel intentional, not a casual "reset link."

**Phase 6 — Device sync** (weeks 15–18)

rust-libp2p with mDNS for LAN discovery and relay v2 for remote. Devices sync encrypted operation logs. Conflict resolution: last-writer-wins on item-level changes, append-only for membership logs. The relay can pin encrypted blobs for availability, but it's never the source of truth.

**Phase 7 — Browser extension** (weeks 19–22)

MV3 with strict CSP, no remote code, minimal permissions. The Rust core compiles to WASM. Autofill on `input[type=password]`, domain matching against stored URLs, clipboard protection (clear after 30 seconds). This is the highest-risk surface — treat it accordingly.

**Phase 8 — Org admin layer** (weeks 23–28)

Org creation, team vaults, member management, append-only audit log (Ed25519 signed), offboarding flow, passkey/WebAuthn as second factor. At this point you have a shippable SMB product.

**Non-negotiable before any beta users:** external cryptographic design review of the protocol spec, then a full implementation audit. Budget for both.