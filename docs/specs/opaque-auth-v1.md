# OPAQUE Authentication V1 Plan

Date checked: 2026-05-09

## Scope

This plan covers the first OPAQUE authentication milestone for Shield Vault. It defines crate choice, protocol scope, storage responsibilities, and tests to write before implementation. It does not yet implement relay endpoints, account lifecycle UX, device trust, recovery, or sharing.

## Guarantee

OPAQUE lets a client authenticate with a password without sending the plaintext password, a password hash, or a reusable password-equivalent secret to the relay. The relay stores an OPAQUE registration record and server setup material, but it should not learn the password.

## Non-Guarantees

- OPAQUE does not decrypt vault contents and must not replace `/core` vault encryption.
- OPAQUE does not make a weak password strong by itself; use the crate's Argon2 key-stretching feature.
- Registration still requires a server-authenticated confidential channel, as described by RFC 9807.
- A compromised endpoint can still read plaintext after unlock.
- Account authentication does not provide business recovery or revocation semantics.

## Selected Crate

- Crate: `opaque-ke`
- Version for implementation: `4.0.1`
- Status: latest stable release; `4.1.0-pre.2` exists but is a pre-release.
- RFC status: README states the implementation is based on RFC 9807; the 4.0 line synced with RFC 9807.
- Features for implementation: default features plus `argon2`.

Do not use the pre-release line unless a specific required fix is identified and documented. Do not use the example `ksf::Identity` outside tests or examples; it is for fast examples only.

## Planned Cipher Suite

Use the crate's documented Ristretto-based suite shape:

```text
OprfCs = opaque_ke::Ristretto255
KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>
Ksf = argon2::Argon2<'static>
```

The exact Rust type aliases were finalized during implementation against `opaque-ke` 4.0.1.

## Storage Responsibilities

Relay-side storage will eventually need:

- Serialized `ServerSetup` or equivalent server setup secret material.
- One serialized OPAQUE password file / registration record per account identifier.
- Account identifier metadata needed to retrieve the correct record.

Security rules:

- `ServerSetup` secret material is relay-secret operational data and must not be logged.
- Registration upload / password file material is sensitive, roughly password-hash equivalent, and must be protected at rest.
- The relay still never receives vault plaintext, master passwords, master keys, unwrapped vault keys, or recovery shares.

Client-side storage will eventually need:

- Server public setup key pinning or consistency checks where exposed by the crate.
- No persisted master password or password-equivalent OPAQUE client state after a flow finishes.

## Protocol Notes

- Use dummy login behavior for unknown accounts so the relay does not reveal whether an account exists.
- Verify server public key consistency between registration and login when the API exposes it.
- Treat OPAQUE session keys as authentication/session material, not vault encryption keys.
- Keep OPAQUE account authentication separate from local vault unlock. A user may authenticate to the relay and still need the local vault secret material to decrypt.

## Registration Flow

Registration is a four-step flow over a server-authenticated confidential channel.

```text
Client                                            Relay
------                                            -----
ClientRegistration::start(password)
  -> RegistrationRequest
                           RegistrationRequest ->
                                      ServerRegistration::start(
                                        ServerSetup,
                                        RegistrationRequest,
                                        credential_identifier
                                      )
                                      -> RegistrationResponse
                         <- RegistrationResponse
ClientRegistration::finish(
  password,
  RegistrationResponse,
  ClientRegistrationFinishParameters
)
  -> RegistrationUpload
  -> optional export_key
                             RegistrationUpload ->
                                      ServerRegistration::finish(
                                        RegistrationUpload
                                      )
                                      -> password_file
                                      persist password_file
```

V1 registration inputs:

- `account_id`: stable relay account identifier, normalized before use.
- `credential_identifier`: bytes derived from the relay account identifier. It must match lookup storage for the final password file.
- `password`: client-only bytes. Never log, persist, or send directly.
- `server_setup`: relay secret setup material generated once for the relay deployment or tenant.

V1 registration outputs:

- Relay stores serialized `password_file` keyed by `account_id`.
- Relay stores or already has serialized `server_setup`.
- Client may receive `server_public_key` or equivalent consistency material where the crate exposes it.
- Client does not persist OPAQUE transient state after registration finishes.
- Do not use `export_key` for vault encryption in V1.

## Login Flow

Login is a four-step flow with three messages.

```text
Client                                            Relay
------                                            -----
ClientLogin::start(password)
  -> CredentialRequest
                             CredentialRequest ->
                                      lookup password_file(account_id)
                                      ServerLogin::start(
                                        ServerSetup,
                                        Option<password_file>,
                                        CredentialRequest,
                                        credential_identifier,
                                        ServerLoginParameters
                                      )
                                      -> CredentialResponse
                                      -> ServerLogin state
                         <- CredentialResponse
ClientLogin::finish(
  password,
  CredentialResponse,
  ClientLoginFinishParameters
)
  -> CredentialFinalization
  -> client_session_key
                           CredentialFinalization ->
                                      ServerLogin::finish(
                                        CredentialFinalization,
                                        ServerLoginParameters
                                      )
                                      -> server_session_key
```

V1 login rules:

- If `account_id` is missing, call the crate's dummy/missing-account path with `None` for the password file rather than returning early.
- Return a generic authentication failure for wrong password, missing account, malformed credentials, or finalization failure.
- Compare client and server session keys only in tests; production should use the session material to authenticate the relay session or derive application session state.
- Drop client and server transient login state after the flow completes.

## Relay API Shape

The first relay API should remain dumb and OPAQUE-specific:

```text
POST /opaque/register/start
  request:  account_id, registration_request
  response: registration_response

POST /opaque/register/finish
  request:  account_id, registration_upload
  response: success

POST /opaque/login/start
  request:  account_id, credential_request
  response: credential_response

POST /opaque/login/finish
  request:  account_id, credential_finalization
  response: success, relay_session_token_or_material
```

The relay endpoints must not accept vault plaintext, local vault keys, master passwords, recovery shares, or item payloads.

## Serialization Boundaries

- Use `opaque-ke` serialization for OPAQUE protocol messages and password files.
- Wrap stored blobs in Shield Vault records that include `format_version`, `opaque_ke_version`, `cipher_suite_id`, and creation/update timestamps.
- Do not reinterpret OPAQUE blobs with BCS unless the blob is an opaque byte field inside a Shield Vault storage record.
- Record compatibility tests before changing `opaque-ke` versions.

## Tests To Write First

- Registration round trip produces a serializable server password file.
- Login with the correct password succeeds.
- Client and server derive the same session key.
- Login with the wrong password fails.
- Serialized server setup and password file deserialize and remain usable.
- Dummy login path for a missing account does not reveal account existence through the message shape.
- No debug output or errors include passwords, session keys, registration uploads, server setup secrets, or password files.

## Silent Security Failure Risks

- Accidentally using `ksf::Identity` in production.
- Treating OPAQUE export keys or session keys as vault keys.
- Logging serialized registration records or server setup material.
- Skipping server public key consistency checks.
- Leaking account existence by returning distinguishable login errors too early.
- Confusing OPAQUE account authentication with client-side vault recovery.

