//! Educational cryptography implementations for Shield Vault.
//!
//! Nothing in this crate is production crypto. The shipping `shield-vault-core`
//! crate must use audited libraries instead of depending on this code.

pub mod argon2id;
pub mod xchacha20_poly1305;
