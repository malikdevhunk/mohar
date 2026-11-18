//! Authority seals.
//!
//! A seal is RFC 8785 canonical JSON. The signature covers every field
//! except `signatures` itself, so a changed byte in the IR, the authority
//! list or the hashes fails verification. Keys are ML-DSA-65 seeds, which
//! is the serialization RustCrypto prefers over a hand-rolled container.
//!
//! `ml-dsa` has not been independently audited. The seal records that.

mod cbom;
mod grant;
mod keys;
mod report;
mod seal;

pub use cbom::cbom_json;
pub use grant::{Config, TrustFile, load_config, load_grant, load_trust};
pub use keys::{PublicKeyFile, generate_keypair, read_public_key, read_secret_key, write_keypair};
pub use report::{review_against, review_text};
pub use seal::{Seal, SealError, seal_program, verify_seal};

pub const FORMAT: &str = "mohar-seal/0";
pub const COMPILER: &str = "mohar 0.1.0";
