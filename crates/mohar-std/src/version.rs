//! Versions of the crates the default backend links.
//!
//! Kept next to `Cargo.toml` on purpose: the seal prints them, and a test
//! checks the strings still match the locked packages.

pub const BACKEND_NAME: &str = "rustcrypto";

pub const CRATES: &[(&str, &str)] = &[
    ("ml-kem", "0.3.4"),
    ("ml-dsa", "0.1.2"),
    ("slh-dsa", "0.1.0"),
    ("chacha20poly1305", "0.10.1"),
    ("sha3", "0.10.8"),
    ("sha2", "0.10.9"),
    ("hkdf", "0.12.4"),
    ("x25519-dalek", "2.0.1"),
    ("p256", "0.11.1"),
    ("subtle", "2.6.1"),
];

pub const AUDIT_NOTICE: &str = "\
The default RustCrypto backend is linked. The ml-kem, ml-dsa and slh-dsa crates \
state that they have not been independently audited. Mohar does not add an audit. \
Use another backend if you need that assurance. Post-quantum here means the \
algorithms are the NIST standards designed against known quantum attacks; it is \
not a proof that a quantum computer cannot break them.";

/// A short identifier mixed into the standard-library hash inside a seal.
pub const STD_FINGERPRINT: &str = "mohar-std 0.1.0 rustcrypto ml-kem=0.3.4 ml-dsa=0.1.2 slh-dsa=0.1.0 chacha20poly1305=0.10.1 sha3=0.10.8 x25519-dalek=2.0.1 p256=0.11.1";
