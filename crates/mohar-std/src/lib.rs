//! Builtins that back Mohar's standard library.
//!
//! Cryptography is thin glue over RustCrypto. Nothing in this crate
//! implements a primitive of its own: key generation, encapsulation,
//! signatures, AEAD and hashing all call the corresponding crate.
//!
//! The `ml-kem`, `ml-dsa` and `slh-dsa` crates state in their own
//! documentation that they have never been independently audited. Mohar
//! repeats that warning. Symmetric algorithms (ChaCha20-Poly1305, SHA-2,
//! SHA-3, HKDF) and X25519 come from the same family of crates. If you need
//! a FIPS-tracked implementation, this is the trait to wrap it with; v0.1
//! links the RustCrypto backend only.

mod aead;
mod error;
mod hash;
mod kem;
mod legacy;
mod sig;
pub mod version;

pub use aead::{aead_open, aead_seal};
pub use error::CryptoError;
pub use hash::{hkdf_sha3, sha3_256, sha256};
pub use kem::{
    hybrid_decaps, hybrid_encaps, hybrid_generate, mlkem768_decaps, mlkem768_encaps,
    mlkem768_generate, mlkem1024_decaps, mlkem1024_encaps, mlkem1024_generate,
};
pub use legacy::{
    ecdsa_p256_public, ecdsa_p256_sign, ecdsa_p256_verify, rsa_pss_sign, rsa_pss_verify,
};
pub use sig::{
    MlDsaLevel, mldsa_generate, mldsa_sign, mldsa_verify, slh_generate, slh_sign, slh_verify,
};

/// Constant-time equality of two byte strings.
///
/// Lengths are compared first and a length mismatch returns false. Callers
/// that need a fixed-width check (tags, digests) pass equal lengths. The
/// comparison itself uses `subtle`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

/// Constant-time select between two `u64`s.
pub fn ct_select_u64(cond: bool, a: u64, b: u64) -> u64 {
    use subtle::{Choice, ConditionallySelectable};
    u64::conditional_select(&b, &a, Choice::from(u8::from(cond)))
}

/// Constant-time select between two `i64`s.
pub fn ct_select_i64(cond: bool, a: i64, b: i64) -> i64 {
    use subtle::{Choice, ConditionallySelectable};
    i64::conditional_select(&b, &a, Choice::from(u8::from(cond)))
}

/// Constant-time select between two byte strings of equal length.
///
/// `a` is chosen when `cond` is true.
pub fn ct_select_bytes(cond: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    use subtle::{Choice, ConditionallySelectable};
    let c = Choice::from(u8::from(cond));
    let n = a.len().min(b.len());
    let mut out = vec![0u8; n];
    for i in 0..n {
        out[i] = u8::conditional_select(&b[i], &a[i], c);
    }
    out
}

/// Best-effort wipe. The interpreter calls this when `ct::zeroize` runs.
pub fn wipe(buf: &mut [u8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    use rand_core::RngCore;
    rand_core::OsRng
        .try_fill_bytes(buf)
        .map_err(|_| CryptoError::Rng)
}

/// Referenced so Cargo keeps the direct pin on `signature` 2.3.0-pre.4,
/// the pre-release `slh-dsa` 0.1.0 compiles against. Later pre-releases
/// changed the trait and do not build that crate.
#[allow(dead_code)]
fn pin_slh_signature_crate() -> usize {
    signature::Error::new().to_string().len()
}
