//! SHA-3, SHA-256 and HKDF-SHA3.

use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use crate::error::CryptoResult;

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let dig = Sha3_256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let dig = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

pub fn hkdf_sha3(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> CryptoResult<()> {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = hkdf::Hkdf::<Sha3_256>::new(salt, ikm);
    hk.expand(info, out)
        .map_err(|_| crate::error::CryptoError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_abc() {
        // FIPS 202, SHA3-256("") and SHA3-256("abc").
        let empty = sha3_256(b"");
        assert_eq!(
            hex::encode(empty),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        let abc = sha3_256(b"abc");
        assert_eq!(
            hex::encode(abc),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }
}
