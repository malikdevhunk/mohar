//! Classical signatures, present so the quantum lint has something real to
//! point at. ECDSA P-256 is the `p256` crate. RSA-PSS is named for the policy
//! and the CBOM, and refuses to run: linking a second multiprecision
//! implementation in v0.1 is not worth the audit surface.

use p256::EncodedPoint;
use p256::ecdsa::signature::{Signature as SignatureEncoding, Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::error::{CryptoError, CryptoResult};

fn signing_key(sk: &[u8]) -> CryptoResult<SigningKey> {
    if sk.len() != 32 {
        return Err(CryptoError::KeyLength);
    }
    SigningKey::from_bytes(sk).map_err(|_| CryptoError::Malformed)
}

pub fn ecdsa_p256_sign(sk: &[u8], msg: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = signing_key(sk)?;
    let sig: Signature = sk.sign(msg);
    Ok(sig.as_ref().to_vec())
}

pub fn ecdsa_p256_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(point) = EncodedPoint::from_bytes(pk) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_encoded_point(&point) else {
        return false;
    };
    let Ok(sig) = SignatureEncoding::from_bytes(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

#[allow(dead_code)]
pub fn ecdsa_p256_public(sk: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = signing_key(sk)?;
    let vk = VerifyingKey::from(&sk);
    Ok(vk.to_encoded_point(true).as_bytes().to_vec())
}

#[allow(dead_code)]
pub fn rsa_pss_sign(_sk: &[u8], _msg: &[u8]) -> CryptoResult<Vec<u8>> {
    Err(CryptoError::RsaNotLinked)
}

#[allow(dead_code)]
pub fn rsa_pss_verify(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> CryptoResult<bool> {
    Err(CryptoError::RsaNotLinked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_roundtrip() {
        let mut sk = [0u8; 32];
        sk[31] = 7;
        let pk = ecdsa_p256_public(&sk).unwrap();
        let sig = ecdsa_p256_sign(&sk, b"invoice").unwrap();
        assert!(ecdsa_p256_verify(&pk, b"invoice", &sig));
        assert!(!ecdsa_p256_verify(&pk, b"other", &sig));
    }
}
