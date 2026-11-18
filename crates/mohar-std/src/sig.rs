//! ML-DSA and SLH-DSA signatures.
//!
//! Private keys for ML-DSA are the 32-byte seed RustCrypto uses as the
//! preferred serialization (`ML-DSA.KeyGen_internal`). SLH-DSA private keys
//! are the crate's own fixed-width encoding.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, KeyExport, Keypair, MlDsa44, MlDsa65, MlDsa87,
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use slh_dsa::signature::{Keypair as SlhKeypair, Signer as SlhSigner, Verifier as SlhVerifier};
use slh_dsa::{Sha2_128s, SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey};

use crate::error::{CryptoError, CryptoResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaLevel {
    D44,
    D65,
    D87,
}

pub fn mldsa_generate(level: MlDsaLevel) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    match level {
        MlDsaLevel::D44 => keygen_at::<MlDsa44>(),
        MlDsaLevel::D65 => keygen_at::<MlDsa65>(),
        MlDsaLevel::D87 => keygen_at::<MlDsa87>(),
    }
}

pub fn mldsa_sign(level: MlDsaLevel, sk_seed: &[u8], msg: &[u8]) -> CryptoResult<Vec<u8>> {
    match level {
        MlDsaLevel::D44 => sign::<MlDsa44>(sk_seed, msg),
        MlDsaLevel::D65 => sign::<MlDsa65>(sk_seed, msg),
        MlDsaLevel::D87 => sign::<MlDsa87>(sk_seed, msg),
    }
}

pub fn mldsa_verify(level: MlDsaLevel, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match level {
        MlDsaLevel::D44 => verify::<MlDsa44>(pk, msg, sig),
        MlDsaLevel::D65 => verify::<MlDsa65>(pk, msg, sig),
        MlDsaLevel::D87 => verify::<MlDsa87>(pk, msg, sig),
    }
}

fn keygen_at<P>() -> CryptoResult<(Vec<u8>, Vec<u8>)>
where
    P: ml_dsa::MlDsaParams,
    SigningKey<P>: Generate + Keypair<VerifyingKey = VerifyingKey<P>> + ml_dsa::KeyExport,
{
    let sk = SigningKey::<P>::generate();
    let pk = sk.verifying_key().encode();
    Ok((sk.to_bytes().to_vec(), pk.as_slice().to_vec()))
}

fn sign<P>(sk_seed: &[u8], msg: &[u8]) -> CryptoResult<Vec<u8>>
where
    P: ml_dsa::MlDsaParams,
    SigningKey<P>: Signer<Signature<P>>,
{
    if sk_seed.len() != 32 {
        return Err(CryptoError::KeyLength);
    }
    let mut seed = ml_dsa::Seed::default();
    seed.copy_from_slice(sk_seed);
    let sk = SigningKey::<P>::from_seed(&seed);
    let sig = sk.sign(msg);
    Ok(sig.encode().as_slice().to_vec())
}

fn verify<P>(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool
where
    P: ml_dsa::MlDsaParams,
    VerifyingKey<P>: Verifier<Signature<P>>,
{
    let mut pk_buf = EncodedVerifyingKey::<P>::default();
    if pk.len() != pk_buf.len() {
        return false;
    }
    pk_buf.copy_from_slice(pk);
    let vk = VerifyingKey::<P>::decode(&pk_buf);
    let mut sig_buf = EncodedSignature::<P>::default();
    if sig.len() != sig_buf.len() {
        return false;
    }
    sig_buf.copy_from_slice(sig);
    let Some(parsed) = Signature::<P>::decode(&sig_buf) else {
        return false;
    };
    vk.verify(msg, &parsed).is_ok()
}

pub fn slh_generate() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let mut rng = rand_core::OsRng;
    let sk = SlhSigningKey::<Sha2_128s>::new(&mut rng);
    let vk = SlhKeypair::verifying_key(&sk);
    Ok((sk.to_vec(), vk.to_vec()))
}

pub fn slh_sign(sk: &[u8], msg: &[u8]) -> CryptoResult<Vec<u8>> {
    let sk = SlhSigningKey::<Sha2_128s>::try_from(sk).map_err(|_| CryptoError::KeyLength)?;
    let sig = SlhSigner::try_sign(&sk, msg).map_err(|_| CryptoError::Malformed)?;
    Ok(sig.to_vec())
}

pub fn slh_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = SlhVerifyingKey::<Sha2_128s>::try_from(pk) else {
        return false;
    };
    let Ok(sig) = slh_dsa::Signature::<Sha2_128s>::try_from(sig) else {
        return false;
    };
    SlhVerifier::verify(&vk, msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa65_roundtrip() {
        let (sk, pk) = mldsa_generate(MlDsaLevel::D65).unwrap();
        let msg = b"mohar seal";
        let sig = mldsa_sign(MlDsaLevel::D65, &sk, msg).unwrap();
        assert!(mldsa_verify(MlDsaLevel::D65, &pk, msg, &sig));
        assert!(!mldsa_verify(MlDsaLevel::D65, &pk, b"other", &sig));
    }

    #[test]
    fn slh_roundtrip() {
        let (sk, pk) = slh_generate().unwrap();
        let msg = b"hedge";
        let sig = slh_sign(&sk, msg).unwrap();
        assert!(slh_verify(&pk, msg, &sig));
        assert!(!slh_verify(&pk, b"nope", &sig));
    }
}
