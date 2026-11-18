//! ML-KEM and the Mohar hybrid (X25519 + ML-KEM-768, combined with HKDF-SHA3).
//!
//! The hybrid is not the IETF X-Wing construction. Both shares are required,
//! then HKDF-SHA3-256 extracts 32 bytes with info `mohar-hybrid-v1`. The seal
//! records the algorithm name `X25519-MLKEM768`.

use ml_kem::kem::{Ciphertext, Encapsulate, Kem, Key, KeyExport, TryDecapsulate};
use ml_kem::{
    DecapsulationKey768, DecapsulationKey1024, EncapsulationKey768, EncapsulationKey1024, MlKem768,
    MlKem1024, Seed,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{CryptoError, CryptoResult};
use crate::hash::hkdf_sha3;

const HYBRID_INFO: &[u8] = b"mohar-hybrid-v1";

fn to_vec(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    bytes.as_ref().to_vec()
}

fn shared32(shared: impl AsRef<[u8]>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_ref());
    out
}

fn load_seed(bytes: &[u8]) -> CryptoResult<Seed> {
    if bytes.len() != 64 {
        return Err(CryptoError::KeyLength);
    }
    let mut seed = Seed::default();
    seed.copy_from_slice(bytes);
    Ok(seed)
}

macro_rules! kem_ops {
    ($gen:ident, $enc:ident, $dec:ident, $param:ty, $dk:ty, $ek:ty) => {
        pub fn $gen() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
            let (dk, ek) = <$param as Kem>::generate_keypair();
            let seed = dk.to_seed().ok_or(CryptoError::Malformed)?;
            Ok((to_vec(&seed), to_vec(ek.to_bytes())))
        }

        pub fn $enc(pk: &[u8]) -> CryptoResult<(Vec<u8>, [u8; 32])> {
            let mut key = Key::<$ek>::default();
            if pk.len() != key.len() {
                return Err(CryptoError::KeyLength);
            }
            key.copy_from_slice(pk);
            let ek = <$ek>::new(&key).map_err(|_| CryptoError::Malformed)?;
            let (ct, shared) = ek.encapsulate();
            Ok((to_vec(&ct), shared32(&shared)))
        }

        pub fn $dec(sk: &[u8], ct: &[u8]) -> CryptoResult<[u8; 32]> {
            let dk = <$dk>::from_seed(load_seed(sk)?);
            let mut buf = Ciphertext::<$param>::default();
            if ct.len() != buf.len() {
                return Err(CryptoError::Malformed);
            }
            buf.copy_from_slice(ct);
            let shared = dk
                .try_decapsulate(&buf)
                .map_err(|_| CryptoError::Malformed)?;
            Ok(shared32(&shared))
        }
    };
}

kem_ops!(
    mlkem768_generate,
    mlkem768_encaps,
    mlkem768_decaps,
    MlKem768,
    DecapsulationKey768,
    EncapsulationKey768
);
kem_ops!(
    mlkem1024_generate,
    mlkem1024_encaps,
    mlkem1024_decaps,
    MlKem1024,
    DecapsulationKey1024,
    EncapsulationKey1024
);

pub fn hybrid_generate() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let x_sk = StaticSecret::random_from_rng(OsRng);
    let x_pk = PublicKey::from(&x_sk);
    let (kem_sk, kem_pk) = mlkem768_generate()?;
    let mut sk = Vec::with_capacity(32 + kem_sk.len());
    sk.extend_from_slice(x_sk.as_bytes());
    sk.extend_from_slice(&kem_sk);
    let mut pk = Vec::with_capacity(32 + kem_pk.len());
    pk.extend_from_slice(x_pk.as_bytes());
    pk.extend_from_slice(&kem_pk);
    Ok((sk, pk))
}

pub fn hybrid_encaps(pk: &[u8]) -> CryptoResult<(Vec<u8>, [u8; 32])> {
    if pk.len() <= 32 {
        return Err(CryptoError::KeyLength);
    }
    let (x_pk_bytes, kem_pk) = pk.split_at(32);
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(x_pk_bytes);
    let x_pk = PublicKey::from(x_bytes);
    let eph = StaticSecret::random_from_rng(OsRng);
    let eph_pk = PublicKey::from(&eph);
    let x_ss = eph.diffie_hellman(&x_pk);
    let (kem_ct, kem_ss) = mlkem768_encaps(kem_pk)?;
    let mut ct = Vec::with_capacity(32 + kem_ct.len());
    ct.extend_from_slice(eph_pk.as_bytes());
    ct.extend_from_slice(&kem_ct);
    Ok((ct, combine(x_ss.as_bytes(), &kem_ss)?))
}

pub fn hybrid_decaps(sk: &[u8], ct: &[u8]) -> CryptoResult<[u8; 32]> {
    if sk.len() <= 32 || ct.len() <= 32 {
        return Err(CryptoError::KeyLength);
    }
    let (x_sk_bytes, kem_sk) = sk.split_at(32);
    let (eph_bytes, kem_ct) = ct.split_at(32);
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(x_sk_bytes);
    let mut eph = [0u8; 32];
    eph.copy_from_slice(eph_bytes);
    let x_sk = StaticSecret::from(x_bytes);
    let eph_pk = PublicKey::from(eph);
    let x_ss = x_sk.diffie_hellman(&eph_pk);
    let kem_ss = mlkem768_decaps(kem_sk, kem_ct)?;
    combine(x_ss.as_bytes(), &kem_ss)
}

fn combine(x_ss: &[u8], kem_ss: &[u8]) -> CryptoResult<[u8; 32]> {
    let mut ikm = Vec::with_capacity(x_ss.len() + kem_ss.len());
    ikm.extend_from_slice(x_ss);
    ikm.extend_from_slice(kem_ss);
    let mut out = [0u8; 32];
    hkdf_sha3(&ikm, b"mohar", HYBRID_INFO, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem768_roundtrip() {
        let (sk, pk) = mlkem768_generate().unwrap();
        let (ct, send) = mlkem768_encaps(&pk).unwrap();
        let recv = mlkem768_decaps(&sk, &ct).unwrap();
        assert_eq!(send, recv);
    }

    #[test]
    fn mlkem1024_roundtrip() {
        let (sk, pk) = mlkem1024_generate().unwrap();
        let (ct, send) = mlkem1024_encaps(&pk).unwrap();
        let recv = mlkem1024_decaps(&sk, &ct).unwrap();
        assert_eq!(send, recv);
    }

    #[test]
    fn hybrid_roundtrip() {
        let (sk, pk) = hybrid_generate().unwrap();
        let (ct, send) = hybrid_encaps(&pk).unwrap();
        let recv = hybrid_decaps(&sk, &ct).unwrap();
        assert_eq!(send, recv);
    }
}
