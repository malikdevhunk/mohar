//! ML-DSA-65 key files.
//!
//! A secret file holds the 32-byte seed. A public file holds the encoded
//! verifying key and a key id (SHA3-256 of that key, hex). This is not a
//! PKCS#8 wrapper: RustCrypto's preferred ML-DSA private key is the seed,
//! and v0.1 stores it with a small header so a human can see the algorithm.

use std::fs;
use std::path::Path;

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey, Verifier};
use sha3::{Digest, Sha3_256};

use crate::seal::SealError;

#[derive(Clone, Debug)]
pub struct PublicKeyFile {
    pub key_id: String,
    pub public_key: Vec<u8>,
}

pub fn generate_keypair() -> Result<(Vec<u8>, PublicKeyFile), SealError> {
    let sk = SigningKey::<MlDsa65>::generate();
    let seed = sk.to_bytes().to_vec();
    let pk = sk.verifying_key().encode();
    let public_key = pk.as_slice().to_vec();
    Ok((
        seed,
        PublicKeyFile {
            key_id: key_id(&public_key),
            public_key,
        },
    ))
}

pub fn key_id(public_key: &[u8]) -> String {
    hex::encode(Sha3_256::digest(public_key))
}

pub fn write_keypair(
    dir_prefix: &Path,
    seed: &[u8],
    public: &PublicKeyFile,
) -> Result<(), SealError> {
    let secret = format!(
        "MOHAR KEY v1\nalgorithm = ML-DSA-65\nsecret_seed = {}\n",
        hex::encode(seed)
    );
    let pub_text = format!(
        "MOHAR PUB v1\nalgorithm = ML-DSA-65\nkey_id = {}\npublic_key = {}\n",
        public.key_id,
        hex::encode(&public.public_key)
    );
    fs::write(dir_prefix, secret).map_err(|e| SealError::Io(e.to_string()))?;
    let mut pub_path = dir_prefix.as_os_str().to_owned();
    pub_path.push(".pub");
    fs::write(pub_path, pub_text).map_err(|e| SealError::Io(e.to_string()))?;
    Ok(())
}

pub fn read_secret_key(path: &Path) -> Result<Vec<u8>, SealError> {
    let text = fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?;
    parse_field(&text, "secret_seed")
}

pub fn read_public_key(path: &Path) -> Result<PublicKeyFile, SealError> {
    let text = fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?;
    let public_key = parse_field(&text, "public_key")?;
    let key_id = text
        .lines()
        .find_map(|l| l.strip_prefix("key_id = "))
        .unwrap_or("")
        .trim()
        .to_string();
    let key_id = if key_id.is_empty() {
        key_id_of(&public_key)
    } else {
        key_id
    };
    Ok(PublicKeyFile { key_id, public_key })
}

fn key_id_of(bytes: &[u8]) -> String {
    key_id(bytes)
}

fn parse_field(text: &str, field: &str) -> Result<Vec<u8>, SealError> {
    let prefix = format!("{field} = ");
    let hex_str = text
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .ok_or_else(|| SealError::Key(format!("missing {field}")))?;
    hex::decode(hex_str.trim()).map_err(|e| SealError::Key(e.to_string()))
}

pub fn sign_bytes(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, SealError> {
    if seed.len() != 32 {
        return Err(SealError::Key("ML-DSA-65 seed must be 32 bytes".into()));
    }
    let mut raw = ml_dsa::Seed::default();
    raw.copy_from_slice(seed);
    let sk = SigningKey::<MlDsa65>::from_seed(&raw);
    let sig = sk.sign(message);
    Ok(sig.encode().as_slice().to_vec())
}

pub fn verify_bytes(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};
    let mut pk = EncodedVerifyingKey::<MlDsa65>::default();
    if public_key.len() != pk.len() {
        return false;
    }
    pk.copy_from_slice(public_key);
    let vk = VerifyingKey::<MlDsa65>::decode(&pk);
    let mut sig_buf = EncodedSignature::<MlDsa65>::default();
    if signature.len() != sig_buf.len() {
        return false;
    }
    sig_buf.copy_from_slice(signature);
    let Some(sig) = Signature::<MlDsa65>::decode(&sig_buf) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}
