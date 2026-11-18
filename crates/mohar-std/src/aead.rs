//! ChaCha20-Poly1305. The construction is the RustCrypto crate's, not ours.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{CryptoError, CryptoResult};

pub fn aead_seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CryptoError::KeyLength);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

pub fn aead_open(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CryptoError::KeyLength);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let ct = aead_seal(&key, &nonce, b"release-token").unwrap();
        let pt = aead_open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"release-token");
        assert!(aead_open(&key, &nonce, &ct[..ct.len() - 1]).is_err());
    }
}
