//! Errors from the crypto glue. These are failures of a primitive
//! (bad key length, tag mismatch), not Mohar type errors.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("operating system random number generator failed")]
    Rng,
    #[error("key material has the wrong length")]
    KeyLength,
    #[error("ciphertext or signature is the wrong length or is malformed")]
    Malformed,
    #[error("authentication failed")]
    Authentication,
    #[error("legacy RSA-PSS is visible to the crypto policy but is not executed in v0.1")]
    RsaNotLinked,
}

pub type CryptoResult<T> = Result<T, CryptoError>;
