use std::string::FromUtf8Error;

use hex::FromHexError;
use thiserror::Error;
#[derive(Error, Debug)]
/// Custom error `enum` for getting passwords.
/// Encapsulates every error that may occur during reading and decrypting a password from the SQLite database.
pub enum GetPasswordError {
    #[error("error decoding: {0}")]
    Decode(#[from] FromHexError),
    #[error("error converting decrypted data to a string: {0}")]
    ToString(#[from] FromUtf8Error),
    // this is so awesome:
    // at first i was having issues because i couldn't use `#[from] aes_gcm::Error,` (doesn't impl std error)
    // so instead i used it as an argument and then took the decrypt result and used `map_err()` with the aes_gcm error.
    #[error("error occurred during decryption: {0}")]
    AesGcm(aes_gcm::Error),
    #[error("error getting password from db: {0}")]
    SQLite(#[from] rusqlite::Error),
    #[error("no nonce was found matching the field")]
    NoMatchingNonce,
}
#[derive(Error, Debug)]
pub enum InsertEncryptedFieldError {
    #[error("error encrypting")]
    AesGcm(aes_gcm::Error),
    #[error("SQlite error: {0}")]
    SQLite(#[from] rusqlite::Error),
}
