use std::string::FromUtf8Error;

use hex::FromHexError;
use thiserror::Error;
#[derive(Error, Debug)]
/// Custom error `enum` for getting passwords.
/// Encapsulates every error that may occur during reading and decrypting a password from the SQLite database.
pub enum BackendError {
    #[error("error decoding: {0}")]
    DecodeError(#[from] FromHexError),
    #[error("error converting decrypted data to a string: {0}")]
    ToStringError(#[from] FromUtf8Error),
    #[error("error occurred during decryption: {0}")]
    AesError(aes_gcm::Error),
    #[error("error getting password from db: {0}")]
    SQLiteError(#[from] rusqlite::Error),
    #[error("no nonce was found matching the field")]
    NoMatchingNonce,
}