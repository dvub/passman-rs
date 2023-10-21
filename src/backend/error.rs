use std::string::FromUtf8Error;

use hex::FromHexError;
use thiserror::Error;
#[derive(Error, Debug)]
/// Custom error `enum` for backend operations.
/// Contains errors that may occur at *any phase of a backend operation*, e.g. reading a password.
pub enum BackendError {
    #[error("error decoding: {0}")]
    DecodeError(#[from] FromHexError),

    #[error("error converting decrypted data to a string: {0}")]
    ToStringError(#[from] FromUtf8Error),

    #[error("error occurred during encryption/decryption")]
    AesError,

    #[error("error getting password from db: {0}")]
    SQLiteError(#[from] rusqlite::Error),

    #[error("no nonce was found matching the field")]
    NoMatchingNonce,

    #[error("Attempted to authenticate invalid master record field")]
    InvalidMasterRecordField,
}
