use aes_gcm::{
    aead::{
        consts::{B0, B1},
        generic_array::GenericArray,
        Aead, OsRng,
    },
    aes::Aes256,
    AeadCore, Aes256Gcm, AesGcm, Key, KeyInit,
};
use pbkdf2::pbkdf2_hmac;
use sha2::{
    digest::typenum::{UInt, UTerm},
    Digest, Sha256,
};

use crate::db_ops::GetPasswordError;

pub type Nonce = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;

/// Hashes `text` using `Sha256`.
pub fn hash(
    text: &[u8],
) -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let mut hasher = Sha256::new();
    hasher.update(text);
    hasher.finalize()
}
// pbkdf2 function pulled from pwd-rs
pub fn derive_key(master_password: impl AsRef<[u8]>, kdf_salt: impl AsRef<[u8]>) -> [u8; 32] {
    let n = 4096;
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.as_ref(),
        kdf_salt.as_ref(),
        n,
        &mut derived_key,
    );
    derived_key
}

pub fn decrypt_password_field(
    data: &str,
    decoded_nonce: &[u8],
    cipher: &AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
) -> Result<String, GetPasswordError> {
    let decoded = hex::decode(data)?;
    let decrypted = cipher
        .decrypt(GenericArray::from_slice(decoded_nonce), decoded.as_ref())
        .map_err(GetPasswordError::AesGcm)?;
    Ok(String::from_utf8(decrypted)?)
}

pub fn encrypt_password_field(
    password_name: &str,
    column_name: &str,
    data: &str,
    master: &str,
    nonce: &Nonce,
) -> Result<String, aes_gcm::Error> {
    let derived_key = derive_key(master, password_name);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key);
    let cipher = Aes256Gcm::new(key);

    let encrypted = cipher.encrypt(nonce, data.as_bytes())?;
    Ok(hex::encode(encrypted))
}
