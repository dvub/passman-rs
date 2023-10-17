use aes_gcm::{
    aead::{
        consts::{B0, B1},
        generic_array::GenericArray,
        Aead, OsRng,
    },
    aes::Aes256,
    Aes256Gcm, AesGcm, Key, KeyInit,
};

use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::{
    Digest, Sha256,
};
use typenum::consts::{U12, U32};

use crate::error::GetPasswordError;



/// Hashes `text` using `Sha256`.
///
/// # Arguments
///
/// - `text` - a reference to a `[u8]` to hash.
pub fn hash(
    text: &[u8],
) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::new();
    hasher.update(text);
    hasher.finalize()
}
/// Derives an encryption key from a password with the ppbkdf2 algorithm.
///
/// # Arguments
///
/// - `master_password` - the master password.
/// - `kdf_salt` - a password to use to generate a key.
pub fn derive_key(master_password: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> [u8; 32] {
    let n = 4096;
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.as_ref(),
        password.as_ref(),
        n,
        &mut derived_key,
    );
    derived_key
}
/// Decrypts a `Password` field. May fail with a `GetPasswordError`.
///
/// # Arguments
/// - `data` - the password field to decrypt.
/// - `nonce` - a raw nonce to use for decryption.
/// - `cipher` - an AES 256 GCM cipher to use for decryption.
///
pub fn decrypt_password_field(
    data: impl AsRef<[u8]>,
    nonce: impl AsRef<[u8]>,
    cipher: &AesGcm<Aes256, U12>,
) -> Result<String, GetPasswordError> {
    let decoded = hex::decode(data)?;
    let decrypted = cipher
        .decrypt(GenericArray::from_slice(nonce.as_ref()), decoded.as_ref())
        .map_err(GetPasswordError::AesGcm)?;
    Ok(String::from_utf8(decrypted)?)
}
/// Encrypts a `Password` field. May fail with a `aes_gcm::Error`.
///
/// # Arguments
/// - `data` - the password field to encrypt.
/// - `nonce` - a raw nonce to use for encryption.
/// - `cipher` - an AES 256 GCM cipher to use for decryption.
///
pub fn encrypt_password_field(
    data: impl AsRef<[u8]>,
    nonce: &aes_gcm::Nonce<U12>,
    cipher: &AesGcm<Aes256, U12>,
) -> Result<String, aes_gcm::Error> {
    let encrypted = cipher.encrypt(nonce, data.as_ref())?;
    Ok(hex::encode(encrypted))
}

pub fn gen_cipher(master: impl AsRef<[u8]>, password_name: impl AsRef<[u8]>) -> AesGcm<Aes256, U12> {
    let derived = derive_key(master, password_name);
    let key = Key::<Aes256Gcm>::from_slice(&derived);
    Aes256Gcm::new(key)
}

/// generates a password given a length using randomness from the OS
pub fn generate_password(length: usize) -> String {
    let characters: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()~`-=_+[]{}\\|;':\",.<>/?".chars().collect();
    // wouldn't it be lovely if all of my code was this well-written?
    // this code only looks like this because i didn't write it.
    (0..length)
        .map(|_| characters[OsRng.gen_range(0..characters.len())])
        .collect()
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::Aead, aead::OsRng, AeadCore, Aes256Gcm, Key, KeyInit};
    #[test]
    fn sha512() {
        // the string literal came from an online hasher to compare results to
        let res = &super::hash(b"test")[..];
        let expected =
            hex_literal::hex!("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        assert_eq!(res, expected);
    }
    #[test]
    fn derive_key() {
        let res = super::derive_key("mymasterpassword", "salt");
        let expected =
            hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
                .unwrap();
        assert_eq!(res.to_vec(), expected);
    }

    #[test]
    fn decrypt() {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let key = hex::decode("8f21affeb61e304e7b474229ffeb34309ed31beda58d153bc7ad9da6e9b6184c")
            .unwrap();
        // manually creating this key/cipher
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);

        let ciphertext = hex::encode(cipher.encrypt(&nonce, b"data".as_ref()).unwrap());

        // here's the function we're testing
        let result = super::decrypt_password_field(&ciphertext, &nonce, &cipher).unwrap();

        assert_eq!(result, "data");
    }
    #[test]
    fn encrypt() {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        // function to test

        // sourced from: https://neurotechnics.com/tools/pbkdf2-test
        // hex::decode() will decode into an array and then create an encryption key for us to compare to
        let key = super::derive_key("master", "salt");
        // manually creating this key/cipher
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(key);
        let res = super::encrypt_password_field("data", &nonce, &cipher);

        // encrypt and compare!
        let ciphertext = cipher.encrypt(&nonce, b"data".as_ref()).unwrap();

        assert_eq!(res.unwrap(), hex::encode(ciphertext));
    }
    
}
