use aes_gcm::aead::{
    consts::{B0, B1},
    generic_array::GenericArray,
};
use pbkdf2::pbkdf2_hmac;
use sha2::{
    digest::typenum::{UInt, UTerm},
    Digest, Sha256,
};

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
