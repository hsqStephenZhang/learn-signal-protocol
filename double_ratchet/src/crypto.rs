use aes::{
    cipher::{block_padding::Pkcs7, KeyIvInit},
    Aes256,
};
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{ChainKey, RootKey};

pub(crate) fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    hmac.finalize().into_bytes().into()
}

use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use std::result::Result;

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

impl std::fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn aes_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    Ok(cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| EncryptionError::BadKeyOrIv)?
        .encrypt_padded_vec_mut::<Pkcs7>(ptext))
}

pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::BadKeyOrIv)?
        .decrypt_padded_vec_mut::<Pkcs7>(ctext)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))
}

pub(crate) fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey) {
    const LABEL: &[u8] = b"WhisperRatchet";
    derive_keys_with_label(LABEL, secret_input)
}

// return two key, one for the sender, another for the receiver
// for slice, the RootKey is the root of senderKeyChain, the ChainKey is the receiverKeyChain
// for bob, vice versa
fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
}

pub fn generate_key_pair() -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey) {
    let private_key = x25519_dalek::StaticSecret::random();
    let public_key = x25519_dalek::PublicKey::from(&private_key);
    (private_key, public_key)
}
