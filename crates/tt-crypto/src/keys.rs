//! Thin wrappers over the primitive crates, so the protocol code reads like the spec.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CryptoError;

pub type Key32 = [u8; 32];

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// A fresh X25519 key pair as (private, public).
pub fn generate_dh() -> (Key32, Key32) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

pub fn dh_public(private: &Key32) -> Key32 {
    *PublicKey::from(&StaticSecret::from(*private)).as_bytes()
}

/// X25519. Rejects all-zero output, which happens if the peer sent a
/// low-order point (a known way to force a predictable shared secret).
pub fn dh(private: &Key32, public: &Key32) -> Result<Key32, CryptoError> {
    let shared = StaticSecret::from(*private).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(CryptoError::WeakKey);
    }
    Ok(shared.to_bytes())
}

pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("output length is small and fixed");
}

pub fn hmac(key: &Key32, data: &[u8]) -> Key32 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length works");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// KDF_CK from the Double Ratchet spec: one step of a symmetric chain.
/// Returns (next chain key, message key). Used by sender keys too.
pub fn kdf_ck(chain_key: &Key32) -> (Key32, Key32) {
    (hmac(chain_key, &[0x02]), hmac(chain_key, &[0x01]))
}

/// AES-256-GCM with a random 96-bit nonce, output is `nonce || ciphertext || tag`.
/// Every key here is used for exactly one message, so random nonces are fine.
pub fn aead_encrypt(key: &Key32, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = random_bytes();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: ad })
        .expect("encryption with a valid key can't fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn aead_decrypt(key: &Key32, data: &[u8], ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 + 16 {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, ct) = data.split_at(12);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: ad })
        .map_err(|_| CryptoError::Decrypt)
}

pub fn ed25519_public(private: &Key32) -> Key32 {
    SigningKey::from_bytes(private).verifying_key().to_bytes()
}

pub fn generate_signing() -> Key32 {
    SigningKey::generate(&mut OsRng).to_bytes()
}

pub fn sign(private: &Key32, msg: &[u8]) -> Vec<u8> {
    SigningKey::from_bytes(private).sign(msg).to_bytes().to_vec()
}

/// Strict Ed25519 verification (rejects malleable signatures and weak keys).
pub fn verify(public: &Key32, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    let key = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::BadKey)?;
    key.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| CryptoError::BadSignature)
}
