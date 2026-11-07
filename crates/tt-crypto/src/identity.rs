//! Device identity and prekeys.
//!
//! Each device has two long-term keys:
//! * an **Ed25519** key for signing. Its public half is the [`DeviceKey`],
//!   which is the user's whole identity.
//! * an **X25519** key for X3DH.
//!
//! The [`IdentityCert`] signs the X25519 key with the Ed25519 key, so nobody
//! can pair someone's identity with a DH key they control. (Shadow didn't bind
//! these two keys; Signal avoids the problem with XEdDSA, one key for both jobs.)

use std::fmt;

use serde::{Deserialize, Serialize};
use tt_core::encoding::{b64, hex32};
use tt_core::DeviceKey;

use crate::keys::{self, Key32};
use crate::CryptoError;

const CERT_LABEL: &[u8] = b"tt-identity-cert-v1";
const SPK_LABEL: &[u8] = b"tt-signed-prekey-v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    sign_priv: Key32,
    dh_priv: Key32,
    pub cert: IdentityCert,
}

/// The X25519 identity key, signed by the device's Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCert {
    pub device: DeviceKey,
    #[serde(with = "hex32")]
    pub dh_pub: Key32,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl IdentityCert {
    pub fn verify(&self) -> Result<(), CryptoError> {
        keys::verify(&self.device.0, &[CERT_LABEL, &self.dh_pub].concat(), &self.signature)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity").field("device", &self.cert.device).finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let sign_priv = keys::generate_signing();
        let (dh_priv, dh_pub) = keys::generate_dh();
        let device = DeviceKey(keys::ed25519_public(&sign_priv));
        let signature = keys::sign(&sign_priv, &[CERT_LABEL, &dh_pub].concat());
        Self { sign_priv, dh_priv, cert: IdentityCert { device, dh_pub, signature } }
    }

    pub fn device_key(&self) -> DeviceKey {
        self.cert.device
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        keys::sign(&self.sign_priv, msg)
    }

    pub(crate) fn dh_priv(&self) -> &Key32 {
        &self.dh_priv
    }

    pub fn generate_spk(&self, id: u32) -> SignedPreKey {
        let (private, key) = keys::generate_dh();
        let signature = self.sign(&[SPK_LABEL, &key].concat());
        SignedPreKey { private, public: SignedPreKeyPublic { id, key, signature } }
    }

    pub fn generate_opks(&self, start_id: u32, count: u32) -> Vec<OneTimePreKey> {
        (start_id..start_id + count)
            .map(|id| {
                let (private, key) = keys::generate_dh();
                OneTimePreKey { private, public: OneTimePreKeyPublic { id, key } }
            })
            .collect()
    }
}

/// Medium-term prekey, signed so the relay can't swap it.
#[derive(Clone, Serialize, Deserialize)]
pub struct SignedPreKey {
    pub(crate) private: Key32,
    pub public: SignedPreKeyPublic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub id: u32,
    #[serde(with = "hex32")]
    pub key: Key32,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl SignedPreKeyPublic {
    pub fn verify(&self, signer: &DeviceKey) -> Result<(), CryptoError> {
        keys::verify(&signer.0, &[SPK_LABEL, &self.key].concat(), &self.signature)
    }
}

/// Single-use prekey. The relay hands each one out once; we delete the
/// private half after it's used, which gives forward secrecy for the first message.
#[derive(Clone, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub(crate) private: Key32,
    pub public: OneTimePreKeyPublic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePreKeyPublic {
    pub id: u32,
    #[serde(with = "hex32")]
    pub key: Key32,
}

/// What the relay gives someone who wants to start a session with us.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub cert: IdentityCert,
    pub spk: SignedPreKeyPublic,
    pub opk: Option<OneTimePreKeyPublic>,
}

impl PreKeyBundle {
    pub fn verify(&self) -> Result<(), CryptoError> {
        self.cert.verify()?;
        self.spk.verify(&self.cert.device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_and_spk_verify() {
        let id = DeviceIdentity::generate();
        id.cert.verify().unwrap();
        let spk = id.generate_spk(1);
        let bundle = PreKeyBundle { cert: id.cert.clone(), spk: spk.public, opk: None };
        bundle.verify().unwrap();
    }

    #[test]
    fn swapped_dh_key_is_rejected() {
        let id = DeviceIdentity::generate();
        let mut cert = id.cert.clone();
        cert.dh_pub = keys::generate_dh().1;
        assert_eq!(cert.verify(), Err(CryptoError::BadSignature));
    }
}
