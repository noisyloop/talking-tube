//! Sender keys (the scheme Signal groups and Matrix's Megolm use).
//!
//! Each member has a chain key + signing key per channel and sends them to
//! every other member over the pairwise Double Ratchet sessions. A message is
//! encrypted once, whatever the channel size.
//!
//! TODO:
//! * HMAC chain ratchet per sender (same KDF_CK as the Double Ratchet).
//! * Ed25519 signature on every group message.
//! * On `remove_member`: every remaining member makes a new sender key and
//!   sends it to the others. This is the step that is easy to get wrong.

use tt_core::DeviceKey;

use crate::{CryptoError, Envelope, GroupCipher, Scheme};

pub struct SenderKeyGroup {
    _private: (),
}

impl GroupCipher for SenderKeyGroup {
    fn scheme(&self) -> Scheme {
        Scheme::SenderKeys
    }

    fn encrypt(&mut self, _plaintext: &[u8]) -> Result<Envelope, CryptoError> {
        Err(CryptoError::Unimplemented("sender keys encrypt"))
    }

    fn decrypt(&mut self, _sender: &DeviceKey, _envelope: &Envelope) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Unimplemented("sender keys decrypt"))
    }

    fn add_member(&mut self, _member: &DeviceKey) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Unimplemented("sender keys add_member"))
    }

    fn remove_member(&mut self, _member: &DeviceKey) -> Result<(), CryptoError> {
        Err(CryptoError::Unimplemented("sender keys remove_member"))
    }
}
