//! Signal protocol for direct messages.
//!
//! TODO:
//! 1. Port X3DH (`x3dh_send` / `x3dh_receive`) and the Double Ratchet
//!    (`RatchetState`, `ratchet_encrypt` / `ratchet_decrypt`) from Shadow.
//! 2. Upgrade X3DH to PQXDH (adds an ML-KEM prekey) to match current Signal.
//! 3. Run Shadow's test vectors against the port.

use crate::{CryptoError, DmSession, Envelope};

/// Double Ratchet session with one peer device.
pub struct RatchetSession {
    _private: (),
}

impl DmSession for RatchetSession {
    fn encrypt(&mut self, _plaintext: &[u8], _ad: &[u8]) -> Result<Envelope, CryptoError> {
        Err(CryptoError::Unimplemented("double ratchet encrypt"))
    }

    fn decrypt(&mut self, _envelope: &Envelope, _ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::Unimplemented("double ratchet decrypt"))
    }
}
