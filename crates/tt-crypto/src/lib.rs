//! Encryption for Talking Tube.
//!
//! * **DMs** use the Signal protocol: X3DH handshake + Double Ratchet,
//!   implemented from Signal's public specifications (see `docs/ENCRYPTION.md`).
//!   The code is to be ported from Shadow's `cli/src/crypto`.
//! * **Channels** use a [`GroupCipher`]. Sender keys first, MLS later.
//!
//! Everything above this crate only talks to the traits below, so the
//! algorithms can be swapped without touching the relay or the client.

pub mod dm;
pub mod error;
pub mod group;
pub mod identity;

pub use error::CryptoError;

/// An opaque ciphertext plus whatever header the scheme needs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub scheme: Scheme,
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scheme {
    DoubleRatchet,
    SenderKeys,
    Mls,
}

/// One-to-one session (Double Ratchet).
pub trait DmSession {
    fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<Envelope, CryptoError>;
    fn decrypt(&mut self, envelope: &Envelope, ad: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Encryption state for one channel.
pub trait GroupCipher {
    fn scheme(&self) -> Scheme;
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Envelope, CryptoError>;
    fn decrypt(&mut self, sender: &tt_core::DeviceKey, envelope: &Envelope)
        -> Result<Vec<u8>, CryptoError>;
    /// A member joined. Returns key material to deliver over their DM sessions.
    fn add_member(&mut self, member: &tt_core::DeviceKey) -> Result<Vec<u8>, CryptoError>;
    /// A member left or was removed. Must rotate keys so they can't read new messages.
    fn remove_member(&mut self, member: &tt_core::DeviceKey) -> Result<(), CryptoError>;
}
