//! Encryption for Talking Tube.
//!
//! * **DMs** use the Signal protocol, implemented from Signal's public specs
//!   and ported from Shadow:
//!   [`x3dh`] sets up a shared secret with someone who may be offline, and the
//!   [`ratchet`] (Double Ratchet) gives every message a fresh key.
//!   [`session::Session`] ties the two together.
//! * **Channels** use [`sender_keys`]: each member has one key chain per
//!   community, delivered to the others over DM sessions, so a message is
//!   encrypted once no matter how many people are in the channel.
//!
//! Primitives: X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM.
//!
//! This is research code. It has not been audited. Don't protect anything real with it.

pub mod error;
pub mod identity;
pub mod keys;
pub mod padding;
pub mod ratchet;
pub mod safety;
pub mod sender_keys;
pub mod session;
pub mod x3dh;

pub use error::CryptoError;
pub use identity::{DeviceIdentity, IdentityCert, OneTimePreKey, PreKeyBundle, SignedPreKey};
pub use sender_keys::{OwnSenderKey, PeerSenderKey, SenderKeyDistribution, SenderKeyMessage};
pub use session::{DmCiphertext, Session};
