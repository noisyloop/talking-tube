//! Talking Tube wire protocol.
//!
//! Two layers:
//! * [`frames`]: JSON over WebSocket between a client and its relay. The relay
//!   sees these. Payloads are opaque ciphertext.
//! * [`inner`]: what's inside the ciphertext. Only the members see these.
//!
//! [`invite`] is the shareable invite link format.

pub mod frames;
pub mod inner;
pub mod invite;

pub use frames::{ClientFrame, RelayFrame};

/// Domain-separated message a client signs to log in.
pub fn auth_message(nonce: &[u8]) -> Vec<u8> {
    [b"tt-relay-auth-v1".as_slice(), nonce].concat()
}

/// Largest payload a relay accepts, after base64 decoding.
pub const MAX_PAYLOAD: usize = 64 * 1024;
