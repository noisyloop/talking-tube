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

/// What a client signs to log in: a label, the relay's URL, and its nonce.
///
/// Including the URL stops a malicious relay from passing another relay's
/// challenge through to you and using your signature to log in as you there.
pub fn auth_message(relay_url: &str, nonce: &[u8]) -> Vec<u8> {
    let url = normalize_url(relay_url);
    [
        b"tt-relay-auth-v2".as_slice(),
        &(url.len() as u32).to_be_bytes(),
        url.as_bytes(),
        nonce,
    ]
    .concat()
}

/// The form of a relay URL that gets compared and signed.
pub fn normalize_url(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Largest payload a relay accepts, after base64 decoding.
pub const MAX_PAYLOAD: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_message_binds_the_relay() {
        let nonce = [7u8; 32];
        assert_eq!(auth_message("ws://a:1/", &nonce), auth_message("WS://A:1", &nonce));
        assert_ne!(auth_message("ws://a:1", &nonce), auth_message("ws://b:1", &nonce));
    }
}
