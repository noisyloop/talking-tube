//! Messages exchanged between a client and a relay over WebSocket.
//!
//! The relay never sees plaintext. It routes [`tt_crypto::Envelope`]s and
//! stores them for offline members. Clients log in by signing a
//! relay-provided challenge with their device key: no email, no phone.

use serde::{Deserialize, Serialize};
use tt_core::{ChannelId, CommunityId, DeviceKey, MessageId};
use tt_crypto::Envelope;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Reply to [`RelayFrame::Challenge`] with an Ed25519 signature.
    Auth { device: DeviceKey, signature: Vec<u8> },
    /// Upload X3DH/PQXDH prekeys so others can start DMs while we're offline.
    PublishPrekeys { bundle: Vec<u8> },
    FetchPrekeys { device: DeviceKey },
    SendDm { to: DeviceKey, envelope: Envelope },
    SendChannel { community: CommunityId, channel: ChannelId, envelope: Envelope },
    Subscribe { community: CommunityId },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    Challenge { nonce: [u8; 32] },
    AuthOk,
    Prekeys { device: DeviceKey, bundle: Vec<u8> },
    Dm { id: MessageId, from: DeviceKey, envelope: Envelope },
    Channel {
        id: MessageId,
        community: CommunityId,
        channel: ChannelId,
        from: DeviceKey,
        envelope: Envelope,
    },
    Error { message: String },
}
