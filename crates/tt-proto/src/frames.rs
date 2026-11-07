//! Frames between client and relay.
//!
//! What the relay learns: device keys, which communities each device
//! subscribes to, who sends to whom and when, payload sizes (padded), and when
//! a payload should be deleted. It never learns message text, channel names,
//! channel IDs, member names or community names.

use serde::{Deserialize, Serialize};
use tt_core::encoding::b64;
use tt_core::{CommunityId, DeviceKey};
use tt_crypto::identity::{IdentityCert, OneTimePreKeyPublic, SignedPreKeyPublic};
use tt_crypto::PreKeyBundle;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    /// Answer to [`RelayFrame::Challenge`]: an Ed25519 signature over
    /// [`crate::auth_message`]. No passwords, no email.
    Auth {
        device: DeviceKey,
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    /// Upload our identity cert and signed prekey, and add one-time prekeys.
    PublishPrekeys {
        cert: IdentityCert,
        spk: SignedPreKeyPublic,
        new_opks: Vec<OneTimePreKeyPublic>,
    },
    FetchPrekeys { device: DeviceKey },
    SendDm {
        to: DeviceKey,
        #[serde(with = "b64")]
        payload: Vec<u8>,
        /// When the relay should delete it, delivered or not.
        expires_at: Option<u64>,
    },
    /// We've stored this DM; the relay can delete it.
    AckDm { id: u64 },
    /// Get live community messages, plus stored ones with `seq > since`.
    Subscribe { community: CommunityId, since: u64 },
    Unsubscribe { community: CommunityId },
    /// Post to a community. The relay assigns the next sequence number and
    /// sends it to every subscriber, including us.
    SendCommunity {
        community: CommunityId,
        #[serde(with = "b64")]
        payload: Vec<u8>,
        expires_at: Option<u64>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrame {
    Challenge {
        #[serde(with = "b64")]
        nonce: Vec<u8>,
    },
    AuthOk { opks_remaining: usize },
    /// The relay is running low on our one-time prekeys.
    PrekeysLow { remaining: usize },
    /// `bundle` is `None` if that device never published prekeys.
    Prekeys { device: DeviceKey, bundle: Option<PreKeyBundle> },
    Dm {
        id: u64,
        from: DeviceKey,
        #[serde(with = "b64")]
        payload: Vec<u8>,
        sent_at: u64,
    },
    Community {
        community: CommunityId,
        seq: u64,
        from: DeviceKey,
        #[serde(with = "b64")]
        payload: Vec<u8>,
        sent_at: u64,
    },
    /// All stored messages after `since` have been sent.
    Synced { community: CommunityId, head: u64 },
    Error { message: String },
}
