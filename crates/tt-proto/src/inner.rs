//! Plaintext payloads, which only exist after decryption.
//!
//! * A DM payload ([`DmPayload`]) is padded, then encrypted with the pairwise
//!   Double Ratchet session.
//! * A community payload ([`tt_core::CommunityEvent`]) is padded, then
//!   encrypted with the sender's sender key.

use serde::{Deserialize, Serialize};
use tt_core::{ChatEvent, CommunityId, CommunityState, DeviceKey};
use tt_crypto::SenderKeyDistribution;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DmPayload {
    /// A normal DM.
    Chat { event: ChatEvent },
    /// Change the disappearing timer of this DM conversation.
    SetTimer { secs: Option<u64> },
    /// "Let me in": sent to the person who made the invite.
    JoinRequest { community: CommunityId, token: String, display_name: String },
    /// The inviter's answer: the community as of `cursor`. The joiner reads
    /// the community stream from `cursor + 1`.
    Welcome { state: CommunityState, cursor: u64 },
    JoinRejected { community: CommunityId, reason: String },
    /// Our sender key for a community, so this member can read our posts.
    SenderKey { community: CommunityId, distribution: SenderKeyDistribution },
}

/// Associated data for community messages: binds a ciphertext to one
/// community and one sender, so it can't be replayed elsewhere.
pub fn community_ad(community: &CommunityId, sender: &DeviceKey) -> Vec<u8> {
    [b"tt-community-v1".as_slice(), community.as_bytes(), sender.as_bytes()].concat()
}
