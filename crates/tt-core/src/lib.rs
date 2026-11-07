//! Shared domain types for Talking Tube.
//!
//! There are no accounts, and no email or phone number is ever collected.
//! A user *is* an Ed25519 public key generated on the device ([`DeviceKey`]).
//! Display names are self-asserted and per-community.
//!
//! Nothing in this crate does cryptography. It holds the rules: who may do
//! what in a community ([`community`]), and how chat events change a message
//! history ([`history`]), including disappearing messages.

pub mod community;
pub mod encoding;
pub mod history;
pub mod ids;
pub mod time;

pub use community::{Channel, CommunityEvent, CommunityState, Effect, Member, Op, OpError, Role};
pub use history::{Applied, ChatEvent, History, Rights, StoredMessage};
pub use ids::{ChannelId, CommunityId, DeviceKey, MessageId};

/// Longest message body we accept, in characters.
pub const MAX_TEXT_CHARS: usize = 4000;
/// Longest community, channel or display name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
