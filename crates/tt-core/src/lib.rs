//! Shared domain types for Talking Tube.
//!
//! There are no accounts, and no email or phone number is ever collected. A user *is* an Ed25519 public key generated on the
//! device. Display names are self-asserted and per-community.

pub mod ids;
pub mod model;

pub use ids::{ChannelId, CommunityId, DeviceKey, MessageId};
pub use model::{Channel, ChannelKind, Community, Member, Role};
