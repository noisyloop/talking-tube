use serde::{Deserialize, Serialize};

use crate::ids::{ChannelId, CommunityId, DeviceKey};

/// A Discord-style "server". Called a community to avoid confusion with the relay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Community {
    pub id: CommunityId,
    /// Encrypted to members; the relay only stores the ciphertext.
    pub name: String,
    pub channels: Vec<Channel>,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub kind: ChannelKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelKind {
    Text,
    /// Placeholder; voice is out of scope for the first milestones.
    Voice,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub device: DeviceKey,
    pub display_name: String,
    pub role: Role,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Moderator,
    Member,
}
