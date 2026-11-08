//! Community ("server") state and the operations that change it.
//!
//! Nobody stores a community's state centrally. Every member keeps a copy and
//! changes it by applying [`Op`]s in the order the relay assigns them. Because
//! everyone applies the same ops in the same order with the same rules,
//! everyone ends up with the same state.
//!
//! An op's author is authenticated by the sender-key signature on the message
//! that carried it (see `tt-crypto`), so this module trusts `author`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::history::ChatEvent;
use crate::ids::{ChannelId, CommunityId, DeviceKey};
use crate::MAX_NAME_CHARS;

/// Roles, lowest to highest. `Ord` follows declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Moderator,
    Admin,
    Owner,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Member => "member",
            Role::Moderator => "moderator",
            Role::Admin => "admin",
            Role::Owner => "owner",
        })
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "member" => Ok(Role::Member),
            "mod" | "moderator" => Ok(Role::Moderator),
            "admin" => Ok(Role::Admin),
            "owner" => Ok(Role::Owner),
            other => Err(format!("unknown role '{other}'")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub display_name: String,
    pub role: Role,
    pub joined_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub topic: String,
    /// Messages in this channel disappear this many seconds after they are sent.
    pub disappearing_secs: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityState {
    pub id: CommunityId,
    pub name: String,
    pub owner: DeviceKey,
    pub members: BTreeMap<DeviceKey, Member>,
    pub channels: Vec<Channel>,
    pub bans: BTreeSet<DeviceKey>,
    /// Lowest role allowed to invite people.
    pub invite_role: Role,
}

/// A change to a community. Carried inside an encrypted [`CommunityEvent`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Rename { name: String },
    CreateChannel { id: ChannelId, name: String },
    RenameChannel { id: ChannelId, name: String },
    DeleteChannel { id: ChannelId },
    SetTopic { id: ChannelId, topic: String },
    /// `None` turns disappearing messages off.
    SetChannelTimer { id: ChannelId, secs: Option<u64> },
    SetInviteRole { role: Role },
    AddMember { device: DeviceKey, display_name: String },
    SetRole { device: DeviceKey, role: Role },
    Kick { device: DeviceKey },
    Ban { device: DeviceKey },
    Unban { device: DeviceKey },
    Leave,
    SetNick { display_name: String },
    TransferOwnership { device: DeviceKey },
}

/// Everything sent inside a community: either a state change or a chat event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommunityEvent {
    Op { op: Op },
    Chat { channel: ChannelId, event: ChatEvent },
}

/// Side effects the client must act on, mostly for key management.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    None,
    /// Send the new member our sender key.
    MemberAdded(DeviceKey),
    /// Rotate our sender key so the removed member can't read new messages.
    MemberRemoved(DeviceKey),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpError {
    #[error("author is not a member")]
    NotMember,
    #[error("not allowed: {0}")]
    Forbidden(&'static str),
    #[error("unknown channel")]
    UnknownChannel,
    #[error("unknown member")]
    UnknownMember,
    #[error("that device is banned")]
    Banned,
    #[error("already a member")]
    AlreadyMember,
    #[error("invalid: {0}")]
    Invalid(&'static str),
}

/// Disappearing timers must be between 5 seconds and 1 year.
pub const MIN_TIMER_SECS: u64 = 5;
pub const MAX_TIMER_SECS: u64 = 365 * 24 * 3600;

fn clean_name(name: &str) -> Result<String, OpError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(OpError::Invalid("name is empty"));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(OpError::Invalid("name is too long"));
    }
    if crate::text::check(name).is_err() {
        return Err(OpError::Invalid("name has control or text-direction characters"));
    }
    Ok(name.to_string())
}

/// Channel names are lowercase with dashes, like Discord.
pub fn clean_channel_name(name: &str) -> Result<String, OpError> {
    let name = clean_name(name)?
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    Ok(name.trim_start_matches('#').to_string())
}

impl CommunityState {
    /// A new community owned by `owner`, with a `#general` channel.
    pub fn new(
        id: CommunityId,
        owner: DeviceKey,
        owner_name: &str,
        name: &str,
        now: u64,
    ) -> Result<Self, OpError> {
        let mut members = BTreeMap::new();
        members.insert(
            owner,
            Member { display_name: clean_name(owner_name)?, role: Role::Owner, joined_at: now },
        );
        Ok(Self {
            id,
            name: clean_name(name)?,
            owner,
            members,
            channels: vec![Channel {
                id: ChannelId::random(),
                name: "general".into(),
                topic: String::new(),
                disappearing_secs: None,
            }],
            bans: BTreeSet::new(),
            invite_role: Role::Member,
        })
    }

    pub fn role_of(&self, device: &DeviceKey) -> Option<Role> {
        self.members.get(device).map(|m| m.role)
    }

    pub fn is_member(&self, device: &DeviceKey) -> bool {
        self.members.contains_key(device)
    }

    pub fn channel(&self, id: &ChannelId) -> Option<&Channel> {
        self.channels.iter().find(|c| &c.id == id)
    }

    pub fn channel_by_name(&self, name: &str) -> Option<&Channel> {
        let name = name.trim_start_matches('#').to_lowercase();
        self.channels.iter().find(|c| c.name == name)
    }

    fn channel_mut(&mut self, id: &ChannelId) -> Result<&mut Channel, OpError> {
        self.channels.iter_mut().find(|c| &c.id == id).ok_or(OpError::UnknownChannel)
    }

    /// Applies `op` written by `author`, or explains why it's not allowed.
    /// On error the state is unchanged.
    pub fn apply(&mut self, author: &DeviceKey, op: &Op, now: u64) -> Result<Effect, OpError> {
        let me = self.role_of(author).ok_or(OpError::NotMember)?;
        let require = |min: Role, what: &'static str| {
            if me >= min {
                Ok(())
            } else {
                Err(OpError::Forbidden(what))
            }
        };

        match op {
            Op::Rename { name } => {
                require(Role::Admin, "only admins can rename the community")?;
                self.name = clean_name(name)?;
            }
            Op::CreateChannel { id, name } => {
                require(Role::Admin, "only admins can create channels")?;
                let name = clean_channel_name(name)?;
                if self.channel(id).is_some() || self.channel_by_name(&name).is_some() {
                    return Err(OpError::Invalid("channel already exists"));
                }
                self.channels.push(Channel {
                    id: *id,
                    name,
                    topic: String::new(),
                    disappearing_secs: None,
                });
            }
            Op::RenameChannel { id, name } => {
                require(Role::Admin, "only admins can rename channels")?;
                let name = clean_channel_name(name)?;
                if self.channel_by_name(&name).is_some_and(|c| &c.id != id) {
                    return Err(OpError::Invalid("channel name taken"));
                }
                self.channel_mut(id)?.name = name;
            }
            Op::DeleteChannel { id } => {
                require(Role::Admin, "only admins can delete channels")?;
                self.channel(id).ok_or(OpError::UnknownChannel)?;
                if self.channels.len() == 1 {
                    return Err(OpError::Invalid("can't delete the last channel"));
                }
                self.channels.retain(|c| &c.id != id);
            }
            Op::SetTopic { id, topic } => {
                require(Role::Moderator, "only moderators can set topics")?;
                if topic.chars().count() > 256 {
                    return Err(OpError::Invalid("topic is too long"));
                }
                if crate::text::check(topic).is_err() {
                    return Err(OpError::Invalid("topic has control or text-direction characters"));
                }
                self.channel_mut(id)?.topic = topic.trim().to_string();
            }
            Op::SetChannelTimer { id, secs } => {
                require(Role::Admin, "only admins can change disappearing timers")?;
                if let Some(s) = secs {
                    if !(MIN_TIMER_SECS..=MAX_TIMER_SECS).contains(s) {
                        return Err(OpError::Invalid("timer must be between 5s and 1 year"));
                    }
                }
                self.channel_mut(id)?.disappearing_secs = *secs;
            }
            Op::SetInviteRole { role } => {
                require(Role::Admin, "only admins can change who can invite")?;
                if *role == Role::Owner {
                    return Err(OpError::Invalid("invite role can't be owner"));
                }
                self.invite_role = *role;
            }
            Op::AddMember { device, display_name } => {
                require(self.invite_role, "your role can't invite people")?;
                if self.bans.contains(device) {
                    return Err(OpError::Banned);
                }
                if self.is_member(device) {
                    return Err(OpError::AlreadyMember);
                }
                self.members.insert(
                    *device,
                    Member {
                        display_name: clean_name(display_name)?,
                        role: Role::Member,
                        joined_at: now,
                    },
                );
                return Ok(Effect::MemberAdded(*device));
            }
            Op::SetRole { device, role } => {
                let target = self.role_of(device).ok_or(OpError::UnknownMember)?;
                if device == author {
                    return Err(OpError::Forbidden("can't change your own role"));
                }
                if *role == Role::Owner {
                    return Err(OpError::Invalid("use transfer_ownership"));
                }
                // You can only manage people below you, and only grant roles below yours.
                if me <= target || me <= *role {
                    return Err(OpError::Forbidden("you can only manage roles below yours"));
                }
                self.members.get_mut(device).expect("checked").role = *role;
            }
            Op::Kick { device } => {
                require(Role::Moderator, "only moderators can kick")?;
                let target = self.role_of(device).ok_or(OpError::UnknownMember)?;
                if me <= target {
                    return Err(OpError::Forbidden("you can only kick people below you"));
                }
                self.members.remove(device);
                return Ok(Effect::MemberRemoved(*device));
            }
            Op::Ban { device } => {
                require(Role::Admin, "only admins can ban")?;
                let was_member = match self.role_of(device) {
                    Some(target) if me <= target => {
                        return Err(OpError::Forbidden("you can only ban people below you"))
                    }
                    Some(_) => true,
                    None => false,
                };
                self.members.remove(device);
                self.bans.insert(*device);
                if was_member {
                    return Ok(Effect::MemberRemoved(*device));
                }
            }
            Op::Unban { device } => {
                require(Role::Admin, "only admins can unban")?;
                self.bans.remove(device);
            }
            Op::Leave => {
                if *author == self.owner {
                    return Err(OpError::Forbidden("the owner must transfer ownership first"));
                }
                self.members.remove(author);
                return Ok(Effect::MemberRemoved(*author));
            }
            Op::SetNick { display_name } => {
                let name = clean_name(display_name)?;
                self.members.get_mut(author).expect("checked").display_name = name;
            }
            Op::TransferOwnership { device } => {
                if *author != self.owner {
                    return Err(OpError::Forbidden("only the owner can transfer ownership"));
                }
                if device == author {
                    return Err(OpError::Invalid("you already own it"));
                }
                self.members.get_mut(device).ok_or(OpError::UnknownMember)?.role = Role::Owner;
                self.members.get_mut(author).expect("checked").role = Role::Admin;
                self.owner = *device;
            }
        }
        Ok(Effect::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (CommunityState, DeviceKey, DeviceKey, DeviceKey) {
        let owner = DeviceKey::random();
        let alice = DeviceKey::random();
        let bob = DeviceKey::random();
        let mut s = CommunityState::new(CommunityId::random(), owner, "owner", "Club", 0).unwrap();
        for (d, n) in [(alice, "alice"), (bob, "bob")] {
            s.apply(&owner, &Op::AddMember { device: d, display_name: n.into() }, 0).unwrap();
        }
        (s, owner, alice, bob)
    }

    #[test]
    fn members_cannot_manage_channels() {
        let (mut s, _, alice, _) = setup();
        let op = Op::CreateChannel { id: ChannelId::random(), name: "memes".into() };
        assert!(matches!(s.apply(&alice, &op, 0), Err(OpError::Forbidden(_))));
    }

    #[test]
    fn roles_only_flow_downwards() {
        let (mut s, owner, alice, bob) = setup();
        s.apply(&owner, &Op::SetRole { device: alice, role: Role::Admin }, 0).unwrap();
        // An admin may make a moderator...
        s.apply(&alice, &Op::SetRole { device: bob, role: Role::Moderator }, 0).unwrap();
        // ...but not another admin, and a moderator can't kick an admin.
        assert!(s.apply(&alice, &Op::SetRole { device: bob, role: Role::Admin }, 0).is_err());
        assert!(s.apply(&bob, &Op::Kick { device: alice }, 0).is_err());
        assert!(s.apply(&alice, &Op::Kick { device: owner }, 0).is_err());
    }

    #[test]
    fn kick_and_ban_report_removal() {
        let (mut s, owner, alice, bob) = setup();
        assert_eq!(s.apply(&owner, &Op::Kick { device: alice }, 0), Ok(Effect::MemberRemoved(alice)));
        assert_eq!(s.apply(&owner, &Op::Ban { device: bob }, 0), Ok(Effect::MemberRemoved(bob)));
        let rejoin = Op::AddMember { device: bob, display_name: "bob".into() };
        assert_eq!(s.apply(&owner, &rejoin, 0), Err(OpError::Banned));
        // Removed members can't act any more.
        assert_eq!(s.apply(&alice, &Op::Leave, 0), Err(OpError::NotMember));
    }

    #[test]
    fn timers_are_bounded() {
        let (mut s, owner, _, _) = setup();
        let id = s.channels[0].id;
        assert!(s.apply(&owner, &Op::SetChannelTimer { id, secs: Some(1) }, 0).is_err());
        s.apply(&owner, &Op::SetChannelTimer { id, secs: Some(60) }, 0).unwrap();
        assert_eq!(s.channels[0].disappearing_secs, Some(60));
    }

    #[test]
    fn owner_cannot_leave_without_transfer() {
        let (mut s, owner, alice, _) = setup();
        assert!(s.apply(&owner, &Op::Leave, 0).is_err());
        s.apply(&owner, &Op::TransferOwnership { device: alice }, 0).unwrap();
        assert_eq!(s.owner, alice);
        assert_eq!(s.apply(&owner, &Op::Leave, 0), Ok(Effect::MemberRemoved(owner)));
    }

    #[test]
    fn rejects_escapes_in_topics_and_names() {
        let (mut s, owner, _, _) = setup();
        let id = s.channels[0].id;
        // OSC 52 would write to the reader's clipboard in some terminals.
        let topic = Op::SetTopic { id, topic: "\x1b]52;c;aGk=\x07".into() };
        assert!(s.apply(&owner, &topic, 0).is_err());
        let nick = Op::SetNick { display_name: "\u{202E}nimda".into() };
        assert!(s.apply(&owner, &nick, 0).is_err());
    }

    #[test]
    fn failed_op_leaves_state_unchanged() {
        let (mut s, _, alice, _) = setup();
        let before = s.clone();
        let _ = s.apply(&alice, &Op::Rename { name: "Mine".into() }, 0);
        assert_eq!(s, before);
    }
}
