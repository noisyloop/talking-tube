//! Message history for one channel or DM, and the chat events that change it.
//!
//! Disappearing messages: a message's deadline is the *earliest* of
//! * the `expires_at` its sender chose, and
//! * the time we received it plus the channel's (or DM's) timer.
//!
//! So a sender can make a message vanish sooner than the timer, never later.
//! [`History::purge_expired`] deletes messages whose deadline has passed.
//! Clients call it on a timer; the relay deletes the ciphertext at the same time.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ids::{DeviceKey, MessageId};
use crate::MAX_TEXT_CHARS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatEvent {
    Post {
        id: MessageId,
        text: String,
        reply_to: Option<MessageId>,
        sent_at: u64,
        expires_at: Option<u64>,
    },
    Edit { id: MessageId, text: String },
    Delete { id: MessageId },
    React { id: MessageId, emoji: String, on: bool },
    Pin { id: MessageId, on: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: MessageId,
    pub author: DeviceKey,
    pub text: String,
    pub reply_to: Option<MessageId>,
    pub sent_at: u64,
    pub received_at: u64,
    pub expires_at: Option<u64>,
    pub edited: bool,
    pub pinned: bool,
    pub reactions: BTreeMap<String, BTreeSet<DeviceKey>>,
}

/// What the person acting may do beyond touching their own messages.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rights {
    pub delete_any: bool,
    pub pin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    Posted(MessageId),
    Edited(MessageId),
    Deleted(MessageId),
    Reacted(MessageId),
    Pinned(MessageId, bool),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct History {
    pub messages: Vec<StoredMessage>,
}

fn earliest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn check_text(text: &str) -> Result<(), &'static str> {
    if text.trim().is_empty() {
        return Err("empty message");
    }
    if text.chars().count() > MAX_TEXT_CHARS {
        return Err("message too long");
    }
    crate::text::check(text)
}

impl History {
    pub fn get(&self, id: &MessageId) -> Option<&StoredMessage> {
        self.messages.iter().find(|m| &m.id == id)
    }

    fn get_mut(&mut self, id: &MessageId) -> Result<&mut StoredMessage, &'static str> {
        self.messages.iter_mut().find(|m| &m.id == id).ok_or("unknown message")
    }

    /// Finds a message by a hex prefix of its ID (what the UI shows).
    pub fn find_prefix(&self, prefix: &str) -> Option<&StoredMessage> {
        let prefix = prefix.to_lowercase();
        let mut hits = self.messages.iter().filter(|m| m.id.to_string().starts_with(&prefix));
        let first = hits.next()?;
        hits.next().is_none().then_some(first)
    }

    /// Applies `event` from `author`. `timer_secs` is the channel/DM timer.
    pub fn apply(
        &mut self,
        author: DeviceKey,
        event: &ChatEvent,
        rights: Rights,
        received_at: u64,
        timer_secs: Option<u64>,
    ) -> Result<Applied, &'static str> {
        match event {
            ChatEvent::Post { id, text, reply_to, sent_at, expires_at } => {
                check_text(text)?;
                if self.get(id).is_some() {
                    return Err("duplicate message id");
                }
                // Saturating: the timer can come from someone else (a DM peer), and
                // overflow would panic in debug builds.
                let local_deadline =
                    timer_secs.map(|s| received_at.saturating_add(s.saturating_mul(1000)));
                let expires_at = earliest(*expires_at, local_deadline);
                if expires_at.is_some_and(|t| t <= received_at) {
                    return Err("message already expired");
                }
                self.messages.push(StoredMessage {
                    id: *id,
                    author,
                    text: text.clone(),
                    reply_to: *reply_to,
                    sent_at: *sent_at,
                    received_at,
                    expires_at,
                    edited: false,
                    pinned: false,
                    reactions: BTreeMap::new(),
                });
                Ok(Applied::Posted(*id))
            }
            ChatEvent::Edit { id, text } => {
                check_text(text)?;
                let m = self.get_mut(id)?;
                if m.author != author {
                    return Err("you can only edit your own messages");
                }
                m.text = text.clone();
                m.edited = true;
                Ok(Applied::Edited(*id))
            }
            ChatEvent::Delete { id } => {
                let m = self.get_mut(id)?;
                if m.author != author && !rights.delete_any {
                    return Err("you can only delete your own messages");
                }
                self.messages.retain(|m| &m.id != id);
                Ok(Applied::Deleted(*id))
            }
            ChatEvent::React { id, emoji, on } => {
                if emoji.is_empty() || emoji.chars().count() > 8 || crate::text::check(emoji).is_err() {
                    return Err("bad emoji");
                }
                let m = self.get_mut(id)?;
                let set = m.reactions.entry(emoji.clone()).or_default();
                if *on {
                    set.insert(author);
                } else {
                    set.remove(&author);
                    if set.is_empty() {
                        m.reactions.remove(emoji);
                    }
                }
                Ok(Applied::Reacted(*id))
            }
            ChatEvent::Pin { id, on } => {
                if !rights.pin {
                    return Err("you can't pin messages here");
                }
                self.get_mut(id)?.pinned = *on;
                Ok(Applied::Pinned(*id, *on))
            }
        }
    }

    /// Deletes expired messages. Returns how many were removed.
    pub fn purge_expired(&mut self, now: u64) -> usize {
        let before = self.messages.len();
        self.messages.retain(|m| m.expires_at.is_none_or(|t| t > now));
        before - self.messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(id: MessageId, expires_at: Option<u64>) -> ChatEvent {
        ChatEvent::Post { id, text: "hi".into(), reply_to: None, sent_at: 0, expires_at }
    }

    #[test]
    fn timer_caps_sender_expiry() {
        let mut h = History::default();
        let a = MessageId::random();
        let b = MessageId::random();
        let author = DeviceKey::random();
        // Sender asked for no expiry, channel timer is 10s.
        h.apply(author, &post(a, None), Rights::default(), 1_000, Some(10)).unwrap();
        // Sender asked for 2s, channel timer is 10s: sender wins.
        h.apply(author, &post(b, Some(3_000)), Rights::default(), 1_000, Some(10)).unwrap();
        assert_eq!(h.get(&a).unwrap().expires_at, Some(11_000));
        assert_eq!(h.get(&b).unwrap().expires_at, Some(3_000));
        assert_eq!(h.purge_expired(5_000), 1);
        assert_eq!(h.purge_expired(11_000), 1);
        assert!(h.messages.is_empty());
    }

    #[test]
    fn only_authors_edit_and_moderators_delete() {
        let mut h = History::default();
        let id = MessageId::random();
        let alice = DeviceKey::random();
        let bob = DeviceKey::random();
        h.apply(alice, &post(id, None), Rights::default(), 0, None).unwrap();
        let edit = ChatEvent::Edit { id, text: "changed".into() };
        assert!(h.apply(bob, &edit, Rights::default(), 0, None).is_err());
        assert!(h.apply(bob, &ChatEvent::Delete { id }, Rights::default(), 0, None).is_err());
        let moderator = Rights { delete_any: true, pin: true };
        h.apply(bob, &ChatEvent::Delete { id }, moderator, 0, None).unwrap();
        assert!(h.messages.is_empty());
    }

    #[test]
    fn rejects_terminal_escapes() {
        let mut h = History::default();
        let author = DeviceKey::random();
        let fake = ChatEvent::Post {
            id: MessageId::random(),
            text: "\x1b[2J\x1b[Halice: send me your keys".into(),
            reply_to: None,
            sent_at: 0,
            expires_at: None,
        };
        assert!(h.apply(author, &fake, Rights::default(), 0, None).is_err());
        let id = MessageId::random();
        h.apply(author, &post(id, None), Rights::default(), 0, None).unwrap();
        let react = ChatEvent::React { id, emoji: "\x1b[31m".into(), on: true };
        assert!(h.apply(author, &react, Rights::default(), 0, None).is_err());
    }

    #[test]
    fn huge_timer_does_not_overflow() {
        let mut h = History::default();
        let id = MessageId::random();
        let r = h.apply(DeviceKey::random(), &post(id, None), Rights::default(), 1_700_000_000_000, Some(u64::MAX));
        assert!(r.is_ok());
        assert_eq!(h.get(&id).unwrap().expires_at, Some(u64::MAX));
    }

    #[test]
    fn reactions_toggle() {
        let mut h = History::default();
        let id = MessageId::random();
        let a = DeviceKey::random();
        h.apply(a, &post(id, None), Rights::default(), 0, None).unwrap();
        let react = |on| ChatEvent::React { id, emoji: "🔥".into(), on };
        h.apply(a, &react(true), Rights::default(), 0, None).unwrap();
        assert_eq!(h.get(&id).unwrap().reactions["🔥"].len(), 1);
        h.apply(a, &react(false), Rights::default(), 0, None).unwrap();
        assert!(h.get(&id).unwrap().reactions.is_empty());
    }
}
