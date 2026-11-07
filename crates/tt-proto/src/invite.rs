//! Invite links: `tt1.<base64url(json)>`.
//!
//! An invite says which relay, which community, and who to ask. The token is
//! a random secret the inviter checks; anyone holding the link can ask to
//! join, so share it like a password.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tt_core::{CommunityId, DeviceKey};

const PREFIX: &str = "tt1.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub relay: String,
    pub community: CommunityId,
    /// Shown before joining. Not trusted: the real name comes with the Welcome.
    pub name_hint: String,
    pub inviter: DeviceKey,
    pub token: String,
}

impl Invite {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serializes");
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let body = s.trim().strip_prefix(PREFIX).ok_or("not a tt1 invite")?;
        let json = URL_SAFE_NO_PAD.decode(body).map_err(|e| e.to_string())?;
        serde_json::from_slice(&json).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let i = Invite {
            relay: "ws://127.0.0.1:7070".into(),
            community: CommunityId::random(),
            name_hint: "Club".into(),
            inviter: DeviceKey::random(),
            token: "abc".into(),
        };
        assert_eq!(Invite::decode(&i.encode()).unwrap(), i);
    }
}
