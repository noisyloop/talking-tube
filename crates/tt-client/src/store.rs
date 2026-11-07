//! Everything the client remembers, saved as one JSON file.
//!
//! Research shortcut: the file is **not encrypted**. It holds private keys
//! and message history, so it's written with owner-only permissions on Unix.
//! A real client would encrypt it with a key from the OS keychain.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tt_core::{ChannelId, CommunityId, CommunityState, DeviceKey, History};
use tt_crypto::{DeviceIdentity, OneTimePreKey, OwnSenderKey, PeerSenderKey, Session, SignedPreKey};

#[derive(Serialize, Deserialize)]
pub struct Store {
    pub identity: DeviceIdentity,
    pub display_name: String,
    pub spk: SignedPreKey,
    pub opks: BTreeMap<u32, OneTimePreKey>,
    pub next_opk_id: u32,
    /// One-time prekeys with an id below this have been uploaded.
    pub published_opk_id: u32,
    /// Several sessions per peer can exist (both sides started one at once);
    /// the first is the one we send with.
    pub sessions: BTreeMap<DeviceKey, Vec<Session>>,
    pub contacts: BTreeMap<DeviceKey, Contact>,
    pub dms: BTreeMap<DeviceKey, Conversation>,
    pub communities: BTreeMap<CommunityId, LocalCommunity>,
    pub pending_joins: BTreeMap<CommunityId, PendingJoin>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Contact {
    /// Our own label for them.
    pub alias: Option<String>,
    pub verified: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Conversation {
    pub history: History,
    pub timer_secs: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct LocalCommunity {
    pub state: CommunityState,
    /// Last relay sequence number we've processed.
    pub cursor: u64,
    pub my_key: OwnSenderKey,
    /// generation -> key, per member (including us).
    pub peer_keys: BTreeMap<DeviceKey, BTreeMap<u32, PeerSenderKey>>,
    pub channels: BTreeMap<ChannelId, History>,
    pub invites: BTreeMap<String, InviteRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteRecord {
    pub expires_at: u64,
    pub uses_left: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingJoin {
    pub inviter: DeviceKey,
    pub name_hint: String,
}

impl Store {
    pub fn new(display_name: &str) -> Self {
        let identity = DeviceIdentity::generate();
        let spk = identity.generate_spk(1);
        Self {
            identity,
            display_name: display_name.to_string(),
            spk,
            opks: BTreeMap::new(),
            next_opk_id: 1,
            published_opk_id: 1,
            sessions: BTreeMap::new(),
            contacts: BTreeMap::new(),
            dms: BTreeMap::new(),
            communities: BTreeMap::new(),
            pending_joins: BTreeMap::new(),
        }
    }

    pub fn me(&self) -> DeviceKey {
        self.identity.device_key()
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&data).context("parsing store")
    }

    /// Writes to a temp file and renames, so a crash can't leave half a file.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
