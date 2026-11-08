//! Protocol logic: sessions, sender keys, community state, disappearing
//! messages, plugins.
//!
//! # How a community message flows
//! 1. We encrypt a [`CommunityEvent`] with our sender key and send it.
//! 2. The relay gives it a sequence number and sends it to every subscriber,
//!    us included.
//! 3. Everyone processes the stream strictly in sequence order
//!    ([`Engine::drain_stream`]). If a message's sender key hasn't arrived
//!    yet, the stream waits for it.
//! 4. Ops change the shared [`CommunityState`]; chat events change a channel's history.
//!
//! # Keys when people come and go
//! * Someone joins: everyone sends them their current sender key over DM.
//! * Someone leaves or is removed: everyone makes a new sender key and sends
//!   it to the remaining members, so the removed person can't read new posts.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use tt_core::time::{hhmm, now_ms};
use tt_core::{
    Applied, ChannelId, ChatEvent, CommunityEvent, CommunityId, CommunityState, DeviceKey, Effect,
    MessageId, Op, Rights, Role, StoredMessage,
};
use tt_crypto::padding::{pad, unpad};
use tt_crypto::{DmCiphertext, OwnSenderKey, PeerSenderKey, PreKeyBundle, SenderKeyDistribution,
    SenderKeyMessage, Session};
use tt_plugin::{parse_command, Action, MessageEvent, Place, Registry};
use tt_proto::inner::{community_ad, DmPayload};
use tt_proto::invite::Invite;
use tt_core::text::sanitize;
use tt_proto::{auth_message, normalize_url, ClientFrame, RelayFrame};

use crate::store::{InviteRecord, LocalCommunity, PendingJoin, Store};

const OPK_BATCH: u32 = 50;
const OPK_LOW: usize = 20;
const MAX_SESSIONS_PER_PEER: usize = 5;
/// How long the stream waits for a missing sender key before skipping the message.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Something for the UI to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Info(String),
    Error(String),
    /// `line` is ready to print; it's prefixed with the place if that isn't the current view.
    Chat { place: Place, line: String },
}

/// Sanitizes every line, keeping our own line breaks (help text, links).
fn clean_lines(s: &str) -> String {
    s.split('\n').map(sanitize).collect::<Vec<_>>().join("\n")
}

/// Printing a notice always strips control characters, as a second line of
/// defense behind the input checks in `tt_core::text`.
impl std::fmt::Display for Notice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Notice::Info(s) => f.write_str(&clean_lines(s)),
            Notice::Error(s) => write!(f, "! {}", clean_lines(s)),
            Notice::Chat { line, .. } => f.write_str(&sanitize(line)),
        }
    }
}

struct Incoming {
    seq: u64,
    from: DeviceKey,
    payload: Vec<u8>,
    arrived: Instant,
}

pub struct Engine {
    pub store: Store,
    path: Option<PathBuf>,
    out: Vec<ClientFrame>,
    notices: Vec<Notice>,
    /// DMs waiting for a prekey bundle so we can start a session.
    pending_dm: HashMap<DeviceKey, Vec<DmPayload>>,
    /// Community messages received but not processed yet, in sequence order.
    stream: HashMap<CommunityId, VecDeque<Incoming>>,
    /// Sender keys that arrived before the Welcome did.
    orphan_keys: HashMap<CommunityId, Vec<(DeviceKey, SenderKeyDistribution)>>,
    plugins: Registry,
    /// Answer other people's plugin commands too.
    pub bot_mode: bool,
    /// Where typed text goes.
    pub view: Option<Place>,
    pub relay_url: Option<String>,
    online: bool,
    dirty: bool,
}

fn json<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("protocol types serialize")
}

impl Engine {
    /// `path` is where the store is saved; `None` keeps it in memory (tests).
    pub fn new(store: Store, path: Option<PathBuf>) -> Self {
        let mut plugins = Registry::default();
        plugins.register(Box::new(tt_plugin_echo::Echo));
        plugins.register(Box::new(tt_plugin_dice::Dice));
        Self {
            store,
            path,
            out: Vec::new(),
            notices: Vec::new(),
            pending_dm: HashMap::new(),
            stream: HashMap::new(),
            orphan_keys: HashMap::new(),
            plugins,
            bot_mode: false,
            view: None,
            relay_url: None,
            online: false,
            dirty: false,
        }
    }

    pub fn plugins_mut(&mut self) -> &mut Registry {
        &mut self.plugins
    }

    pub(crate) fn plugins(&self) -> &Registry {
        &self.plugins
    }

    pub fn me(&self) -> DeviceKey {
        self.store.me()
    }

    pub fn is_online(&self) -> bool {
        self.online
    }

    pub fn take_outgoing(&mut self) -> Vec<ClientFrame> {
        std::mem::take(&mut self.out)
    }

    pub fn take_notices(&mut self) -> Vec<Notice> {
        std::mem::take(&mut self.notices)
    }

    pub fn save_if_dirty(&mut self) -> anyhow::Result<()> {
        if self.dirty {
            if let Some(p) = &self.path {
                self.store.save(p)?;
            }
            self.dirty = false;
        }
        Ok(())
    }

    pub(crate) fn info(&mut self, s: impl Into<String>) {
        self.notices.push(Notice::Info(s.into()));
    }

    pub(crate) fn error(&mut self, s: impl Into<String>) {
        self.notices.push(Notice::Error(s.into()));
    }

    fn send(&mut self, frame: ClientFrame) {
        if self.online {
            self.out.push(frame);
        }
    }

    // ───────────────────────── connection ─────────────────────────

    pub fn on_connected(&mut self, url: &str) {
        self.relay_url = Some(normalize_url(url));
        self.online = false;
        // Anything buffered is re-sent by the relay when we resubscribe.
        self.stream.clear();
    }

    pub fn on_disconnected(&mut self) {
        self.online = false;
        self.out.clear();
    }

    pub fn handle_frame(&mut self, frame: RelayFrame) {
        self.dirty = true;
        match frame {
            RelayFrame::Challenge { relay, nonce } => {
                // Only sign a challenge for the relay we actually dialed.
                let dialed = self.relay_url.clone().unwrap_or_default();
                if normalize_url(&relay) != dialed {
                    return self.error(format!(
                        "refusing to log in: we dialed {dialed} but the relay says it is {}",
                        sanitize(&relay)
                    ));
                }
                let signature = self.store.identity.sign(&auth_message(&dialed, &nonce));
                self.out.push(ClientFrame::Auth { device: self.me(), signature });
            }
            RelayFrame::AuthOk { opks_remaining } => {
                self.online = true;
                self.publish_prekeys(opks_remaining < OPK_LOW);
                let subs: Vec<_> =
                    self.store.communities.iter().map(|(id, c)| (*id, c.cursor)).collect();
                for (community, since) in subs {
                    self.send(ClientFrame::Subscribe { community, since });
                }
                let waiting: Vec<_> = self.pending_dm.keys().copied().collect();
                for device in waiting {
                    self.send(ClientFrame::FetchPrekeys { device });
                }
                self.info("connected");
            }
            RelayFrame::PrekeysLow { .. } => self.publish_prekeys(true),
            RelayFrame::Prekeys { device, bundle } => self.on_prekeys(device, bundle),
            RelayFrame::Dm { id, from, payload, sent_at } => {
                // Ack first: even a message we can't read shouldn't be redelivered forever.
                self.send(ClientFrame::AckDm { id });
                if let Err(e) = self.on_dm(from, &payload, sent_at) {
                    let who = self.name_of(None, &from);
                    self.error(format!("dropped a DM from {who}: {e}"));
                }
            }
            RelayFrame::Community { community, seq, from, payload, .. } => {
                self.stream.entry(community).or_default().push_back(Incoming {
                    seq,
                    from,
                    payload,
                    arrived: Instant::now(),
                });
                self.drain_stream(community);
            }
            RelayFrame::Synced { .. } => {}
            RelayFrame::Error { message } => self.error(format!("relay: {}", sanitize(&message))),
        }
    }

    fn publish_prekeys(&mut self, generate_more: bool) {
        if generate_more {
            let start = self.store.next_opk_id;
            for opk in self.store.identity.generate_opks(start, OPK_BATCH) {
                self.store.opks.insert(opk.public.id, opk);
            }
            self.store.next_opk_id += OPK_BATCH;
        }
        let new_opks = self
            .store
            .opks
            .range(self.store.published_opk_id..)
            .map(|(_, o)| o.public.clone())
            .collect();
        self.store.published_opk_id = self.store.next_opk_id;
        self.send(ClientFrame::PublishPrekeys {
            cert: self.store.identity.cert.clone(),
            spk: self.store.spk.public.clone(),
            new_opks,
        });
    }

    // ───────────────────────── DMs ─────────────────────────

    pub(crate) fn send_dm(&mut self, peer: DeviceKey, payload: DmPayload) {
        if peer == self.me() {
            return;
        }
        if self.store.sessions.get(&peer).is_some_and(|s| !s.is_empty()) {
            return self.encrypt_dm(peer, payload);
        }
        // No session yet: ask the relay for their prekeys and queue the message.
        let queue = self.pending_dm.entry(peer).or_default();
        queue.push(payload);
        if queue.len() == 1 {
            self.send(ClientFrame::FetchPrekeys { device: peer });
        }
    }

    fn encrypt_dm(&mut self, peer: DeviceKey, payload: DmPayload) {
        let expires_at = match &payload {
            DmPayload::Chat { event: ChatEvent::Post { expires_at, .. } } => *expires_at,
            _ => None,
        };
        let plaintext = pad(&json(&payload));
        let cert = self.store.identity.cert.clone();
        let session = &mut self.store.sessions.get_mut(&peer).expect("checked by caller")[0];
        match session.encrypt(&cert, &plaintext) {
            Ok(ct) => {
                self.send(ClientFrame::SendDm { to: peer, payload: json(&ct), expires_at });
                self.dirty = true;
            }
            Err(e) => self.error(format!("couldn't encrypt: {e}")),
        }
    }

    fn on_prekeys(&mut self, device: DeviceKey, bundle: Option<PreKeyBundle>) {
        let queued = self.pending_dm.remove(&device).unwrap_or_default();
        if queued.is_empty() {
            return;
        }
        let Some(bundle) = bundle else {
            let who = self.name_of(None, &device);
            return self.error(format!("{who} has never connected to this relay, so they can't get messages yet"));
        };
        if bundle.cert.device != device {
            return self.error("relay sent prekeys for the wrong device");
        }
        // A session may have appeared meanwhile (they messaged us first).
        if self.store.sessions.get(&device).is_none_or(|s| s.is_empty()) {
            match Session::initiate(&self.store.identity, &bundle) {
                Ok(s) => self.store.sessions.entry(device).or_default().insert(0, s),
                Err(e) => return self.error(format!("bad prekey bundle: {e}")),
            }
        }
        for payload in queued {
            self.encrypt_dm(device, payload);
        }
    }

    fn on_dm(&mut self, from: DeviceKey, payload: &[u8], sent_at: u64) -> anyhow::Result<()> {
        let ct: DmCiphertext = serde_json::from_slice(payload)?;
        let mut warning = None;
        let plaintext = match ct {
            DmCiphertext::PreKey { sender, init, header, ciphertext } => {
                if sender.device != from {
                    bail!("identity certificate doesn't match the sender");
                }
                let store = &mut self.store;
                let sessions = store.sessions.entry(from).or_default();
                if let Some(i) = sessions.iter().position(|s| s.created_by(&init.ek_pub)) {
                    // Another message from a handshake we've already accepted.
                    let pt = sessions[i].decrypt(&header, &ciphertext)?;
                    let s = sessions.remove(i);
                    sessions.insert(0, s);
                    pt
                } else {
                    if init.spk_id != store.spk.public.id {
                        bail!("they used a signed prekey we don't have");
                    }
                    let opk = match init.opk_id {
                        Some(id) => Some(
                            store.opks.get(&id).cloned().ok_or_else(|| anyhow!("one-time prekey already used"))?,
                        ),
                        None => None,
                    };
                    let mut s = Session::respond(&store.identity, &store.spk, opk.as_ref(), &sender, &init)?;
                    let pt = s.decrypt(&header, &ciphertext)?;
                    // Only now is it safe to burn the one-time prekey.
                    if let Some(id) = init.opk_id {
                        store.opks.remove(&id);
                    }
                    if sessions.first().is_some_and(|old| old.peer.dh_pub != sender.dh_pub) {
                        warning = Some("their identity DH key changed; compare safety numbers");
                    }
                    sessions.insert(0, s);
                    sessions.truncate(MAX_SESSIONS_PER_PEER);
                    pt
                }
            }
            DmCiphertext::Normal { header, ciphertext } => {
                let sessions = self.store.sessions.get_mut(&from).ok_or_else(|| anyhow!("no session"))?;
                let (i, pt) = sessions
                    .iter_mut()
                    .enumerate()
                    .find_map(|(i, s)| s.decrypt(&header, &ciphertext).ok().map(|pt| (i, pt)))
                    .ok_or_else(|| anyhow!("no session could decrypt it"))?;
                let s = sessions.remove(i);
                sessions.insert(0, s);
                pt
            }
        };
        if let Some(w) = warning {
            let who = self.name_of(None, &from);
            self.error(format!("{who}: {w}"));
        }
        let payload: DmPayload = serde_json::from_slice(unpad(&plaintext)?)?;
        self.on_dm_payload(from, payload, sent_at);
        Ok(())
    }

    fn on_dm_payload(&mut self, from: DeviceKey, payload: DmPayload, _sent_at: u64) {
        match payload {
            DmPayload::Chat { event } => {
                let now = now_ms();
                let conv = self.store.dms.entry(from).or_default();
                let rights = Rights { delete_any: false, pin: true };
                match conv.history.apply(from, &event, rights, now, conv.timer_secs) {
                    Ok(applied) => self.after_chat(Place::Dm(from), from, applied),
                    Err(e) => self.error(format!("ignored DM event: {e}")),
                }
            }
            DmPayload::SetTimer { secs } => {
                // The peer picks this number; keep it in the same range as channel timers.
                if let Err(e) = check_timer(secs) {
                    return self.error(format!("ignored a DM timer change: {e}"));
                }
                self.store.dms.entry(from).or_default().timer_secs = secs;
                let who = self.name_of(None, &from);
                self.info(format!("{who} set disappearing messages to {}", describe_timer(secs)));
            }
            DmPayload::JoinRequest { community, token, display_name } => {
                if let Err(reason) = self.on_join_request(from, community, &token, &display_name) {
                    self.send_dm(from, DmPayload::JoinRejected { community, reason: reason.clone() });
                    self.info(format!("turned down a join request: {}", sanitize(&reason)));
                }
            }
            DmPayload::Welcome { state, cursor } => self.on_welcome(from, state, cursor),
            DmPayload::JoinRejected { community, reason } => {
                if self.store.pending_joins.get(&community).is_some_and(|p| p.inviter == from) {
                    self.store.pending_joins.remove(&community);
                    self.orphan_keys.remove(&community);
                    self.error(format!("join refused: {}", sanitize(&reason)));
                }
            }
            DmPayload::SenderKey { community, distribution } => {
                self.on_sender_key(from, community, distribution)
            }
        }
    }

    pub fn set_dm_timer(&mut self, peer: DeviceKey, secs: Option<u64>) -> Result<(), String> {
        check_timer(secs)?;
        self.store.dms.entry(peer).or_default().timer_secs = secs;
        self.send_dm(peer, DmPayload::SetTimer { secs });
        self.info(format!("disappearing messages: {}", describe_timer(secs)));
        Ok(())
    }

    // ───────────────────────── joining ─────────────────────────

    pub fn create_community(&mut self, name: &str) -> Result<CommunityId, String> {
        let id = CommunityId::random();
        let me = self.me();
        let state = CommunityState::new(id, me, &self.store.display_name, name, now_ms())
            .map_err(|e| e.to_string())?;
        let general = state.channels[0].id;
        self.add_local_community(state, 0);
        self.view = Some(Place::Channel(id, general));
        self.info(format!("created {name}"));
        Ok(id)
    }

    fn add_local_community(&mut self, state: CommunityState, cursor: u64) {
        let id = state.id;
        let me = self.me();
        let my_key = OwnSenderKey::generate(0);
        let mut local = LocalCommunity {
            state,
            cursor,
            peer_keys: Default::default(),
            channels: Default::default(),
            invites: Default::default(),
            my_key,
        };
        // Keep a reader copy of our own key so we can read our own posts.
        local
            .peer_keys
            .entry(me)
            .or_default()
            .insert(0, PeerSenderKey::from_distribution(&local.my_key.distribution()));
        for (from, d) in self.orphan_keys.remove(&id).unwrap_or_default() {
            local.peer_keys.entry(from).or_default().insert(d.generation, PeerSenderKey::from_distribution(&d));
        }
        let members: Vec<DeviceKey> = local.state.members.keys().copied().collect();
        self.store.communities.insert(id, local);
        self.distribute_my_key(id, members);
        self.send(ClientFrame::Subscribe { community: id, since: cursor });
        self.dirty = true;
    }

    pub fn create_invite(&mut self, community: CommunityId, hours: u64, uses: Option<u32>)
        -> Result<String, String> {
        let relay = self.relay_url.clone().ok_or("connect to a relay first")?;
        let me = self.me();
        let c = self.store.communities.get_mut(&community).ok_or("unknown community")?;
        if c.state.role_of(&me).is_none_or(|r| r < c.state.invite_role) {
            return Err(format!("only {}s and above can invite here", c.state.invite_role));
        }
        let token = hex::encode(tt_crypto::keys::random_bytes::<16>());
        c.invites.insert(
            token.clone(),
            InviteRecord {
                expires_at: now_ms().saturating_add(hours.min(24 * 365).saturating_mul(3_600_000)),
                uses_left: uses,
            },
        );
        self.dirty = true;
        Ok(Invite { relay, community, name_hint: c.state.name.clone(), inviter: me, token }.encode())
    }

    pub fn join(&mut self, invite: &str) -> Result<(), String> {
        let mut invite = Invite::decode(invite)?;
        // Anyone can write an invite; its name is shown before we trust anything.
        invite.name_hint = sanitize(&invite.name_hint);
        let relay = self.relay_url.as_deref().ok_or("connect to a relay first")?;
        if normalize_url(&invite.relay) != relay {
            let r = sanitize(&invite.relay);
            return Err(format!("this invite is for {r}; run `tt run --relay {r}`"));
        }
        if self.store.communities.contains_key(&invite.community) {
            return Err("you're already in that community".into());
        }
        self.store.pending_joins.insert(
            invite.community,
            PendingJoin { inviter: invite.inviter, name_hint: invite.name_hint.clone() },
        );
        let display_name = self.store.display_name.clone();
        self.send_dm(
            invite.inviter,
            DmPayload::JoinRequest { community: invite.community, token: invite.token, display_name },
        );
        self.info(format!("asked to join {} (the inviter has to be online to let you in)", invite.name_hint));
        Ok(())
    }

    fn on_join_request(&mut self, from: DeviceKey, community: CommunityId, token: &str, name: &str)
        -> Result<(), String> {
        let me = self.me();
        let now = now_ms();
        let c = self.store.communities.get_mut(&community).ok_or("unknown community")?;
        let invite = c
            .invites
            .get_mut(token)
            .filter(|r| r.expires_at > now && r.uses_left != Some(0))
            .ok_or("that invite is invalid or expired")?;
        let op = Op::AddMember { device: from, display_name: name.to_string() };
        c.state.clone().apply(&me, &op, now).map_err(|e| e.to_string())?;
        if let Some(n) = invite.uses_left.as_mut() {
            *n -= 1;
        }
        // The Welcome goes out once the relay has ordered this op (see on_effect).
        self.send_community(community, CommunityEvent::Op { op })
    }

    fn on_welcome(&mut self, from: DeviceKey, state: CommunityState, cursor: u64) {
        let Some(pending) = self.store.pending_joins.get(&state.id) else {
            return self.error("got a welcome we didn't ask for");
        };
        if pending.inviter != from || !state.is_member(&self.me()) {
            return self.error("got a welcome that doesn't match our request");
        }
        self.store.pending_joins.remove(&state.id);
        let (id, name, first) = (state.id, state.name.clone(), state.channels[0].id);
        self.add_local_community(state, cursor);
        self.view = Some(Place::Channel(id, first));
        self.info(format!("joined {name}"));
    }

    // ───────────────────────── sender keys ─────────────────────────

    fn on_sender_key(&mut self, from: DeviceKey, community: CommunityId, d: SenderKeyDistribution) {
        if from == self.me() {
            return;
        }
        if let Some(c) = self.store.communities.get_mut(&community) {
            // Never replace a key we already have: that would rewind the chain.
            c.peer_keys
                .entry(from)
                .or_default()
                .entry(d.generation)
                .or_insert_with(|| PeerSenderKey::from_distribution(&d));
            self.drain_stream(community);
        } else if self.store.pending_joins.contains_key(&community) {
            self.orphan_keys.entry(community).or_default().push((from, d));
        }
    }

    fn distribute_my_key(&mut self, community: CommunityId, to: Vec<DeviceKey>) {
        let Some(c) = self.store.communities.get(&community) else { return };
        let distribution = c.my_key.distribution();
        for peer in to {
            self.send_dm(peer, DmPayload::SenderKey { community, distribution: distribution.clone() });
        }
    }

    fn rotate_my_key(&mut self, community: CommunityId) {
        let me = self.me();
        let Some(c) = self.store.communities.get_mut(&community) else { return };
        c.my_key = c.my_key.rotate();
        let copy = PeerSenderKey::from_distribution(&c.my_key.distribution());
        c.peer_keys.entry(me).or_default().insert(c.my_key.generation, copy);
        let members = c.state.members.keys().copied().collect();
        self.distribute_my_key(community, members);
    }

    // ───────────────────────── community stream ─────────────────────────

    pub(crate) fn send_community(&mut self, community: CommunityId, event: CommunityEvent)
        -> Result<(), String> {
        if !self.online {
            return Err("not connected".into());
        }
        let me = self.me();
        let c = self.store.communities.get_mut(&community).ok_or("unknown community")?;
        let now = now_ms();
        let expires_at = match &event {
            CommunityEvent::Chat { event: ChatEvent::Post { expires_at, .. }, .. } => *expires_at,
            CommunityEvent::Chat { channel, .. } => c
                .state
                .channel(channel)
                .and_then(|ch| ch.disappearing_secs)
                .map(|s| now + s * 1000),
            CommunityEvent::Op { .. } => None,
        };
        let msg = c.my_key.encrypt(&community_ad(&community, &me), &pad(&json(&event)));
        self.dirty = true;
        self.send(ClientFrame::SendCommunity { community, payload: json(&msg), expires_at });
        Ok(())
    }

    /// Processes buffered community messages in order, stopping at the first
    /// one whose sender key we don't have yet.
    fn drain_stream(&mut self, community: CommunityId) {
        enum Step {
            Stop,
            Skip,
            Apply(DeviceKey, CommunityEvent),
            Warn(String),
        }
        loop {
            let step = 'step: {
                let Some(c) = self.store.communities.get_mut(&community) else {
                    self.stream.remove(&community);
                    return;
                };
                let Some(q) = self.stream.get_mut(&community) else { return };
                let Some(item) = q.front() else { return };
                if item.seq <= c.cursor {
                    q.pop_front();
                    Step::Skip
                } else if !c.state.is_member(&item.from) {
                    // Anyone subscribed can post; only members count.
                    c.cursor = q.pop_front().expect("front").seq;
                    Step::Skip
                } else {
                    match serde_json::from_slice::<SenderKeyMessage>(&item.payload) {
                        Err(_) => {
                            c.cursor = q.pop_front().expect("front").seq;
                            Step::Warn("skipped a malformed message".into())
                        }
                        Ok(msg) => {
                            let from = item.from;
                            // Missing key: wait for it (on_sender_key or tick restarts us).
                            let Some(gens) = c.peer_keys.get_mut(&from) else { break 'step Step::Stop };
                            let Some(key) = gens.get_mut(&msg.generation) else { break 'step Step::Stop };
                            let result = key.decrypt(&community_ad(&community, &from), &msg);
                            c.cursor = q.pop_front().expect("front").seq;
                            match result.map_err(|e| e.to_string()).and_then(|pt| {
                                let pt = unpad(&pt).map_err(|e| e.to_string())?;
                                serde_json::from_slice::<CommunityEvent>(pt).map_err(|e| e.to_string())
                            }) {
                                Ok(event) => {
                                    // They've moved to this generation; drop older ones.
                                    gens.retain(|g, _| *g >= msg.generation);
                                    Step::Apply(from, event)
                                }
                                Err(e) => Step::Warn(format!("skipped a message we couldn't read: {e}")),
                            }
                        }
                    }
                }
            };
            match step {
                Step::Stop => return,
                Step::Skip => {}
                Step::Warn(w) => self.info(w),
                Step::Apply(from, event) => self.apply_community_event(community, from, event),
            }
        }
    }

    fn apply_community_event(&mut self, community: CommunityId, author: DeviceKey, event: CommunityEvent) {
        let me = self.me();
        let now = now_ms();
        let Some(c) = self.store.communities.get_mut(&community) else { return };
        match event {
            CommunityEvent::Op { op } => {
                let before = c.state.clone();
                match c.state.apply(&author, &op, now) {
                    Ok(effect) => {
                        if let Op::DeleteChannel { id } = &op {
                            c.channels.remove(id);
                            if self.view == Some(Place::Channel(community, *id)) {
                                self.view = Some(Place::Channel(community, c.state.channels[0].id));
                            }
                        }
                        let line = describe_op(&before, &author, &op);
                        self.notices.push(Notice::Info(format!("[{}] {line}", before.name)));
                        self.on_effect(community, author, effect);
                    }
                    Err(e) if author == me => self.error(format!("not applied: {e}")),
                    Err(_) => {}
                }
            }
            CommunityEvent::Chat { channel, event } => {
                let Some(ch) = c.state.channel(&channel) else { return };
                let timer = ch.disappearing_secs;
                let moderator = c.state.role_of(&author).is_some_and(|r| r >= Role::Moderator);
                let rights = Rights { delete_any: moderator, pin: moderator };
                let history = c.channels.entry(channel).or_default();
                match history.apply(author, &event, rights, now, timer) {
                    Ok(applied) => self.after_chat(Place::Channel(community, channel), author, applied),
                    Err(e) if author == me => self.error(e),
                    Err(_) => {}
                }
            }
        }
    }

    fn on_effect(&mut self, community: CommunityId, author: DeviceKey, effect: Effect) {
        let me = self.me();
        match effect {
            Effect::None => {}
            Effect::MemberAdded(device) => {
                if author == me {
                    // We let them in: send the state as of this op.
                    let c = &self.store.communities[&community];
                    let welcome = DmPayload::Welcome { state: c.state.clone(), cursor: c.cursor };
                    self.send_dm(device, welcome);
                }
                self.distribute_my_key(community, vec![device]);
            }
            Effect::MemberRemoved(device) if device == me => {
                let name = self.store.communities.remove(&community).map(|c| c.state.name);
                self.stream.remove(&community);
                self.send(ClientFrame::Unsubscribe { community });
                if matches!(self.view, Some(Place::Channel(c, _)) if c == community) {
                    self.view = None;
                }
                self.info(format!("you're no longer in {}", name.unwrap_or_default()));
            }
            Effect::MemberRemoved(device) => {
                if let Some(c) = self.store.communities.get_mut(&community) {
                    c.peer_keys.remove(&device);
                }
                self.rotate_my_key(community);
            }
        }
    }

    // ───────────────────────── chat ─────────────────────────

    /// Posts text where `place` says. Plugin commands typed by us run here.
    pub fn post_text(&mut self, place: Place, text: &str, reply_to: Option<MessageId>) -> Result<(), String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty message".into());
        }
        let now = now_ms();
        let timer = self.timer_for(place)?;
        let event = ChatEvent::Post {
            id: MessageId::random(),
            text: text.to_string(),
            reply_to,
            sent_at: now,
            expires_at: timer.map(|s| now + s * 1000),
        };
        self.send_chat(place, event)
    }

    pub(crate) fn timer_for(&self, place: Place) -> Result<Option<u64>, String> {
        Ok(match place {
            Place::Dm(peer) => self.store.dms.get(&peer).and_then(|c| c.timer_secs),
            Place::Channel(community, channel) => self
                .store
                .communities
                .get(&community)
                .ok_or("unknown community")?
                .state
                .channel(&channel)
                .ok_or("unknown channel")?
                .disappearing_secs,
        })
    }

    pub(crate) fn send_chat(&mut self, place: Place, event: ChatEvent) -> Result<(), String> {
        match place {
            Place::Dm(peer) => {
                // DMs have no relay ordering, so apply our own events right away.
                let me = self.me();
                let conv = self.store.dms.entry(peer).or_default();
                let rights = Rights { delete_any: false, pin: true };
                let applied = conv.history.apply(me, &event, rights, now_ms(), conv.timer_secs)?;
                self.after_chat(place, me, applied);
                self.send_dm(peer, DmPayload::Chat { event });
                Ok(())
            }
            // Community events are applied when they come back from the relay.
            Place::Channel(community, channel) => {
                self.send_community(community, CommunityEvent::Chat { channel, event })
            }
        }
    }

    pub fn send_op(&mut self, community: CommunityId, op: Op) -> Result<(), String> {
        let me = self.me();
        let c = self.store.communities.get(&community).ok_or("unknown community")?;
        // Check it locally first so mistakes get a clear error.
        c.state.clone().apply(&me, &op, now_ms()).map_err(|e| e.to_string())?;
        self.send_community(community, CommunityEvent::Op { op })
    }

    fn after_chat(&mut self, place: Place, author: DeviceKey, applied: Applied) {
        let line = match &applied {
            Applied::Posted(id) | Applied::Edited(id) | Applied::Reacted(id) => {
                self.history(place).and_then(|h| h.get(id)).map(|m| self.format_message(place, m))
            }
            Applied::Deleted(id) => Some(format!("message {} was deleted", &id.to_string()[..6])),
            Applied::Pinned(id, on) => {
                Some(format!("message {} {}", &id.to_string()[..6], if *on { "pinned" } else { "unpinned" }))
            }
        };
        if let Some(mut line) = line {
            if self.view != Some(place) {
                line = format!("[{}] {line}", self.place_label(place));
            }
            self.notices.push(Notice::Chat { place, line });
        }
        if let Applied::Posted(id) = applied {
            if self.bot_mode && author != self.me() {
                if let Some(text) = self.history(place).and_then(|h| h.get(&id)).map(|m| m.text.clone()) {
                    self.run_plugins(place, author, &text);
                }
            }
        }
    }

    /// Runs plugins on a message. For our own typed commands, `author` is us.
    pub(crate) fn run_plugins(&mut self, place: Place, author: DeviceKey, text: &str) -> bool {
        let name = self.name_of(Some(place), &author);
        let event = MessageEvent { place, author, author_name: &name, text, from_me: author == self.me() };
        let actions: Vec<Action> = if parse_command(text).is_some() {
            match self.plugins.run_command(&event) {
                Some(a) => vec![a],
                None => return false,
            }
        } else {
            self.plugins.run_message_hooks(&event)
        };
        for action in actions {
            match action {
                Action::Reply(t) => {
                    if let Err(e) = self.post_text(place, &t, None) {
                        self.error(e);
                    }
                }
                Action::Notify(t) => self.info(t),
                Action::Ignore => {}
            }
        }
        true
    }

    // ───────────────────────── timers ─────────────────────────

    /// Call about once a second: deletes expired messages and stops waiting
    /// for sender keys that never came.
    pub fn tick(&mut self) {
        let now = now_ms();
        let mut purged = 0;
        for c in self.store.communities.values_mut() {
            for h in c.channels.values_mut() {
                purged += h.purge_expired(now);
            }
        }
        for conv in self.store.dms.values_mut() {
            purged += conv.history.purge_expired(now);
        }
        if purged > 0 {
            self.dirty = true;
        }

        let stuck: Vec<CommunityId> = self
            .stream
            .iter()
            .filter(|(_, q)| q.front().is_some_and(|i| i.arrived.elapsed() > STALL_TIMEOUT))
            .map(|(id, _)| *id)
            .collect();
        for community in stuck {
            if let (Some(q), Some(c)) =
                (self.stream.get_mut(&community), self.store.communities.get_mut(&community))
            {
                if let Some(item) = q.pop_front() {
                    c.cursor = c.cursor.max(item.seq);
                }
            }
            self.info("skipped a message: the sender's key never arrived");
            self.drain_stream(community);
        }
    }

    // ───────────────────────── display helpers ─────────────────────────

    pub fn history(&self, place: Place) -> Option<&tt_core::History> {
        match place {
            Place::Dm(peer) => self.store.dms.get(&peer).map(|c| &c.history),
            Place::Channel(c, ch) => self.store.communities.get(&c)?.channels.get(&ch),
        }
    }

    /// Best name for a device: our alias, their name in this community, any
    /// community, or a short key.
    pub fn name_of(&self, place: Option<Place>, device: &DeviceKey) -> String {
        if let Some(Place::Channel(c, _)) = place {
            if let Some(m) = self.store.communities.get(&c).and_then(|c| c.state.members.get(device)) {
                return m.display_name.clone();
            }
        }
        if *device == self.me() {
            return self.store.display_name.clone();
        }
        if let Some(alias) = self.store.contacts.get(device).and_then(|c| c.alias.clone()) {
            return alias;
        }
        self.store
            .communities
            .values()
            .find_map(|c| c.state.members.get(device).map(|m| m.display_name.clone()))
            .unwrap_or_else(|| device.short())
    }

    pub fn place_label(&self, place: Place) -> String {
        match place {
            Place::Dm(peer) => format!("@{}", self.name_of(None, &peer)),
            Place::Channel(c, ch) => match self.store.communities.get(&c) {
                Some(local) => format!(
                    "{} #{}",
                    local.state.name,
                    local.state.channel(&ch).map_or("?", |ch| ch.name.as_str())
                ),
                None => "?".into(),
            },
        }
    }

    /// Display names aren't unique, so anyone can join as "alice". When a
    /// name is shared in this community, or the author isn't verified and
    /// shares a name with someone we know, add the start of their key.
    fn display_author(&self, place: Place, author: &DeviceKey) -> String {
        let name = self.name_of(Some(place), author);
        let lower = name.to_lowercase();
        let clash = match place {
            Place::Channel(c, _) => self.store.communities.get(&c).is_some_and(|c| {
                c.state.members.iter().any(|(d, m)| d != author && m.display_name.to_lowercase() == lower)
            }),
            Place::Dm(_) => false,
        } || (*author != self.me() && lower == self.store.display_name.to_lowercase());
        if clash {
            format!("{name}#{}", &author.to_string()[..4])
        } else {
            name
        }
    }

    pub fn format_message(&self, place: Place, m: &StoredMessage) -> String {
        let mut line = format!(
            "[{}] {} {}: ",
            &m.id.to_string()[..6],
            hhmm(m.sent_at),
            self.display_author(place, &m.author)
        );
        if let Some(r) = m.reply_to {
            line.push_str(&format!("↪{} ", &r.to_string()[..6]));
        }
        line.push_str(&m.text);
        if m.edited {
            line.push_str(" (edited)");
        }
        if m.pinned {
            line.push_str(" 📌");
        }
        for (emoji, who) in &m.reactions {
            line.push_str(&format!(" {emoji}{}", who.len()));
        }
        if let Some(t) = m.expires_at {
            let left = t.saturating_sub(now_ms()) / 1000;
            line.push_str(&format!(" ⏳{}", describe_secs(left)));
        }
        line
    }
}

/// Disappearing timers must be off or between 5 seconds and 1 year.
pub fn check_timer(secs: Option<u64>) -> Result<(), String> {
    use tt_core::community::{MAX_TIMER_SECS, MIN_TIMER_SECS};
    match secs {
        Some(s) if !(MIN_TIMER_SECS..=MAX_TIMER_SECS).contains(&s) => {
            Err("timer must be between 5s and 1 year".into())
        }
        _ => Ok(()),
    }
}

pub fn describe_secs(s: u64) -> String {
    match s {
        s if s >= 86_400 && s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
        s if s >= 60 && s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

pub fn describe_timer(secs: Option<u64>) -> String {
    secs.map_or("off".into(), describe_secs)
}

fn describe_op(state: &CommunityState, author: &DeviceKey, op: &Op) -> String {
    let name = |d: &DeviceKey| {
        state.members.get(d).map_or_else(|| d.short(), |m| m.display_name.clone())
    };
    let channel = |id: &ChannelId| state.channel(id).map_or("?".to_string(), |c| format!("#{}", c.name));
    let clean = |n: &str| tt_core::community::clean_channel_name(n).unwrap_or_else(|_| n.to_string());
    let who = name(author);
    match op {
        Op::Rename { name } => format!("{who} renamed the community to {name}"),
        Op::CreateChannel { name, .. } => format!("{who} created #{}", clean(name)),
        Op::RenameChannel { id, name } => format!("{who} renamed {} to #{}", channel(id), clean(name)),
        Op::DeleteChannel { id } => format!("{who} deleted {}", channel(id)),
        Op::SetTopic { id, topic } => format!("{who} set the topic of {}: {topic}", channel(id)),
        Op::SetChannelTimer { id, secs } => {
            format!("{who} set disappearing messages in {} to {}", channel(id), describe_timer(*secs))
        }
        Op::SetInviteRole { role } => format!("{who} let {role}s and above invite people"),
        Op::AddMember { display_name, .. } => format!("{who} let {display_name} in"),
        Op::SetRole { device, role } => format!("{who} made {} {role}", name(device)),
        Op::Kick { device } => format!("{who} kicked {}", name(device)),
        Op::Ban { device } => format!("{who} banned {}", name(device)),
        Op::Unban { device } => format!("{who} unbanned {}", device.short()),
        Op::Leave => format!("{who} left"),
        Op::SetNick { display_name } => format!("{who} is now called {display_name}"),
        Op::TransferOwnership { device } => format!("{who} gave ownership to {}", name(device)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(name: &str) -> Engine {
        Engine::new(Store::new(name), None)
    }

    #[test]
    fn refuses_challenges_for_another_relay() {
        let mut e = engine("alice");
        e.on_connected("ws://good.example:7070/");
        // A malicious relay forwards a real relay's challenge.
        e.handle_frame(RelayFrame::Challenge { relay: "ws://victim.example:7070".into(), nonce: vec![1; 32] });
        assert!(e.take_outgoing().is_empty());
        assert!(matches!(e.take_notices().as_slice(), [Notice::Error(_)]));
        // The real thing (case and trailing slash don't matter).
        e.handle_frame(RelayFrame::Challenge { relay: "WS://good.example:7070".into(), nonce: vec![1; 32] });
        let out = e.take_outgoing();
        let [ClientFrame::Auth { device, signature }] = out.as_slice() else { panic!("expected auth") };
        let msg = auth_message("ws://good.example:7070", &[1; 32]);
        tt_crypto::keys::verify(&device.0, &msg, signature).unwrap();
    }

    #[test]
    fn ignores_out_of_range_timers_from_peers() {
        let mut e = engine("alice");
        let peer = DeviceKey::random();
        e.on_dm_payload(peer, DmPayload::SetTimer { secs: Some(u64::MAX) }, 0);
        e.on_dm_payload(peer, DmPayload::SetTimer { secs: Some(0) }, 0);
        assert_eq!(e.store.dms.get(&peer).and_then(|c| c.timer_secs), None);
        e.on_dm_payload(peer, DmPayload::SetTimer { secs: Some(60) }, 0);
        assert_eq!(e.store.dms[&peer].timer_secs, Some(60));
        assert!(e.set_dm_timer(peer, Some(1)).is_err());
    }

    #[test]
    fn printing_strips_control_characters() {
        let n = Notice::Error("relay: \x1b[2Jgotcha\u{202E}".into());
        assert!(!n.to_string().chars().any(tt_core::text::is_unsafe));
        let help = Notice::Info("line one\nline two".into());
        assert_eq!(help.to_string(), "line one\nline two");
    }

    #[test]
    fn shared_names_get_a_key_suffix() {
        let mut e = engine("alice");
        let id = e.create_community("Club").unwrap();
        let general = e.store.communities[&id].state.channels[0].id;
        let me = e.me();
        let impostor = DeviceKey::random();
        let c = e.store.communities.get_mut(&id).unwrap();
        c.state.apply(&me, &Op::AddMember { device: impostor, display_name: "Alice".into() }, 0).unwrap();
        let place = Place::Channel(id, general);
        assert!(e.display_author(place, &impostor).starts_with("Alice#"));
        assert!(e.display_author(place, &me).starts_with("alice#"));
    }
}
