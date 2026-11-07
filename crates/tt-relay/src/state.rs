//! The relay's in-memory state. Every method takes the lock briefly and
//! never awaits, and every frame for a device goes through that device's
//! queue while the lock is held, so devices see messages in sequence order.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use tokio::sync::mpsc::UnboundedSender;
use tt_core::time::now_ms;
use tt_core::{CommunityId, DeviceKey};
use tt_crypto::identity::{IdentityCert, OneTimePreKeyPublic, SignedPreKeyPublic};
use tt_crypto::PreKeyBundle;
use tt_proto::{ClientFrame, RelayFrame, MAX_PAYLOAD};

use crate::Config;

const MAX_OPKS: usize = 500;
const OPKS_LOW: usize = 10;
const MAX_MAILBOX: usize = 10_000;
const MAX_LOG: usize = 50_000;

struct Conn {
    id: u64,
    tx: UnboundedSender<RelayFrame>,
    subscriptions: HashSet<CommunityId>,
}

struct Prekeys {
    cert: IdentityCert,
    spk: SignedPreKeyPublic,
    opks: VecDeque<OneTimePreKeyPublic>,
}

struct StoredDm {
    from: DeviceKey,
    payload: Vec<u8>,
    sent_at: u64,
    delete_at: u64,
}

struct Entry {
    seq: u64,
    from: DeviceKey,
    payload: Vec<u8>,
    sent_at: u64,
    delete_at: u64,
}

#[derive(Default)]
struct Log {
    next_seq: u64,
    entries: VecDeque<Entry>,
    subscribers: HashSet<DeviceKey>,
}

#[derive(Default)]
struct State {
    next_conn: u64,
    next_dm: u64,
    conns: HashMap<DeviceKey, Conn>,
    prekeys: HashMap<DeviceKey, Prekeys>,
    mailboxes: HashMap<DeviceKey, BTreeMap<u64, StoredDm>>,
    logs: HashMap<CommunityId, Log>,
}

impl State {
    fn send(&self, to: &DeviceKey, frame: RelayFrame) {
        if let Some(c) = self.conns.get(to) {
            let _ = c.tx.send(frame);
        }
    }
}

pub struct Relay {
    config: Config,
    state: Mutex<State>,
}

fn error(message: impl Into<String>) -> RelayFrame {
    RelayFrame::Error { message: message.into() }
}

impl Relay {
    pub fn new(config: Config) -> Self {
        Self { config, state: Mutex::new(State::default()) }
    }

    fn delete_at(&self, now: u64, expires_at: Option<u64>) -> u64 {
        let max = now + self.config.retention.as_millis() as u64;
        expires_at.map_or(max, |t| t.min(max))
    }

    /// Registers a logged-in connection, replacing any older one for the
    /// device, then sends AuthOk and the device's mailbox.
    pub fn connect(&self, device: DeviceKey, tx: UnboundedSender<RelayFrame>) -> u64 {
        let mut s = self.state.lock().unwrap();
        s.next_conn += 1;
        let id = s.next_conn;
        if let Some(old) = s.conns.remove(&device) {
            for c in old.subscriptions {
                if let Some(log) = s.logs.get_mut(&c) {
                    log.subscribers.remove(&device);
                }
            }
        }
        let opks_remaining = s.prekeys.get(&device).map_or(0, |p| p.opks.len());
        let _ = tx.send(RelayFrame::AuthOk { opks_remaining });
        let now = now_ms();
        if let Some(mailbox) = s.mailboxes.get(&device) {
            for (id, dm) in mailbox.iter().filter(|(_, d)| d.delete_at > now) {
                let _ = tx.send(RelayFrame::Dm {
                    id: *id,
                    from: dm.from,
                    payload: dm.payload.clone(),
                    sent_at: dm.sent_at,
                });
            }
        }
        s.conns.insert(device, Conn { id, tx, subscriptions: HashSet::new() });
        id
    }

    pub fn disconnect(&self, device: &DeviceKey, conn_id: u64) {
        let mut s = self.state.lock().unwrap();
        if s.conns.get(device).map(|c| c.id) != Some(conn_id) {
            return; // a newer connection already replaced this one
        }
        let conn = s.conns.remove(device).expect("checked");
        for c in conn.subscriptions {
            if let Some(log) = s.logs.get_mut(&c) {
                log.subscribers.remove(device);
            }
        }
    }

    pub fn reply(&self, device: &DeviceKey, frame: RelayFrame) {
        self.state.lock().unwrap().send(device, frame);
    }

    pub fn handle(&self, me: &DeviceKey, frame: ClientFrame) {
        let now = now_ms();
        let mut guard = self.state.lock().unwrap();
        let s = &mut *guard;
        match frame {
            ClientFrame::Auth { .. } => s.send(me, error("already logged in")),

            ClientFrame::PublishPrekeys { cert, spk, new_opks } => {
                // Only accept keys that are really signed by this device.
                if cert.device != *me || cert.verify().is_err() || spk.verify(me).is_err() {
                    return s.send(me, error("prekeys not signed by this device"));
                }
                let entry = s.prekeys.entry(*me).or_insert_with(|| Prekeys {
                    cert: cert.clone(),
                    spk: spk.clone(),
                    opks: VecDeque::new(),
                });
                entry.cert = cert;
                entry.spk = spk;
                entry.opks.extend(new_opks);
                while entry.opks.len() > MAX_OPKS {
                    entry.opks.pop_front();
                }
            }

            ClientFrame::FetchPrekeys { device } => {
                let (bundle, low) = match s.prekeys.get_mut(&device) {
                    Some(p) => {
                        let opk = p.opks.pop_front(); // each one-time key goes out once
                        let low = (p.opks.len() < OPKS_LOW).then_some(p.opks.len());
                        (Some(PreKeyBundle { cert: p.cert.clone(), spk: p.spk.clone(), opk }), low)
                    }
                    None => (None, None),
                };
                s.send(me, RelayFrame::Prekeys { device, bundle });
                if let Some(remaining) = low {
                    s.send(&device, RelayFrame::PrekeysLow { remaining });
                }
            }

            ClientFrame::SendDm { to, payload, expires_at } => {
                if payload.len() > MAX_PAYLOAD {
                    return s.send(me, error("payload too large"));
                }
                let mailbox = s.mailboxes.entry(to).or_default();
                if mailbox.len() >= MAX_MAILBOX {
                    return s.send(me, error("recipient's mailbox is full"));
                }
                s.next_dm += 1;
                let id = s.next_dm;
                let delete_at = self.delete_at(now, expires_at);
                let dm = StoredDm { from: *me, payload, sent_at: now, delete_at };
                s.send(&to, RelayFrame::Dm { id, from: *me, payload: dm.payload.clone(), sent_at: now });
                s.mailboxes.entry(to).or_default().insert(id, dm);
            }

            ClientFrame::AckDm { id } => {
                if let Some(m) = s.mailboxes.get_mut(me) {
                    m.remove(&id);
                }
            }

            ClientFrame::Subscribe { community, since } => {
                let Some(conn) = s.conns.get_mut(me) else { return };
                conn.subscriptions.insert(community);
                let log = s.logs.entry(community).or_default();
                log.subscribers.insert(*me);
                let head = log.next_seq;
                let backlog: Vec<RelayFrame> = log
                    .entries
                    .iter()
                    .filter(|e| e.seq > since && e.delete_at > now)
                    .map(|e| RelayFrame::Community {
                        community,
                        seq: e.seq,
                        from: e.from,
                        payload: e.payload.clone(),
                        sent_at: e.sent_at,
                    })
                    .collect();
                for f in backlog {
                    s.send(me, f);
                }
                s.send(me, RelayFrame::Synced { community, head });
            }

            ClientFrame::Unsubscribe { community } => {
                if let Some(c) = s.conns.get_mut(me) {
                    c.subscriptions.remove(&community);
                }
                if let Some(log) = s.logs.get_mut(&community) {
                    log.subscribers.remove(me);
                }
            }

            ClientFrame::SendCommunity { community, payload, expires_at } => {
                if payload.len() > MAX_PAYLOAD {
                    return s.send(me, error("payload too large"));
                }
                // The relay can't tell members from strangers (it never sees
                // the member list), so it only requires a subscription.
                // Clients drop messages from non-members.
                let delete_at = self.delete_at(now, expires_at);
                let Some(log) = s.logs.get_mut(&community).filter(|l| l.subscribers.contains(me))
                else {
                    return s.send(me, error("subscribe before sending"));
                };
                log.next_seq += 1;
                let seq = log.next_seq;
                let frame = RelayFrame::Community {
                    community,
                    seq,
                    from: *me,
                    payload: payload.clone(),
                    sent_at: now,
                };
                log.entries.push_back(Entry { seq, from: *me, payload, sent_at: now, delete_at });
                if log.entries.len() > MAX_LOG {
                    log.entries.pop_front();
                }
                let subscribers: Vec<DeviceKey> = log.subscribers.iter().copied().collect();
                for d in subscribers {
                    s.send(&d, frame.clone());
                }
            }
        }
    }

    /// Deletes expired DMs and community messages.
    pub fn purge_expired(&self) {
        let now = now_ms();
        let mut s = self.state.lock().unwrap();
        for m in s.mailboxes.values_mut() {
            m.retain(|_, d| d.delete_at > now);
        }
        s.mailboxes.retain(|_, m| !m.is_empty());
        for log in s.logs.values_mut() {
            log.entries.retain(|e| e.delete_at > now);
        }
    }
}
