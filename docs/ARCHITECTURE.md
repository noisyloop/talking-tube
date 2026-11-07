# Architecture

Discord-style communities, end-to-end encrypted. No email, no phone number,
no username or password. A user is an Ed25519 device key. Anyone can run a relay.

```
 tt (client)                                tt-relay
 ┌──────────────────────────┐   WebSocket   ┌─────────────────────────────┐
 │ commands  → Engine       │ ────JSON────▶ │ login by signed challenge   │
 │   tt-crypto (sessions,   │               │ prekey bundles              │
 │     sender keys)         │ ◀──────────── │ DM mailboxes                │
 │   tt-core (state, rules) │               │ per-community ordered log   │
 │   tt-plugin (bots, /cmd) │               │ deletes expired ciphertext  │
 └──────────────────────────┘               └─────────────────────────────┘
```

## Crates

| Crate | Purpose |
|---|---|
| `tt-core` | IDs, community state + permission rules, message history + disappearing logic. No crypto, no I/O. |
| `tt-crypto` | X3DH, Double Ratchet, DM sessions, sender keys, padding, safety numbers |
| `tt-proto` | Relay frames (`ClientFrame`/`RelayFrame`), encrypted payloads (`DmPayload`), invite links |
| `tt-plugin` | `Plugin` trait + `Registry` |
| `tt-relay` | The server (library + `tt-relay` binary) |
| `tt-client` | `Engine` (all client logic, no I/O), `net` (WebSocket loop), `tt` binary |
| `plugins/echo`, `plugins/dice` | Example plugins |

## Rules

* Neither the client nor the relay ever asks for an email address or phone
  number, not even optionally or for recovery.
* Recovery means backing up `store.json`. There's no reset. Lose the key and
  the identity is gone.
* The relay never sees plaintext, names, channel IDs or member lists.

## Identity and login

1. `tt init` makes an Ed25519 key (the identity) and an X25519 key (for X3DH),
   with a certificate signing the second with the first.
2. On connect the relay sends a random nonce; the client signs it.
3. The client uploads its signed prekey and a batch of one-time prekeys.

## Communities

There is no server-side community. Every member holds a copy of the
`CommunityState` (name, channels, members, roles, bans, timers) and changes it
by applying `Op`s. Ops travel encrypted, like chat messages.

The relay gives each community message a sequence number. Every client
processes the stream **strictly in that order** and applies each op with the
same rules (`CommunityState::apply`), so every copy ends up the same. A
client's own messages come back from the relay too, and are applied then,
not when sent.

### Roles

`owner > admin > moderator > member`. You can only manage people below you
and only grant roles below yours.

| Action | Needs |
|---|---|
| post, react, edit/delete own | member |
| invite | `invite_role` (member by default) |
| topic, kick, delete others' messages, pin | moderator |
| channels, timers, rename, ban, invite role | admin |
| transfer ownership | owner |

### Joining

1. A member makes an invite: relay URL + community ID + their key + a random token.
2. The joiner DMs a `JoinRequest` to the inviter. The inviter must be online.
3. The inviter checks the token and posts `AddMember`.
4. When that op comes back from the relay at sequence `S`, the inviter DMs the
   joiner a `Welcome` with the state as of `S`. The joiner reads from `S + 1`.
5. Everyone, the joiner included, sends their sender key to everyone else.
   Until a sender's key arrives, the stream waits (up to 15 s).

## Disappearing messages

* Channels: `/timer 1h` (admins) sets `disappearing_secs` on a channel via an op.
* DMs: either person runs `/timer 1h`.
* A message disappears at the earlier of its own `expires_at` and
  `received_at + timer`. Clients purge every second. The relay is told the
  deadline and deletes the ciphertext then, delivered or not.
* What it doesn't do: stop screenshots, or stop a modified client keeping
  messages. Disappearing messages protect against later compromise, not
  against the people you sent them to.

## Plugins

Plugins run in the client after decryption, so encryption never has to be
weakened for bots. See `crates/tt-plugin/src/lib.rs` and `plugins/dice`.
To add one: make a crate implementing `Plugin`, register it in
`Engine::new`. A WASM host could load untrusted plugins later.

## Known gaps

* The inviter has to be online to let someone in.
* The client store is plain JSON (owner-only permissions), not encrypted.
* A member who's offline longer than relay retention (7 days by default)
  misses ops, and their copy of the state drifts. There's no resync yet.
* One device per identity. No multi-device.
* No TLS in the binaries; put the relay behind a TLS proxy for `wss://`.
* The relay is in-memory and has no rate limiting.
* No voice.

## Roadmap ideas

1. PQXDH (post-quantum X3DH), then Signal's post-quantum ratchet.
2. Sealed sender for DMs (port from Shadow).
3. MLS (`openmls`) for big channels: the relay's ordering is exactly what MLS needs.
4. State resync and offline joins (an admin-signed snapshot left on the relay).
5. Encrypted store, multi-device, a TUI (ratatui, as in Shadow), WASM plugins, voice.
