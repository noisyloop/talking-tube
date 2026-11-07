# Architecture

Discord-style communities, end-to-end encrypted. No email, no phone number,
no username or password.
A user is an Ed25519 device key. Anyone can run a relay.

```
 client (tt) ──WebSocket── relay (tt-relay)
   │                         │
   ├ tt-crypto  (decrypt)    ├ routes + stores ciphertext
   ├ tt-plugin  (bots, /cmd) ├ prekey store, offline mailbox
   └ tt-proto   (frames)     └ orders MLS commits per community
```

## Crates

| Crate | Purpose |
|---|---|
| `tt-core` | IDs, communities, channels, members, roles |
| `tt-crypto` | `DmSession` (Signal protocol), `GroupCipher` (sender keys / MLS) |
| `tt-proto` | `ClientFrame` / `RelayFrame` wire types |
| `tt-plugin` | `Plugin` trait + `Registry` (slash commands, message hooks) |
| `tt-relay` | Self-hostable server |
| `tt-client` | `tt` CLI, later TUI (ratatui, as in Shadow) or GUI |
| `plugins/echo` | Example plugin |

## Identity without logins

Rule: neither the client nor the relay ever asks for an email address or phone
number, not even optionally or for recovery. A relay that wants spam control
uses invites, rate limits or proof-of-work instead.

1. `tt init` makes a device key.
2. On connect the relay sends a random nonce; the client signs it.
3. Joining a community is by invite (community ID + relay URL + inviter key),
   shared as a link or QR code.
4. Verify people by comparing safety numbers / QR codes, as in Shadow.
5. Account recovery means backing up your device key (e.g. an encrypted export
   or a passphrase), never an email reset. Lose the key and the identity is gone.

## Plugins

Plugins run in the client after decryption, so encryption never has to be
weakened for bots. A bot is a device key running `tt` headless with plugins.
They are compiled-in Rust crates for now; a WASM host can implement the same
trait later so untrusted plugins run sandboxed.

## Roadmap

1. Port Shadow's crypto into `tt-crypto` with its tests.
2. Relay: auth, prekeys, DM routing.
3. Communities + text channels with sender keys.
4. TUI.
5. PQXDH, sealed sender, MLS, WASM plugins.
6. Voice (later; e.g. WebRTC with SFrame).
