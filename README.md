# talking-tube
Talking tube is a replacement for Discord in Rust, with more encryption.

**Research project. Not audited. Don't protect anything real with it.**

* Communities with channels, roles, invites, kicks and bans, like Discord, but
  no email, phone or login. Your identity is a key made on your device.
* DMs use the Signal protocol (X3DH + Double Ratchet), ported from
  [Shadow](https://github.com/noisyloop/Shadow) and hardened.
* Channels use sender keys (like Signal groups). Keys rotate when someone leaves or is removed.
* Disappearing messages per channel and per DM. The relay deletes the
  ciphertext at the same moment the clients delete the message.
* Edits, deletes, replies, reactions, pins.
* Plugins and bots run on the client, after decryption (`/roll`, `/echo`, …).
* Anyone can run a relay. Relays only ever see ciphertext.

## Try it

```sh
cargo build --release

# terminal 1: a relay
./target/release/tt-relay

# terminal 2: alice
./target/release/tt --home /tmp/alice init --name alice
./target/release/tt --home /tmp/alice run
> /create Night Owls
> /invite                 # prints a tt1.… link

# terminal 3: bob
./target/release/tt --home /tmp/bob init --name bob
./target/release/tt --home /tmp/bob run
> /join tt1.…             # alice must be online to let bob in
> hello!
> /roll 2d6
```

Clients must dial the relay at the URL it reports (`ws://127.0.0.1:7070` by
default; `localhost` is refused). Behind a proxy, start it with
`tt-relay --public-url wss://your.host`.

Type `/help` for every command. Use `tt run --bot` to make a device answer
other people's plugin commands.

## Tests

```sh
cargo test --workspace
```

`crates/tt-client/tests/e2e.rs` starts a real relay and three clients over
WebSocket: joining, key distribution, disappearing channels, a kick with key
rotation, plugins, DMs, edits, reactions and offline delivery.

## Reading order (for learning)

1. `crates/tt-crypto/src/keys.rs`: the primitives, each a few lines.
2. `x3dh.rs` → `ratchet.rs` → `session.rs`: the Signal protocol.
3. `sender_keys.rs`: group encryption, and why it needs a signature.
4. `crates/tt-core/src/community.rs`: roles and permissions as a pure state machine.
5. `crates/tt-client/src/engine.rs`: how it all fits together.
6. `crates/tt-relay/src/state.rs`: what a server needs to know (very little).
7. `plugins/dice`: write your own plugin.

## Docs

* [Architecture](docs/ARCHITECTURE.md)
* [Encryption, and whether we can use Signal's](docs/ENCRYPTION.md)
* [Lab: hands-on exercises](lab.md)
* [Security review](docs/SECURITY.md)
