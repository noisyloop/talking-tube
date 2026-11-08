# Talking Tube lab

Hands-on exercises for learning Rust and end-to-end encryption with this
codebase. Each lab says what to run, what to look for, and why it matters.
Work through them in order; later labs assume earlier ones.

Research code only. Nothing here has been audited.

Everything runs on your own machine. Nothing here needs a CI service.

## Setup

```sh
cargo build                     # binaries land in target/debug/
cargo test --workspace          # should end with 0 failed
```

Handy: `cargo test -p <crate> <name>` runs only tests whose name contains
`<name>`, and `-- --nocapture` shows `println!` output.

Keep a notebook. For each lab write down: **what I expected → what happened
→ why**. The "why" is where the learning is.

---

## Part 1: The building blocks

### Lab 1: Read the primitives

Open `crates/tt-crypto/src/keys.rs`. Every function is a few lines wrapping
a crate.

- What does `dh` refuse, and why? (Look up "X25519 low-order points".)
- `aead_encrypt` uses a random nonce. Why is that safe here, when it's risky
  in general? (Hint: how many messages does each key encrypt?)
- `kdf_ck` returns two keys from one. Which one is kept, and which is used once?

### Lab 2: Padding and what size leaks

```sh
cargo test -p tt-crypto padding -- --nocapture
```

Change `BLOCK` in `padding.rs` to `16`, then `1024`, and re-run. Then answer:
what can someone watching the relay learn from a 256-byte vs a 768-byte
message? What does padding cost?

---

## Part 2: The Signal protocol (DMs)

### Lab 3: X3DH by hand

Read `crates/tt-crypto/src/x3dh.rs`, then run:

```sh
cargo test -p tt-crypto x3dh
```

- Draw the four DH operations: which key of Alice's meets which key of Bob's?
- Which DH proves Alice's identity? Which proves Bob's? Which gives forward secrecy?
- Why can Bob be offline when Alice starts the conversation?

### Lab 4: Watch the ratchet turn

Add this test to the bottom of the `tests` module in `ratchet.rs`:

```rust
#[test]
fn watch_it_turn() {
    let (mut a, mut b) = pair();
    for i in 0..3 {
        let (h, c) = a.encrypt(b"hi", b"").unwrap();
        println!("alice→bob #{i}: ratchet key {} n={}", &hex(&h.dh)[..8], h.n);
        b.decrypt(&h, &c, b"").unwrap();
    }
    let (h, c) = b.encrypt(b"yo", b"").unwrap();
    println!("bob→alice:     ratchet key {} n={}", &hex(&h.dh)[..8], h.n);
    a.decrypt(&h, &c, b"").unwrap();
    let (h, _) = a.encrypt(b"again", b"").unwrap();
    println!("alice→bob:     ratchet key {} n={}", &hex(&h.dh)[..8], h.n);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
```

```sh
cargo test -p tt-crypto watch_it_turn -- --nocapture
```

What changes when only Alice talks? What changes when Bob replies? Map that
onto "symmetric ratchet" vs "DH ratchet", and onto "forward secrecy" vs
"break-in recovery".

### Lab 5: Break it on purpose (ratchet)

In `RatchetState::decrypt`, move `*self = next;` to **before** the
`aead_decrypt` line. Run:

```sh
cargo test -p tt-crypto forged_message
```

It fails. Explain in one sentence what an attacker can now do with a single
fake message. (This was a real bug in the original Shadow port.) Put the
line back and confirm the test passes.

### Lab 6: Break it on purpose (handshake)

In `x3dh::initiate`, comment out `bundle.verify()?;` and run:

```sh
cargo test -p tt-crypto tampered_bundle
```

Who could exploit this: another user, the relay, or both? What would they
learn? Restore the line.

### Lab 7: Out of order, replays, wrong context

```sh
cargo test -p tt-crypto ratchet
```

Read `out_of_order_across_ratchet_steps`, `replay_is_rejected` and
`wrong_associated_data_fails`. For each, find the exact lines in
`ratchet.rs` that make it pass. What is `MAX_SKIP` protecting against?

---

## Part 3: Group encryption (channels)

### Lab 8: Sender keys

```sh
cargo test -p tt-crypto sender_keys
```

Read `sender_keys.rs` top to bottom.

- Every member knows every other member's chain key. So why can't Bob post
  a message that looks like it's from Alice?
- Find the test that proves it, comment out the `keys::verify(...)` line in
  `PeerSenderKey::decrypt`, and watch `members_cannot_forge_each_other` fail.
  Restore it.
- `late_joiner_cannot_read_the_past`: why does that work without any extra code?

### Lab 9: Rotation after a kick

In `OwnSenderKey::rotate`, replace the body with
`Self { generation: self.generation, ..self.clone() }` (so "rotating" keeps the
old key). Run `cargo test -p tt-crypto rotation_locks` and see it fail.
Restore it.

Then read `Effect::MemberRemoved` handling in
`crates/tt-client/src/engine.rs` (`on_effect` and `rotate_my_key`).
Answer: if a community has *n* members and one is kicked, how many DMs get
sent in total? Why is that the main reason MLS exists?

---

## Part 4: Communities without a server

### Lab 10: Permissions as a state machine

```sh
cargo test -p tt-core community
```

`CommunityState::apply` is plain Rust with no crypto and no I/O. Add a rule,
for example "moderators can't kick other moderators", and write the test
first. Note how `failed_op_leaves_state_unchanged` keeps you honest.

### Lab 11: Why order matters

Read the top of `engine.rs` ("How a community message flows").
Thought experiment: Alice makes Bob an admin while, at the same moment, Bob
creates a channel. If two members applied those ops in different orders,
what would differ? How does the relay's sequence number prevent it? What
could a *malicious* relay do with that power? (It can reorder or drop, but
not forge. Why not?)

### Lab 12: Disappearing messages

```sh
cargo test -p tt-core timer_caps_sender_expiry
```

Then try it live (Part 5) with `/timer 10s` in a channel. Answer: what does
disappearing protect against, and what doesn't it? (Screenshots? A modified
client? The relay's disk? A phone stolen next week?)

---

## Part 5: Run it for real

### Lab 13: Three people, one relay

Use three terminals, plus one for the relay:

```sh
./target/debug/tt-relay
```

```sh
./target/debug/tt --home /tmp/lab/alice init --name alice
./target/debug/tt --home /tmp/lab/alice run
/create Lab
/invite
```

```sh
./target/debug/tt --home /tmp/lab/bob init --name bob
./target/debug/tt --home /tmp/lab/bob run
/join tt1.…
```

Do the same for carol. Then try: `/newchannel secrets`, `/ch secrets`,
`/timer 10s`, post something and watch it vanish; `/role bob moderator`;
`/kick carol`; `/dm bob hi`; `/roll 3d6`; `/safety bob`.

### Lab 14: What the relay sees

The relay only logs logins. Add a log line in
`crates/tt-relay/src/state.rs`, inside `ClientFrame::SendCommunity`:

```rust
tracing::info!(community = %community.short(), from = %me.short(), bytes = payload.len(), "community post");
```

Rebuild, re-run Lab 13, and watch the relay terminal. List everything the
relay learns. Compare your list with "What the relay sees" in
`docs/ENCRYPTION.md`. Did we miss anything?

### Lab 15: Look inside your own store

```sh
less /tmp/lab/alice/store.json        # or: jq . /tmp/lab/alice/store.json
```

Find: your private keys, the one-time prekeys (how many are left?), a
session's ratchet state, the sender keys for each community member. Now
explain why "the store isn't encrypted" is listed as a known gap, and what
an attacker with this file could and couldn't read.

### Lab 16: Offline delivery

Quit bob (`/quit`). Have alice `/dm bob are you there`. Start bob again.
Read `offline_delivery` in `crates/tt-client/tests/e2e.rs`: it does the same
thing automatically. Why could alice start an encrypted session with bob
while he was offline? (Back to Lab 3.)

---

## Part 6: Build things

### Lab 17: Write a plugin

Copy `plugins/echo` to `plugins/eightball`. Rename the crate in its
`Cargo.toml`, add it to the workspace `members` and to `tt-client`'s
dependencies, and register it in `Engine::new`. Make `/8ball <question>`
reply with a random answer (look at how `plugins/dice` gets randomness).
Then run a second identity with `tt run --bot` and ask it questions from the first.

### Lab 18: Attack your own client

Read `docs/SECURITY.md`. For findings 1, 2 and 5, undo the fix (for example,
make `tt_core::text::check` always return `Ok(())`), run the named test, and
watch it fail. Then pick an open finding (3, 4 or 6), write a failing test
that shows the attack, and fix it.

### Lab 19: Pick a real feature

Each of these is a good multi-evening project. Write tests first.

1. **Signed prekey rotation.** Make a new SPK every week and keep the old
   one for a while. Where must `on_dm` look?
2. **Zeroize secrets** with the `zeroize` crate. Which structs hold secrets?
3. **Sealed sender** for DMs. Port the idea from Shadow's
   `transport/sealed_sender.py`. What does the relay stop learning?
4. **PQXDH.** Add an ML-KEM prekey to the bundle and mix its shared secret
   into `x3dh::kdf`. Read Signal's PQXDH spec first.
5. **State resync.** Let a member who missed ops ask an admin for a fresh
   `CommunityState`. How do you stop a malicious admin lying about it?

---

## Answer hints

Try first, then peek.

<details><summary>Lab 1</summary>
All-zero output means the peer sent a low-order point and the "shared"
secret is predictable. Random nonces are only dangerous when one key
encrypts many messages; here each key encrypts exactly one.
</details>

<details><summary>Lab 4</summary>
While only Alice talks, the ratchet key stays the same and <code>n</code>
counts up (symmetric ratchet: forward secrecy). When Bob replies, he
uses a new ratchet key, and so does Alice after that (DH ratchet: break-in recovery).
</details>

<details><summary>Lab 5</summary>
A fake message with a far-ahead counter or a new ratchet key would advance
Bob's state, and he could no longer decrypt Alice's real messages: a
one-packet denial of service.
</details>

<details><summary>Lab 6</summary>
Mainly the relay: it hands out the bundles, so it could swap in its own
prekey and read the first messages (a man-in-the-middle attack). Safety
numbers are the backstop.
</details>

<details><summary>Lab 8</summary>
Messages are signed with a per-sender Ed25519 key that only the sender
holds. Late joiners get the chain at its <em>current</em> position, and a
hash chain can't be run backwards.
</details>

<details><summary>Lab 9</summary>
Each of the n−1 remaining members sends a new key to n−2 others:
(n−1)(n−2) DMs, so O(n²). MLS rekeys in O(log n).
</details>

<details><summary>Lab 11</summary>
If Bob's channel op came first, it's rejected (he isn't an admin yet).
If it came second, it's accepted. Different orders would give different
communities. A malicious relay can reorder or drop messages, but it can't
forge them: they're signed by sender keys it doesn't have.
</details>
