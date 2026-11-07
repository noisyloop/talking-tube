# Encryption

## Can we use Signal's encryption?

**Yes, the protocol. Not the library.**

### The Signal *protocol*: yes, and that's what this does

Signal publishes its specifications openly (X3DH, PQXDH, Double Ratchet,
Sesame, XEdDSA), and anyone may implement them. Shadow already did this in
Rust; Talking Tube ports that code into `tt-crypto` for DMs.

### `libsignal` (Signal's own Rust code): not used

* **License.** It's AGPL-3.0. Talking Tube is MIT. Linking it would make the
  whole program AGPL.
* **Not a public library.** It isn't on crates.io, Signal says it doesn't
  support outside use, and the API changes without notice.
* **Tied to Signal's service**: phone-number accounts, Signal's servers,
  their sealed-sender certificates.

### Other options

| Option | What it gives | License | Notes |
|---|---|---|---|
| **Shadow's code, ported** (used) | X3DH + Double Ratchet | MIT (yours) | Readable; not audited |
| `vodozemac` (Matrix) | Olm (Double Ratchet) + Megolm (sender keys) | Apache-2.0 | Audited; not Signal-wire-compatible |
| `openmls` | MLS (RFC 9420) | MIT | For big channels later |

## What's implemented

| Piece | Where | Notes |
|---|---|---|
| Identity | `identity.rs` | Ed25519 identity, X25519 DH key signed by it |
| X3DH | `x3dh.rs` | 3 or 4 DHs, HKDF; AD binds both identities |
| Double Ratchet | `ratchet.rs` | Out-of-order delivery, skipped-key cap |
| DM sessions | `session.rs` | Prekey messages until the first reply; several sessions per peer to survive both sides starting at once |
| Sender keys | `sender_keys.rs` | Per-sender chain + Ed25519 signature, generations |
| Padding | `padding.rs` | Plaintext padded to 256-byte blocks |
| Safety numbers | `safety.rs` | 60 digits from SHA-512 of both keys |

Primitives: X25519, Ed25519 (strict verification), HKDF-SHA256,
HMAC-SHA256, AES-256-GCM.

### Fixes over Shadow's version

* **Transactional decrypt.** Shadow's ratchet advanced its state before
  checking the AEAD tag, so one forged message could knock a session out of
  sync. Now decryption works on a copy and only saves it on success. Tested
  in `forged_message_does_not_break_the_session`.
* **Identity binding.** Shadow published the X25519 identity key unsigned.
  Now it's signed by the Ed25519 key (`IdentityCert`), and the relay and
  peers check that.
* **Session AD.** Every DM authenticates both identities as associated data.
* **One-time prekeys** are deleted only after the first message authenticates.
* **Low-order points** are rejected (`was_contributory`).
* **KDF_CK constants** match the spec (message key 0x01, chain key 0x02).

## Groups: sender keys

Each member has one sender key per community. On join it goes to everyone
over DMs; on leave/kick/ban **everyone** makes a new generation and sends it
to the remaining members. Each message is encrypted once and signed with
the sender's per-key Ed25519 key, so members can't forge each other (they
all know each other's chain keys; only the sender has the signing key).

Trade-offs, compared with the pairwise ratchet:
* No break-in recovery: a stolen chain key reads that sender's later
  messages until the next rotation.
* Rotation on every removal costs one DM per member per member: O(n²).
* MLS fixes both. The relay's per-community ordering is what MLS needs, so
  it can be added as another backend.

## What the relay sees

It can't read anything, but it sees metadata:
* device keys, IP addresses, when each device is online,
* who DMs whom, and when,
* which devices subscribe to which community ID, and who posts there when,
* padded sizes and each payload's deletion time.

It doesn't see message text, names, channel IDs, member lists or roles.

## Not done yet

* **PQXDH**, post-quantum X3DH (adds an ML-KEM prekey), as current Signal uses.
  Signal's post-quantum ratchet (SPQR) after that.
* **Sealed sender** for DMs, so the relay doesn't learn the sender (Shadow has it).
* **Header encryption** in the Double Ratchet.
* **Signed prekey rotation.** One signed prekey is used forever right now.
* **Zeroizing** secret keys in memory, and an encrypted store on disk.
* An **audit**. None of this has been reviewed by anyone else.
