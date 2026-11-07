# Encryption

## Can we use Signal's encryption?

**Yes, the protocol. Probably not the library.**

### The Signal *protocol*: yes

Signal publishes its specifications openly (X3DH, PQXDH, Double Ratchet,
Sesame, XEdDSA), and anyone may implement them. Shadow already does this in
Rust (`cli/src/crypto`: X3DH + Double Ratchet over X25519, HKDF-SHA256,
AES-256-GCM, HMAC-SHA256, Ed25519). Talking Tube reuses that work for DMs.

### `libsignal` (Signal's own Rust code): not a good fit

* **License.** It is AGPL-3.0. Talking Tube is MIT. Linking it would make the
  whole combined program AGPL, including any self-hosted relay changes people
  make. That defeats the point of an MIT project.
* **Not a public library.** It isn't published on crates.io (git dependency
  only), and Signal says it doesn't support use outside its own apps. The API
  changes without notice.
* **It's tied to Signal's service.** Much of it is built around Signal's
  servers, phone-number accounts and its sealed-sender certificates.

If you ever relicense to AGPL, it becomes an option for DMs only.

### Other options

| Option | What it gives | License | Notes |
|---|---|---|---|
| **Port Shadow's code** (chosen) | X3DH + Double Ratchet | MIT (yours) | Already written and tested; not externally audited |
| `vodozemac` (Matrix) | Olm (Double Ratchet) + Megolm (sender keys) | Apache-2.0 | Audited; Olm is a Double Ratchet variant, not Signal-wire-compatible |
| `openmls` | MLS (RFC 9420) | MIT | For big channels later |

## The plan

1. **DMs: Signal protocol.** Port Shadow's X3DH + Double Ratchet into
   `tt-crypto::dm`. Then upgrade X3DH to **PQXDH** (adds an ML-KEM prekey),
   which is what Signal uses now. Signal has since also added a post-quantum
   ratchet (SPQR); that can come later.
2. **Channels, step 1: sender keys.** Same idea as Signal groups and Megolm.
   Each member's sender key is delivered over the pairwise DM sessions, so it
   builds on step 1. One encryption per message.
3. **Channels, step 2: MLS** via `openmls`, behind the `mls` feature. MLS
   needs one agreed order of changes; each community lives on one relay, and
   that relay orders the commits (it sees order, not content).

The client and relay only use the `DmSession` and `GroupCipher` traits, so
step 3 doesn't touch anything outside `tt-crypto`.

## What the relay can still see

The relay can't read messages, but it sees metadata: which device keys are
in which community, when they post, message sizes, and IP addresses.
Shadow's sealed sender hides the sender of DMs and should be ported too. Hiding
channel membership from the relay is an open problem; note it in the threat
model rather than claiming it.
