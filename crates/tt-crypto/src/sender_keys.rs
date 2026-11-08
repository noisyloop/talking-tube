//! Sender keys: the group scheme used by Signal groups and Matrix (Megolm).
//!
//! Each member makes an [`OwnSenderKey`] for each community: a hash chain
//! plus an Ed25519 signing key. They send the public part
//! ([`SenderKeyDistribution`]) to every other member over the pairwise DM
//! sessions. To post, a member steps their chain once and encrypts the
//! message once; everybody who has the distribution can decrypt it.
//!
//! * **Forward secrecy:** chains only go forward, so someone who gets a key
//!   later can't read earlier messages.
//! * **Authenticity:** every member knows everyone's chain keys, so the chain
//!   alone can't prove who wrote a message. The per-sender signing key can:
//!   only the sender has its private half.
//! * **No break-in recovery:** if a chain key leaks, every later message on
//!   that chain is readable until it's replaced. That's why the client makes
//!   a new key (a new *generation*) whenever someone leaves or is removed.

use serde::{Deserialize, Serialize};
use tt_core::encoding::{b64, hex32};

use crate::keys::{self, Key32};
use crate::ratchet::MAX_SKIP;
use crate::CryptoError;

const SIG_LABEL: &[u8] = b"tt-sender-key-msg-v1";
const MAX_STORED_SKIPPED: usize = 2000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    pub generation: u32,
    pub iteration: u32,
    #[serde(with = "hex32")]
    pub chain_key: Key32,
    #[serde(with = "hex32")]
    pub signing_pub: Key32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SenderKeyMessage {
    pub generation: u32,
    pub iteration: u32,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl SenderKeyMessage {
    fn signed_bytes(&self, ad: &[u8]) -> Vec<u8> {
        [
            SIG_LABEL,
            &(ad.len() as u32).to_be_bytes(),
            ad,
            &self.generation.to_be_bytes(),
            &self.iteration.to_be_bytes(),
            &self.ciphertext,
        ]
        .concat()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OwnSenderKey {
    pub generation: u32,
    iteration: u32,
    chain_key: Key32,
    signing_priv: Key32,
}

impl OwnSenderKey {
    pub fn generate(generation: u32) -> Self {
        Self {
            generation,
            iteration: 0,
            chain_key: keys::random_bytes(),
            signing_priv: keys::generate_signing(),
        }
    }

    /// A brand-new key with the next generation number.
    pub fn rotate(&self) -> Self {
        Self::generate(self.generation + 1)
    }

    /// What to send to other members. Starts at our *current* position, so
    /// they can't read anything we sent before.
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            generation: self.generation,
            iteration: self.iteration,
            chain_key: self.chain_key,
            signing_pub: keys::ed25519_public(&self.signing_priv),
        }
    }

    /// `ad` should bind the message to its community and sender.
    pub fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> SenderKeyMessage {
        let (next_ck, mk) = keys::kdf_ck(&self.chain_key);
        let mut msg = SenderKeyMessage {
            generation: self.generation,
            iteration: self.iteration,
            ciphertext: keys::aead_encrypt(&mk, plaintext, ad),
            signature: Vec::new(),
        };
        msg.signature = keys::sign(&self.signing_priv, &msg.signed_bytes(ad));
        self.chain_key = next_ck;
        // A chain has 2^32 messages; after that the client must rotate.
        self.iteration = self.iteration.saturating_add(1);
        msg
    }
}

/// Our copy of someone else's sender key (or our own, so we can read our posts).
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerSenderKey {
    pub generation: u32,
    iteration: u32,
    chain_key: Key32,
    signing_pub: Key32,
    skipped: Vec<(u32, Key32)>,
}

impl PeerSenderKey {
    pub fn from_distribution(d: &SenderKeyDistribution) -> Self {
        Self {
            generation: d.generation,
            iteration: d.iteration,
            chain_key: d.chain_key,
            signing_pub: d.signing_pub,
            skipped: Vec::new(),
        }
    }

    pub fn decrypt(&mut self, ad: &[u8], msg: &SenderKeyMessage) -> Result<Vec<u8>, CryptoError> {
        if msg.generation != self.generation {
            return Err(CryptoError::UnknownGeneration);
        }
        // Check the signature first: it doesn't need the chain, and a forged
        // message must not make us step the chain.
        keys::verify(&self.signing_pub, &msg.signed_bytes(ad), &msg.signature)?;

        if msg.iteration < self.iteration {
            let i = self
                .skipped
                .iter()
                .position(|(n, _)| *n == msg.iteration)
                .ok_or(CryptoError::OldMessage)?;
            let pt = keys::aead_decrypt(&self.skipped[i].1, &msg.ciphertext, ad)?;
            self.skipped.remove(i);
            return Ok(pt);
        }
        if msg.iteration - self.iteration > MAX_SKIP {
            return Err(CryptoError::TooManySkipped);
        }
        // The sender chooses both iterations; the last one can't be stepped past.
        let next_iteration = msg.iteration.checked_add(1).ok_or(CryptoError::TooManySkipped)?;

        let mut ck = self.chain_key;
        let mut skipped = Vec::new();
        for n in self.iteration..msg.iteration {
            let (next, mk) = keys::kdf_ck(&ck);
            skipped.push((n, mk));
            ck = next;
        }
        let (next, mk) = keys::kdf_ck(&ck);
        let pt = keys::aead_decrypt(&mk, &msg.ciphertext, ad)?;

        self.chain_key = next;
        self.iteration = next_iteration;
        self.skipped.extend(skipped);
        if self.skipped.len() > MAX_STORED_SKIPPED {
            let excess = self.skipped.len() - MAX_STORED_SKIPPED;
            self.skipped.drain(..excess);
        }
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_sender_many_readers() {
        let mut own = OwnSenderKey::generate(0);
        let mut bob = PeerSenderKey::from_distribution(&own.distribution());
        let mut carol = PeerSenderKey::from_distribution(&own.distribution());
        let m = own.encrypt(b"club", b"hello all");
        assert_eq!(bob.decrypt(b"club", &m).unwrap(), b"hello all");
        assert_eq!(carol.decrypt(b"club", &m).unwrap(), b"hello all");
    }

    #[test]
    fn out_of_order_and_no_replay() {
        let mut own = OwnSenderKey::generate(0);
        let mut peer = PeerSenderKey::from_distribution(&own.distribution());
        let m0 = own.encrypt(b"", b"0");
        let m1 = own.encrypt(b"", b"1");
        assert_eq!(peer.decrypt(b"", &m1).unwrap(), b"1");
        assert_eq!(peer.decrypt(b"", &m0).unwrap(), b"0");
        assert_eq!(peer.decrypt(b"", &m0), Err(CryptoError::OldMessage));
    }

    #[test]
    fn late_joiner_cannot_read_the_past() {
        let mut own = OwnSenderKey::generate(0);
        let before = own.encrypt(b"", b"before you joined");
        let mut late = PeerSenderKey::from_distribution(&own.distribution());
        assert_eq!(late.decrypt(b"", &before), Err(CryptoError::OldMessage));
        let after = own.encrypt(b"", b"welcome");
        assert_eq!(late.decrypt(b"", &after).unwrap(), b"welcome");
    }

    #[test]
    fn members_cannot_forge_each_other() {
        let alice = OwnSenderKey::generate(0);
        let mut bob_copy_of_alice = PeerSenderKey::from_distribution(&alice.distribution());
        // Mallory knows Alice's chain key (every member does) but not her signing key.
        let mut mallory = alice.clone();
        mallory.signing_priv = keys::generate_signing();
        let forged = mallory.encrypt(b"", b"alice says hi");
        assert_eq!(bob_copy_of_alice.decrypt(b"", &forged), Err(CryptoError::BadSignature));
    }

    #[test]
    fn hostile_iteration_does_not_overflow() {
        // A malicious member distributes a chain that starts at the very end.
        let mut own = OwnSenderKey::generate(0);
        own.iteration = u32::MAX;
        let mut peer = PeerSenderKey::from_distribution(&own.distribution());
        let m = own.encrypt(b"", b"x");
        assert_eq!(peer.decrypt(b"", &m), Err(CryptoError::TooManySkipped));
    }

    #[test]
    fn rotation_locks_out_old_keys() {
        let mut own = OwnSenderKey::generate(0);
        let mut removed = PeerSenderKey::from_distribution(&own.distribution());
        own = own.rotate();
        let m = own.encrypt(b"", b"after kick");
        assert_eq!(removed.decrypt(b"", &m), Err(CryptoError::UnknownGeneration));
    }

    #[test]
    fn ad_binds_the_message_to_its_group() {
        let mut own = OwnSenderKey::generate(0);
        let mut peer = PeerSenderKey::from_distribution(&own.distribution());
        let m = own.encrypt(b"group-a", b"x");
        assert!(peer.decrypt(b"group-b", &m).is_err());
        assert_eq!(peer.decrypt(b"group-a", &m).unwrap(), b"x");
    }
}
