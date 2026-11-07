//! The Double Ratchet, from <https://signal.org/docs/specifications/doubleratchet/>.
//!
//! Two ratchets run together:
//! * the **DH ratchet**: every time the conversation changes direction, both
//!   sides mix a fresh X25519 exchange into the root key. A stolen state stops
//!   working after the next round trip ("break-in recovery").
//! * the **symmetric ratchet**: every message steps a hash chain, and the old
//!   chain key is overwritten, so old message keys can't be recomputed
//!   ("forward secrecy").
//!
//! Changes from Shadow's version:
//! * `decrypt` works on a copy of the state and only saves it if the message
//!   authenticates. Before, a single forged message could advance the state
//!   and break the session.
//! * `KDF_CK` uses the spec's constants (message key = HMAC(ck, 0x01),
//!   next chain key = HMAC(ck, 0x02)); Shadow had them swapped. Both are
//!   secure, but matching the spec makes test vectors comparable.
//! * Stored skipped keys are capped in total, not just per step.
//! * DH outputs are checked for low-order points.
//!
//! Not done (yet): header encryption, so the relay could see ratchet keys and counters
//! if it could see this layer. In Talking Tube the whole DM ciphertext
//! is opaque to the relay anyway, but headers are still unencrypted bytes.

use serde::{Deserialize, Serialize};
use tt_core::encoding::hex32;

use crate::keys::{self, Key32};
use crate::CryptoError;

/// Most message keys we'll derive ahead in one go.
pub const MAX_SKIP: u32 = 1000;
/// Most skipped keys we keep in total, oldest dropped first.
pub const MAX_STORED_SKIPPED: usize = 2000;
const ROOT_INFO: &[u8] = b"tt-double-ratchet-root-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Sender's current ratchet public key.
    #[serde(with = "hex32")]
    pub dh: Key32,
    /// Length of the sender's previous sending chain.
    pub pn: u32,
    /// Message number in the current sending chain.
    pub n: u32,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut v = self.dh.to_vec();
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.n.to_be_bytes());
        v
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SkippedKey {
    dh: Key32,
    n: u32,
    mk: Key32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetState {
    dhs_priv: Key32,
    dhs_pub: Key32,
    dhr: Option<Key32>,
    rk: Key32,
    cks: Option<Key32>,
    ckr: Option<Key32>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
}

/// KDF_RK: mixes a DH output into the root key. Returns (root key, chain key).
fn kdf_rk(rk: &Key32, dh_out: &Key32) -> (Key32, Key32) {
    let mut okm = [0u8; 64];
    keys::hkdf(rk, dh_out, ROOT_INFO, &mut okm);
    let (a, b) = okm.split_at(32);
    (a.try_into().unwrap(), b.try_into().unwrap())
}

fn full_ad(ad: &[u8], header: &Header) -> Vec<u8> {
    [ad, &header.encode()].concat()
}

impl RatchetState {
    /// Initiator side. `sk` comes from X3DH; `their_spk` is the responder's
    /// signed prekey, which doubles as their first ratchet key.
    pub fn init_initiator(sk: &Key32, their_spk: &Key32) -> Result<Self, CryptoError> {
        let (dhs_priv, dhs_pub) = keys::generate_dh();
        let (rk, cks) = kdf_rk(sk, &keys::dh(&dhs_priv, their_spk)?);
        Ok(Self {
            dhs_priv,
            dhs_pub,
            dhr: Some(*their_spk),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        })
    }

    /// Responder side. Can't send until the first message arrives.
    pub fn init_responder(sk: &Key32, spk_priv: &Key32) -> Self {
        Self {
            dhs_priv: *spk_priv,
            dhs_pub: keys::dh_public(spk_priv),
            dhr: None,
            rk: *sk,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<(Header, Vec<u8>), CryptoError> {
        let ck = self.cks.ok_or(CryptoError::NoSendingChain)?;
        let (next_ck, mk) = keys::kdf_ck(&ck);
        self.cks = Some(next_ck);
        let header = Header { dh: self.dhs_pub, pn: self.pn, n: self.ns };
        self.ns += 1;
        let ct = keys::aead_encrypt(&mk, plaintext, &full_ad(ad, &header));
        Ok((header, ct))
    }

    pub fn decrypt(&mut self, header: &Header, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ad = full_ad(ad, header);

        // A late message from a chain we've moved past?
        if let Some(i) = self.skipped.iter().position(|k| k.dh == header.dh && k.n == header.n) {
            let pt = keys::aead_decrypt(&self.skipped[i].mk, ct, &ad)?;
            self.skipped.remove(i);
            return Ok(pt);
        }

        // Work on a copy; commit only if the message authenticates.
        let mut next = self.clone();
        if next.dhr != Some(header.dh) {
            next.skip_until(header.pn)?;
            next.dh_ratchet(&header.dh)?;
        }
        next.skip_until(header.n)?;
        let ck = next.ckr.ok_or(CryptoError::Decrypt)?;
        let (next_ck, mk) = keys::kdf_ck(&ck);
        next.ckr = Some(next_ck);
        next.nr += 1;

        let pt = keys::aead_decrypt(&mk, ct, &ad)?;
        *self = next;
        Ok(pt)
    }

    /// Derives and stores message keys for messages we haven't seen yet.
    fn skip_until(&mut self, until: u32) -> Result<(), CryptoError> {
        let Some(mut ck) = self.ckr else { return Ok(()) };
        if until > self.nr + MAX_SKIP {
            return Err(CryptoError::TooManySkipped);
        }
        let dh = self.dhr.expect("a receiving chain implies a remote key");
        while self.nr < until {
            let (next_ck, mk) = keys::kdf_ck(&ck);
            self.skipped.push(SkippedKey { dh, n: self.nr, mk });
            ck = next_ck;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        if self.skipped.len() > MAX_STORED_SKIPPED {
            let excess = self.skipped.len() - MAX_STORED_SKIPPED;
            self.skipped.drain(..excess);
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, their_dh: &Key32) -> Result<(), CryptoError> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(*their_dh);
        let (rk, ckr) = kdf_rk(&self.rk, &keys::dh(&self.dhs_priv, their_dh)?);
        let (dhs_priv, dhs_pub) = keys::generate_dh();
        let (rk, cks) = kdf_rk(&rk, &keys::dh(&dhs_priv, their_dh)?);
        self.rk = rk;
        self.ckr = Some(ckr);
        self.cks = Some(cks);
        self.dhs_priv = dhs_priv;
        self.dhs_pub = dhs_pub;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (RatchetState, RatchetState) {
        let sk: Key32 = keys::random_bytes();
        let (spk_priv, spk_pub) = keys::generate_dh();
        let alice = RatchetState::init_initiator(&sk, &spk_pub).unwrap();
        let bob = RatchetState::init_responder(&sk, &spk_priv);
        (alice, bob)
    }

    #[test]
    fn ping_pong() {
        let (mut a, mut b) = pair();
        for i in 0..5 {
            let (h, c) = a.encrypt(format!("a{i}").as_bytes(), b"ad").unwrap();
            assert_eq!(b.decrypt(&h, &c, b"ad").unwrap(), format!("a{i}").as_bytes());
            let (h, c) = b.encrypt(format!("b{i}").as_bytes(), b"ad").unwrap();
            assert_eq!(a.decrypt(&h, &c, b"ad").unwrap(), format!("b{i}").as_bytes());
        }
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"1", b"").unwrap();
        let m2 = a.encrypt(b"2", b"").unwrap();
        let m3 = a.encrypt(b"3", b"").unwrap();
        assert_eq!(b.decrypt(&m3.0, &m3.1, b"").unwrap(), b"3");
        // Bob replies, so Alice ratchets; then Alice's old messages arrive.
        let r = b.encrypt(b"r", b"").unwrap();
        a.decrypt(&r.0, &r.1, b"").unwrap();
        let m4 = a.encrypt(b"4", b"").unwrap();
        assert_eq!(b.decrypt(&m4.0, &m4.1, b"").unwrap(), b"4");
        assert_eq!(b.decrypt(&m1.0, &m1.1, b"").unwrap(), b"1");
        assert_eq!(b.decrypt(&m2.0, &m2.1, b"").unwrap(), b"2");
    }

    #[test]
    fn forged_message_does_not_break_the_session() {
        let (mut a, mut b) = pair();
        let (h, mut c) = a.encrypt(b"real", b"").unwrap();
        // Attacker sends a message claiming a new ratchet key and a far-ahead counter.
        let fake = Header { dh: keys::generate_dh().1, pn: 50, n: 50 };
        assert!(b.decrypt(&fake, &c, b"").is_err());
        let last = c.len() - 1;
        c[last] ^= 1;
        assert!(b.decrypt(&h, &c, b"").is_err());
        c[last] ^= 1;
        assert_eq!(b.decrypt(&h, &c, b"").unwrap(), b"real");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt(b"once", b"").unwrap();
        b.decrypt(&h, &c, b"").unwrap();
        assert!(b.decrypt(&h, &c, b"").is_err());
    }

    #[test]
    fn wrong_associated_data_fails() {
        let (mut a, mut b) = pair();
        let (h, c) = a.encrypt(b"x", b"alice->bob").unwrap();
        assert!(b.decrypt(&h, &c, b"mallory->bob").is_err());
    }
}
