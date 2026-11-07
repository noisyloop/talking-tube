//! A DM session: X3DH to start, Double Ratchet after.
//!
//! Until the initiator hears back, every message it sends is a
//! [`DmCiphertext::PreKey`] carrying the X3DH info, so the responder can set
//! up the session from whichever message arrives first (Signal does the same).

use serde::{Deserialize, Serialize};
use tt_core::encoding::b64;
use tt_core::DeviceKey;

use crate::identity::{DeviceIdentity, IdentityCert, OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::keys::Key32;
use crate::ratchet::{Header, RatchetState};
use crate::x3dh::{self, X3dhInit};
use crate::CryptoError;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DmCiphertext {
    PreKey {
        sender: IdentityCert,
        init: X3dhInit,
        header: Header,
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
    },
    Normal {
        header: Header,
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub peer: IdentityCert,
    ratchet: RatchetState,
    ad: Vec<u8>,
    /// Set on the initiator until the first reply arrives.
    pending_init: Option<X3dhInit>,
    /// Set on the responder: which X3DH message created this session.
    responder_ek: Option<Key32>,
}

impl Session {
    /// Starts a session with the owner of `bundle`.
    pub fn initiate(me: &DeviceIdentity, bundle: &PreKeyBundle) -> Result<Self, CryptoError> {
        let (sk, init) = x3dh::initiate(me, bundle)?;
        Ok(Self {
            peer: bundle.cert.clone(),
            ratchet: RatchetState::init_initiator(&sk, &bundle.spk.key)?,
            ad: x3dh::associated_data(&me.cert, &bundle.cert),
            pending_init: Some(init),
            responder_ek: None,
        })
    }

    /// Accepts a session someone else started. Call [`Session::decrypt`] on
    /// the message's header and ciphertext next; drop the session if that fails.
    pub fn respond(
        me: &DeviceIdentity,
        spk: &SignedPreKey,
        opk: Option<&OneTimePreKey>,
        sender: &IdentityCert,
        init: &X3dhInit,
    ) -> Result<Self, CryptoError> {
        let sk = x3dh::respond(me, spk, opk, sender, init)?;
        Ok(Self {
            peer: sender.clone(),
            ratchet: RatchetState::init_responder(&sk, &spk.private),
            ad: x3dh::associated_data(sender, &me.cert),
            pending_init: None,
            responder_ek: Some(init.ek_pub),
        })
    }

    pub fn peer_device(&self) -> DeviceKey {
        self.peer.device
    }

    /// Was this session created by the X3DH message with this ephemeral key?
    pub fn created_by(&self, ek_pub: &Key32) -> bool {
        self.responder_ek.as_ref() == Some(ek_pub)
    }

    pub fn can_send(&self) -> bool {
        self.ratchet.can_send()
    }

    pub fn encrypt(&mut self, me: &IdentityCert, plaintext: &[u8]) -> Result<DmCiphertext, CryptoError> {
        let (header, ciphertext) = self.ratchet.encrypt(plaintext, &self.ad)?;
        Ok(match &self.pending_init {
            Some(init) => DmCiphertext::PreKey {
                sender: me.clone(),
                init: init.clone(),
                header,
                ciphertext,
            },
            None => DmCiphertext::Normal { header, ciphertext },
        })
    }

    pub fn decrypt(&mut self, header: &Header, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pt = self.ratchet.decrypt(header, ciphertext, &self.ad)?;
        // They answered, so they have the session: stop resending X3DH info.
        self.pending_init = None;
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(ct: &DmCiphertext) -> (&Header, &[u8]) {
        match ct {
            DmCiphertext::PreKey { header, ciphertext, .. } => (header, ciphertext),
            DmCiphertext::Normal { header, ciphertext } => (header, ciphertext),
        }
    }

    #[test]
    fn full_handshake_and_conversation() {
        let alice = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let spk = bob.generate_spk(1);
        let opk = bob.generate_opks(1, 1).remove(0);
        let bundle =
            PreKeyBundle { cert: bob.cert.clone(), spk: spk.public.clone(), opk: Some(opk.public.clone()) };

        let mut a = Session::initiate(&alice, &bundle).unwrap();
        let first = a.encrypt(&alice.cert, b"hi bob").unwrap();
        let second = a.encrypt(&alice.cert, b"still there?").unwrap();

        let DmCiphertext::PreKey { sender, init, .. } = &first else { panic!("expected prekey message") };
        assert_eq!(sender.device, alice.device_key());
        let mut b = Session::respond(&bob, &spk, Some(&opk), sender, init).unwrap();
        let (h, c) = open(&first);
        assert_eq!(b.decrypt(h, c).unwrap(), b"hi bob");
        let (h, c) = open(&second);
        assert_eq!(b.decrypt(h, c).unwrap(), b"still there?");

        let reply = b.encrypt(&bob.cert, b"yes").unwrap();
        assert!(matches!(reply, DmCiphertext::Normal { .. }));
        let (h, c) = open(&reply);
        assert_eq!(a.decrypt(h, c).unwrap(), b"yes");
        // Alice has heard back, so she stops sending prekey messages.
        assert!(matches!(a.encrypt(&alice.cert, b"ok").unwrap(), DmCiphertext::Normal { .. }));
    }

    #[test]
    fn wire_format_round_trips_through_json() {
        let alice = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let spk = bob.generate_spk(1);
        let bundle = PreKeyBundle { cert: bob.cert.clone(), spk: spk.public.clone(), opk: None };
        let mut a = Session::initiate(&alice, &bundle).unwrap();
        let ct = a.encrypt(&alice.cert, b"json").unwrap();
        let json = serde_json::to_string(&ct).unwrap();
        let back: DmCiphertext = serde_json::from_str(&json).unwrap();
        let DmCiphertext::PreKey { sender, init, header, ciphertext } = back else { panic!() };
        let mut b = Session::respond(&bob, &spk, None, &sender, &init).unwrap();
        assert_eq!(b.decrypt(&header, &ciphertext).unwrap(), b"json");
    }
}
