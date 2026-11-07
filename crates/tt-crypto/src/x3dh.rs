//! X3DH key agreement, from <https://signal.org/docs/specifications/x3dh/>.
//!
//! Lets Alice start an encrypted session with Bob while Bob is offline, using
//! the prekey bundle Bob left on the relay:
//!
//! ```text
//! DH1 = DH(IK_A, SPK_B)    proves it's Alice
//! DH2 = DH(EK_A, IK_B)     proves it's Bob
//! DH3 = DH(EK_A, SPK_B)    forward secrecy
//! DH4 = DH(EK_A, OPK_B)    extra forward secrecy for the first message, if an OPK was left
//! SK  = HKDF(F || DH1 || DH2 || DH3 [|| DH4])
//! ```
//!
//! Current Signal uses PQXDH, which adds an ML-KEM (post-quantum) prekey.
//! That's a planned upgrade; see `docs/ENCRYPTION.md`.

use serde::{Deserialize, Serialize};
use tt_core::encoding::hex32;

use crate::identity::{DeviceIdentity, IdentityCert, OneTimePreKey, PreKeyBundle, SignedPreKey};
use crate::keys::{self, Key32};
use crate::CryptoError;

const INFO: &[u8] = b"tt-x3dh-v1";
const AD_LABEL: &[u8] = b"tt-session-ad-v1";

/// What the initiator sends so the responder can repeat the calculation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X3dhInit {
    #[serde(with = "hex32")]
    pub ek_pub: Key32,
    pub spk_id: u32,
    pub opk_id: Option<u32>,
}

fn kdf(dhs: &[Key32]) -> Key32 {
    // F = 32 bytes of 0xFF, so the input can never be a valid X25519 point
    // by itself (the spec's domain separation for X25519).
    let mut ikm = vec![0xFF; 32];
    for d in dhs {
        ikm.extend_from_slice(d);
    }
    let mut sk = [0u8; 32];
    keys::hkdf(&[0u8; 32], &ikm, INFO, &mut sk);
    sk
}

/// Associated data bound into every message of the session: both identities.
pub fn associated_data(initiator: &IdentityCert, responder: &IdentityCert) -> Vec<u8> {
    [
        AD_LABEL,
        initiator.device.as_bytes(),
        &initiator.dh_pub,
        responder.device.as_bytes(),
        &responder.dh_pub,
    ]
    .concat()
}

/// Initiator (Alice). Returns the shared secret and what to send to Bob.
pub fn initiate(me: &DeviceIdentity, bundle: &PreKeyBundle) -> Result<(Key32, X3dhInit), CryptoError> {
    bundle.verify()?;
    let (ek_priv, ek_pub) = keys::generate_dh();
    let mut dhs = vec![
        keys::dh(me.dh_priv(), &bundle.spk.key)?,
        keys::dh(&ek_priv, &bundle.cert.dh_pub)?,
        keys::dh(&ek_priv, &bundle.spk.key)?,
    ];
    if let Some(opk) = &bundle.opk {
        dhs.push(keys::dh(&ek_priv, &opk.key)?);
    }
    let init = X3dhInit { ek_pub, spk_id: bundle.spk.id, opk_id: bundle.opk.as_ref().map(|o| o.id) };
    Ok((kdf(&dhs), init))
}

/// Responder (Bob). The caller looks up the prekeys named in `init`.
pub fn respond(
    me: &DeviceIdentity,
    spk: &SignedPreKey,
    opk: Option<&OneTimePreKey>,
    sender: &IdentityCert,
    init: &X3dhInit,
) -> Result<Key32, CryptoError> {
    sender.verify()?;
    if spk.public.id != init.spk_id || opk.map(|o| o.public.id) != init.opk_id {
        return Err(CryptoError::BadKey);
    }
    let mut dhs = vec![
        keys::dh(&spk.private, &sender.dh_pub)?,
        keys::dh(me.dh_priv(), &init.ek_pub)?,
        keys::dh(&spk.private, &init.ek_pub)?,
    ];
    if let Some(opk) = opk {
        dhs.push(keys::dh(&opk.private, &init.ek_pub)?);
    }
    Ok(kdf(&dhs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        let alice = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let spk = bob.generate_spk(7);
        for opk in [None, Some(bob.generate_opks(1, 1).remove(0))] {
            let bundle = PreKeyBundle {
                cert: bob.cert.clone(),
                spk: spk.public.clone(),
                opk: opk.as_ref().map(|o| o.public.clone()),
            };
            let (sk_a, init) = initiate(&alice, &bundle).unwrap();
            let sk_b = respond(&bob, &spk, opk.as_ref(), &alice.cert, &init).unwrap();
            assert_eq!(sk_a, sk_b);
        }
    }

    #[test]
    fn tampered_bundle_is_rejected() {
        let alice = DeviceIdentity::generate();
        let bob = DeviceIdentity::generate();
        let mut bundle =
            PreKeyBundle { cert: bob.cert.clone(), spk: bob.generate_spk(1).public, opk: None };
        bundle.spk.key = keys::generate_dh().1; // a malicious relay swaps the prekey
        assert!(initiate(&alice, &bundle).is_err());
    }
}
