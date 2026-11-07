//! Device identity and prekeys.
//!
//! TODO: port `DeviceIdentity`, `SignedPreKey`, `OneTimePreKey`, `PreKeyBundle`
//! and `verify_bundle` from Shadow `cli/src/crypto/identity.rs`.

/// Long-term device identity. The Ed25519 public key is the user's identity.
pub struct DeviceIdentity {
    _private: (),
}
