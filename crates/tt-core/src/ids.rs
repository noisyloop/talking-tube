//! Identifiers. All of them serialize as hex strings.

use std::fmt;
use std::str::FromStr;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

macro_rules! hex_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            /// A fresh random value from the OS RNG.
            pub fn random() -> Self {
                let mut b = [0u8; $len];
                OsRng.fill_bytes(&mut b);
                Self(b)
            }

            /// First 8 hex characters, for display.
            pub fn short(&self) -> String {
                hex::encode(&self.0[..4])
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.short())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(s.trim()).map_err(|e| e.to_string())?;
                let arr: [u8; $len] = bytes
                    .try_into()
                    .map_err(|_| format!("expected {} hex characters", $len * 2))?;
                Ok(Self(arr))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_id!(
    /// Ed25519 public key of a device. This is the only identity primitive:
    /// no email, no phone number, no username.
    DeviceKey,
    32
);
hex_id!(
    /// A Discord-style "server". Called a community to avoid confusion with the relay.
    CommunityId,
    16
);
hex_id!(ChannelId, 16);
hex_id!(MessageId, 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let id = MessageId::random();
        let s = id.to_string();
        assert_eq!(s.len(), 32);
        assert_eq!(s.parse::<MessageId>().unwrap(), id);
    }

}
