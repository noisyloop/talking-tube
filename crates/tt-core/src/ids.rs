use serde::{Deserialize, Serialize};

/// Ed25519 public key of a device. This is the only identity primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceKey(pub [u8; 32]);

macro_rules! id_type {
    ($name:ident) => {
        /// Random 128-bit identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(pub [u8; 16]);
    };
}

id_type!(CommunityId);
id_type!(ChannelId);
id_type!(MessageId);
