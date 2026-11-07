//! The Talking Tube client.
//!
//! * [`engine::Engine`] holds all the protocol logic. It never touches the
//!   network: it takes in [`tt_proto::RelayFrame`]s and typed lines, and puts
//!   out [`tt_proto::ClientFrame`]s and [`engine::Notice`]s. That makes it
//!   easy to test and easy to put a different UI on.
//! * [`net::run`] connects an engine to a relay over WebSocket.
//! * `commands` turns typed `/commands` into engine calls.

mod commands;
pub mod engine;
pub mod net;
pub mod store;

pub use engine::{Engine, Notice};
pub use store::Store;
pub use tt_plugin::Place;
