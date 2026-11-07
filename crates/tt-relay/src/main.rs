//! Talking Tube relay.
//!
//! TODO:
//! * WebSocket listener (axum or tokio-tungstenite) speaking `tt_proto` frames.
//! * Challenge/response auth with device keys.
//! * Prekey store, offline mailbox, per-community fan-out.
//! * SQLite storage of ciphertext only.

use clap::Parser;

#[derive(Parser)]
#[command(name = "tt-relay", about = "Talking Tube relay")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:7070")]
    listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    tracing::info!(listen = %args.listen, "relay scaffold: nothing to serve yet");
    Ok(())
}
