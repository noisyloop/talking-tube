//! Talking Tube client.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "tt", about = "Talking Tube: encrypted communities, no accounts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a device identity (your only "account").
    Init,
    /// Print your public key to share with others.
    Key,
    /// Connect to a relay.
    Connect { url: String },
    /// Create a community on the connected relay.
    Create { name: String },
    /// Join a community from an invite.
    Join { invite: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut plugins = tt_plugin::Registry::default();
    plugins.register(Box::new(tt_plugin_echo::Echo));

    match Cli::parse().command {
        Command::Init => todo!("generate DeviceIdentity and save it"),
        Command::Key => todo!("print device public key"),
        Command::Connect { .. } => todo!("WebSocket connect + challenge auth"),
        Command::Create { .. } => todo!("create community"),
        Command::Join { .. } => todo!("join from invite"),
    }
}
