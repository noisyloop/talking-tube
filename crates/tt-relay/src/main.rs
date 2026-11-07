use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "tt-relay", about = "Talking Tube relay: stores and forwards ciphertext")]
struct Args {
    /// Address to listen on. Put a TLS reverse proxy in front for wss://.
    #[arg(long, default_value = "127.0.0.1:7070")]
    listen: String,
    /// Delete stored messages after this many days even if they never expire.
    #[arg(long, default_value_t = 7)]
    retention_days: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await?;
    tracing::info!("listening on ws://{}", listener.local_addr()?);
    let config = tt_relay::Config {
        retention: Duration::from_secs(args.retention_days * 86_400),
        ..Default::default()
    };
    tt_relay::serve(listener, config).await
}
