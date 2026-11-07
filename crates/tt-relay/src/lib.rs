//! The Talking Tube relay.
//!
//! A relay is deliberately dumb. It:
//! * logs devices in by challenge/response (sign a random nonce; no accounts),
//! * stores prekey bundles and hands out each one-time prekey once,
//! * keeps a mailbox of DMs for offline devices,
//! * gives every community message a sequence number and fans it out, so all
//!   members see the same order (the community state depends on that),
//! * deletes everything when it expires (disappearing messages) or after the
//!   retention period.
//!
//! All state is in memory: restarting the relay forgets everything. That's
//! fine for research and is a reasonable privacy default.

mod state;

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tt_proto::{ClientFrame, RelayFrame};

pub use state::Relay;

#[derive(Clone, Debug)]
pub struct Config {
    /// Longest time anything is stored.
    pub retention: Duration,
    /// Largest text frame accepted, in bytes.
    pub max_frame: usize,
    /// Time allowed to answer the login challenge.
    pub auth_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retention: Duration::from_secs(7 * 86_400),
            max_frame: 256 * 1024,
            auth_timeout: Duration::from_secs(10),
        }
    }
}

/// Accepts connections forever.
pub async fn serve(listener: TcpListener, config: Config) -> anyhow::Result<()> {
    let relay = Arc::new(Relay::new(config.clone()));

    let purger = relay.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            purger.purge_expired();
        }
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        let relay = relay.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(relay, config, stream).await {
                tracing::debug!(%addr, "connection ended: {e:#}");
            }
        });
    }
}

fn encode(frame: &RelayFrame) -> Message {
    Message::Text(serde_json::to_string(frame).expect("frames serialize"))
}

async fn handle(relay: Arc<Relay>, config: Config, stream: TcpStream) -> anyhow::Result<()> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut sink, mut source) = ws.split();

    // 1. Login: sign a fresh random nonce with your device key.
    let nonce: [u8; 32] = tt_crypto::keys::random_bytes();
    sink.send(encode(&RelayFrame::Challenge { nonce: nonce.to_vec() })).await?;
    let device = tokio::time::timeout(config.auth_timeout, async {
        while let Some(msg) = source.next().await {
            if let Message::Text(text) = msg? {
                if let Ok(ClientFrame::Auth { device, signature }) = serde_json::from_str(&text) {
                    tt_crypto::keys::verify(&device.0, &tt_proto::auth_message(&nonce), &signature)
                        .map_err(|_| anyhow::anyhow!("bad login signature"))?;
                    return Ok(device);
                }
                anyhow::bail!("expected auth frame");
            }
        }
        anyhow::bail!("closed before login")
    })
    .await??;

    // 2. Everything for this device now goes through one ordered queue.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let conn_id = relay.connect(device, tx);
    tracing::info!(device = %device.short(), "logged in");

    let result: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                msg = source.next() => match msg {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > config.max_frame {
                            relay.reply(&device, RelayFrame::Error { message: "frame too large".into() });
                            continue;
                        }
                        match serde_json::from_str::<ClientFrame>(&text) {
                            Ok(frame) => relay.handle(&device, frame),
                            Err(e) => relay.reply(&device, RelayFrame::Error { message: format!("bad frame: {e}") }),
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e.into()),
                },
                out = rx.recv() => match out {
                    Some(frame) => sink.send(encode(&frame)).await?,
                    // Replaced by a newer connection from the same device.
                    None => return Ok(()),
                },
            }
        }
    }
    .await;

    relay.disconnect(&device, conn_id);
    tracing::info!(device = %device.short(), "disconnected");
    result
}
