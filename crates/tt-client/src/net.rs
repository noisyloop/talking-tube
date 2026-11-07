//! Connects an [`Engine`] to a relay over WebSocket.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::tungstenite::Message;
use tt_proto::RelayFrame;

use crate::engine::{Engine, Notice};

/// Input for a running client.
pub enum Input {
    Line(String),
    /// Run code against the engine (handy for tests and other UIs).
    With(Box<dyn FnOnce(&mut Engine) + Send>),
    Quit,
}

/// Why [`run`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Quit,
    Disconnected,
}

/// Runs until the user quits or the connection drops.
pub async fn run(
    engine: &mut Engine,
    url: &str,
    input: &mut UnboundedReceiver<Input>,
    output: &UnboundedSender<Notice>,
) -> anyhow::Result<Exit> {
    let (ws, _) = tokio_tungstenite::connect_async(url).await?;
    let (mut sink, mut stream) = ws.split();
    engine.on_connected(url);
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    let exit = loop {
        let mut exit = None;
        tokio::select! {
            msg = stream.next() => match msg {
                Some(Ok(Message::Text(text))) => match serde_json::from_str::<RelayFrame>(&text) {
                    Ok(frame) => engine.handle_frame(frame),
                    Err(e) => engine.handle_frame(RelayFrame::Error { message: format!("unreadable frame: {e}") }),
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => exit = Some(Exit::Disconnected),
                Some(Ok(_)) => {}
            },
            inp = input.recv() => match inp {
                Some(Input::Line(line)) => engine.handle_line(&line),
                Some(Input::With(f)) => f(engine),
                Some(Input::Quit) | None => exit = Some(Exit::Quit),
            },
            _ = tick.tick() => engine.tick(),
        }
        for frame in engine.take_outgoing() {
            sink.send(Message::Text(serde_json::to_string(&frame)?)).await?;
        }
        for notice in engine.take_notices() {
            let _ = output.send(notice);
        }
        engine.save_if_dirty()?;
        if let Some(e) = exit {
            break e;
        }
    };
    engine.on_disconnected();
    let _ = sink.close().await;
    Ok(exit)
}
