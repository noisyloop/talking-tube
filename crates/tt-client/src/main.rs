//! `tt`: the Talking Tube terminal client.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tt_client::net::{self, Exit, Input};
use tt_client::{Engine, Notice, Store};

#[derive(Parser)]
#[command(name = "tt", about = "Talking Tube: encrypted communities, no accounts, no email, no phone")]
struct Cli {
    /// Where your keys and messages live. Use different folders to run several identities.
    #[arg(long, env = "TT_HOME")]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make a new device identity. This is your whole "account".
    Init {
        #[arg(long)]
        name: String,
    },
    /// Print your public key.
    Key,
    /// Connect to a relay and chat.
    Run {
        #[arg(long, default_value = "ws://127.0.0.1:7070")]
        relay: String,
        /// Answer other people's plugin commands (run this as a bot).
        #[arg(long)]
        bot: bool,
    },
}

fn store_path(home: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    let dir = match home {
        Some(h) => h,
        None => PathBuf::from(std::env::var("HOME").context("set --home or $HOME")?).join(".talking-tube"),
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("store.json"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = store_path(cli.home)?;

    match cli.command {
        Command::Init { name } => {
            if path.exists() {
                bail!("{} already exists; refusing to overwrite your identity", path.display());
            }
            let store = Store::new(&name);
            store.save(&path)?;
            println!("created identity for {name}\nkey: {}", store.me());
            println!("back up {} — there's no email reset; lose it and the identity is gone", path.display());
        }
        Command::Key => println!("{}", Store::load(&path)?.me()),
        Command::Run { relay, bot } => {
            let store = Store::load(&path).context("run `tt init --name <you>` first")?;
            let mut engine = Engine::new(store, Some(path));
            engine.bot_mode = bot;

            let (in_tx, mut in_rx) = mpsc::unbounded_channel();
            let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Notice>();
            tokio::spawn(async move {
                let mut lines = BufReader::new(tokio::io::stdin()).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let msg = if matches!(line.trim(), "/quit" | "/exit") { Input::Quit } else { Input::Line(line) };
                    let quit = matches!(msg, Input::Quit);
                    if in_tx.send(msg).is_err() || quit {
                        break;
                    }
                }
            });

            println!("Talking Tube — you are {} ({})", engine.store.display_name, engine.me().short());
            println!("type /help for commands, /quit to exit");
            // Print notices as they arrive, separately from the engine loop.
            tokio::spawn(async move {
                while let Some(n) = out_rx.recv().await {
                    match n {
                        Notice::Error(_) => eprintln!("{n}"),
                        _ => println!("{n}"),
                    }
                }
            });
            loop {
                match net::run(&mut engine, &relay, &mut in_rx, &out_tx).await {
                    Ok(Exit::Quit) => break,
                    Ok(Exit::Disconnected) => eprintln!("! disconnected; retrying in 3s"),
                    Err(e) => eprintln!("! can't reach {relay}: {e}; retrying in 3s"),
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    Ok(())
}
