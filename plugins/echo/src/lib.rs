//! The smallest useful plugin. Copy this to start your own.

use tt_plugin::{Action, MessageEvent, Plugin, PluginError};

pub struct Echo;

impl Plugin for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "/echo <text> repeats text, /ping answers pong"
    }

    fn commands(&self) -> &[&'static str] {
        &["echo", "ping"]
    }

    fn on_command(&mut self, command: &str, args: &str, event: &MessageEvent<'_>)
        -> Result<Action, PluginError> {
        match command {
            "ping" => Ok(Action::Reply(format!("pong, {}", event.author_name))),
            _ if args.is_empty() => Err(PluginError::Usage("usage: /echo <text>".into())),
            _ => Ok(Action::Reply(args.to_string())),
        }
    }
}
