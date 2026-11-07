//! Plugin API.
//!
//! Plugins (bots, slash commands, auto-replies) run **on the client**, after
//! decryption, so the relay never needs plaintext and encryption never has to
//! be weakened for bots. A bot is just a device key running `tt run --bot`
//! with plugins loaded.
//!
//! * When *you* type `/roll 2d6`, the matching plugin runs on your device and
//!   its reply is posted as your message.
//! * In `--bot` mode, plugins also answer other people's commands and see
//!   every message ([`Plugin::on_message`]).
//!
//! Plugins are compiled-in Rust crates for now. A WASM host could implement
//! the same trait later, so untrusted plugins run sandboxed.

use tt_core::{ChannelId, CommunityId, DeviceKey};

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Other(String),
}

/// Where a message was posted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Dm(DeviceKey),
    Channel(CommunityId, ChannelId),
}

/// A decrypted message, as a plugin sees it.
pub struct MessageEvent<'a> {
    pub place: Place,
    pub author: DeviceKey,
    pub author_name: &'a str,
    pub text: &'a str,
    /// Is the author the device running this plugin?
    pub from_me: bool,
}

/// What a plugin asks the client to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Post this text where the message came from.
    Reply(String),
    /// Show this only to the local user.
    Notify(String),
    Ignore,
}

pub trait Plugin: Send {
    fn name(&self) -> &'static str;

    /// One-line description for `/plugins`.
    fn description(&self) -> &'static str {
        ""
    }

    /// Slash commands handled by this plugin, without the leading `/`.
    fn commands(&self) -> &[&'static str] {
        &[]
    }

    /// Runs for `/command args`.
    fn on_command(&mut self, _command: &str, _args: &str, _event: &MessageEvent<'_>)
        -> Result<Action, PluginError> {
        Ok(Action::Ignore)
    }

    /// Runs for every message that isn't a command. Only called in bot mode.
    fn on_message(&mut self, _event: &MessageEvent<'_>) -> Result<Action, PluginError> {
        Ok(Action::Ignore)
    }
}

#[derive(Default)]
pub struct Registry {
    plugins: Vec<Box<dyn Plugin>>,
}

/// Splits `/cmd args` into `("cmd", "args")`.
pub fn parse_command(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('/')?;
    let (cmd, args) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    (!cmd.is_empty()).then_some((cmd, args.trim()))
}

impl Registry {
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    pub fn plugins(&self) -> impl Iterator<Item = &dyn Plugin> {
        self.plugins.iter().map(|p| p.as_ref())
    }

    pub fn handles(&self, command: &str) -> bool {
        self.plugins.iter().any(|p| p.commands().contains(&command))
    }

    /// Runs the plugin that owns this command, if any.
    /// Errors become [`Action::Notify`] so the user sees them.
    pub fn run_command(&mut self, event: &MessageEvent<'_>) -> Option<Action> {
        let (cmd, args) = parse_command(event.text)?;
        let plugin = self.plugins.iter_mut().find(|p| p.commands().contains(&cmd))?;
        Some(plugin.on_command(cmd, args, event).unwrap_or_else(|e| Action::Notify(e.to_string())))
    }

    /// Gives every plugin a non-command message (bot mode).
    pub fn run_message_hooks(&mut self, event: &MessageEvent<'_>) -> Vec<Action> {
        self.plugins
            .iter_mut()
            .filter_map(|p| p.on_message(event).ok())
            .filter(|a| *a != Action::Ignore)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands() {
        assert_eq!(parse_command("/roll 2d6"), Some(("roll", "2d6")));
        assert_eq!(parse_command("/ping"), Some(("ping", "")));
        assert_eq!(parse_command("hello"), None);
        assert_eq!(parse_command("/"), None);
    }
}
