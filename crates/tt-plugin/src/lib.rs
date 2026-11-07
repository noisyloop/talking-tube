//! Plugin API.
//!
//! Plugins (bots, slash commands, formatters) run **on the client**, after
//! decryption, so the relay never needs plaintext. A bot is just another
//! device key that runs the client headless with plugins loaded.
//!
//! Today plugins are Rust crates compiled in. A WASM host (e.g. wasmtime)
//! can implement the same trait later for sandboxed third-party plugins.

use tt_core::{ChannelId, CommunityId, DeviceKey};

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("{0}")]
    Other(String),
}

/// What a plugin sees for each decrypted message.
pub struct MessageEvent<'a> {
    pub community: Option<CommunityId>,
    pub channel: Option<ChannelId>,
    pub author: DeviceKey,
    pub text: &'a str,
}

/// What a plugin may ask the client to do. The client decides whether to allow it.
#[derive(Debug)]
pub enum Action {
    Reply(String),
    Ignore,
}

pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;

    /// Slash commands this plugin handles, without the leading `/`.
    fn commands(&self) -> &[&'static str] {
        &[]
    }

    fn on_message(&self, _event: &MessageEvent<'_>) -> Result<Action, PluginError> {
        Ok(Action::Ignore)
    }

    fn on_command(&self, _command: &str, _args: &str, _event: &MessageEvent<'_>)
        -> Result<Action, PluginError> {
        Ok(Action::Ignore)
    }
}

#[derive(Default)]
pub struct Registry {
    plugins: Vec<Box<dyn Plugin>>,
}

impl Registry {
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    pub fn plugins(&self) -> impl Iterator<Item = &dyn Plugin> {
        self.plugins.iter().map(|p| p.as_ref())
    }

    /// Routes `/cmd args` to the plugin that owns `cmd`, else gives every plugin the message.
    pub fn dispatch(&self, event: &MessageEvent<'_>) -> Vec<Action> {
        if let Some(rest) = event.text.strip_prefix('/') {
            let (cmd, args) = rest.split_once(' ').unwrap_or((rest, ""));
            return self
                .plugins
                .iter()
                .filter(|p| p.commands().contains(&cmd))
                .filter_map(|p| p.on_command(cmd, args, event).ok())
                .collect();
        }
        self.plugins
            .iter()
            .filter_map(|p| p.on_message(event).ok())
            .collect()
    }
}
