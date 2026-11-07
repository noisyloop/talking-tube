use tt_plugin::{Action, MessageEvent, Plugin, PluginError};

pub struct Echo;

impl Plugin for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn commands(&self) -> &[&'static str] {
        &["echo"]
    }

    fn on_command(&self, _command: &str, args: &str, _event: &MessageEvent<'_>)
        -> Result<Action, PluginError> {
        Ok(Action::Reply(args.to_string()))
    }
}
