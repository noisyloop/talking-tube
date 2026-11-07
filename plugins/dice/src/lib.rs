//! `/roll NdM[+K]` and `/flip`.
//!
//! The roll happens on the device of whoever typed the command, so others
//! have to trust them. (A fair group roll would need a commit-reveal protocol:
//! a nice exercise.)

use rand_core::{OsRng, RngCore};
use tt_plugin::{Action, MessageEvent, Plugin, PluginError};

pub struct Dice;

/// Parses `NdM` or `NdM+K` / `NdM-K`. Defaults to `1d6`.
pub fn parse(spec: &str) -> Result<(u32, u32, i64), String> {
    let spec = if spec.is_empty() { "1d6" } else { spec };
    let (dice, modifier) = match spec.find(['+', '-']) {
        Some(i) => (&spec[..i], spec[i..].parse::<i64>().map_err(|_| "bad modifier")?),
        None => (spec, 0),
    };
    let (n, sides) = dice.split_once('d').ok_or("expected NdM, like 2d6")?;
    let n = if n.is_empty() { 1 } else { n.parse().map_err(|_| "bad dice count")? };
    let sides: u32 = sides.parse().map_err(|_| "bad number of sides")?;
    if !(1..=100).contains(&n) || !(2..=1000).contains(&sides) {
        return Err("1-100 dice with 2-1000 sides".into());
    }
    Ok((n, sides, modifier))
}

/// Uniform in 1..=sides, without modulo bias.
fn roll_one(sides: u32) -> u32 {
    let zone = u32::MAX - (u32::MAX % sides);
    loop {
        let v = OsRng.next_u32();
        if v < zone {
            return v % sides + 1;
        }
    }
}

impl Plugin for Dice {
    fn name(&self) -> &'static str {
        "dice"
    }

    fn description(&self) -> &'static str {
        "/roll [NdM+K] rolls dice, /flip flips a coin"
    }

    fn commands(&self) -> &[&'static str] {
        &["roll", "flip"]
    }

    fn on_command(&mut self, command: &str, args: &str, event: &MessageEvent<'_>)
        -> Result<Action, PluginError> {
        if command == "flip" {
            let side = if OsRng.next_u32() & 1 == 0 { "heads" } else { "tails" };
            return Ok(Action::Reply(format!("🪙 {} flipped {side}", event.author_name)));
        }
        let (n, sides, modifier) = parse(args).map_err(PluginError::Usage)?;
        let rolls: Vec<u32> = (0..n).map(|_| roll_one(sides)).collect();
        let total = rolls.iter().map(|&r| r as i64).sum::<i64>() + modifier;
        let shown = rolls.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
        let spec = if args.is_empty() { "1d6" } else { args };
        Ok(Action::Reply(format!("🎲 {} rolled {spec}: [{shown}] = {total}", event.author_name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specs() {
        assert_eq!(parse("2d6"), Ok((2, 6, 0)));
        assert_eq!(parse("d20+3"), Ok((1, 20, 3)));
        assert_eq!(parse("3d8-1"), Ok((3, 8, -1)));
        assert_eq!(parse(""), Ok((1, 6, 0)));
        assert!(parse("0d6").is_err());
        assert!(parse("banana").is_err());
    }

    #[test]
    fn rolls_stay_in_range() {
        for _ in 0..1000 {
            assert!((1..=6).contains(&roll_one(6)));
        }
    }
}
