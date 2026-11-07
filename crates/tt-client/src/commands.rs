//! Typed input: `/commands` and plain text.

use tt_core::{ChatEvent, CommunityId, DeviceKey, MessageId, Op, Role};
use tt_crypto::safety::safety_number;
use tt_plugin::{parse_command, Place};

use crate::engine::{describe_timer, Engine};

pub const HELP: &str = "\
Communities
  /create <name>               make a community (you own it)
  /communities                 list yours
  /open <community> [channel]  switch to it
  /invite [hours] [uses]       make an invite link (default 1 week, unlimited)
  /join <invite>               ask to join (the inviter must be online)
  /leave                       leave the current community
  /rename <name>               rename the community (admin)
Channels
  /channels                    list channels
  /ch <channel>                switch channel
  /newchannel <name>           (admin)   /renamechannel <name>   /delchannel
  /topic <text>                (moderator)
  /timer <30s|5m|1h|1d|off>    disappearing messages for this channel or DM
Members
  /members                     list members and roles
  /role <who> <member|moderator|admin>   /kick <who>   /ban <who>   /unban <key>
  /transfer <who>              give ownership away
  /inviterole <role>           who may invite (admin)
  /nick <name>                 your display name
DMs
  /dm <who> [text]             open a DM (and send text)
  /dms                         list DMs
  /alias <who> <name>          your own label for someone
Messages (use the 6-character id shown in [brackets])
  /reply <id> <text>   /edit <id> <text>   /delete <id>
  /react <id> <emoji>  /unreact <id> <emoji>   /pin <id>   /unpin <id>   /pins
  /history [n]                 show recent messages
Security
  /whoami                      your key
  /safety <who>                safety number to compare in person
  /verify <who>                mark them verified after comparing
Plugins
  /plugins                     list plugins and their commands
  //text                       send text starting with a slash
Anything else you type is sent to the current channel or DM.";

/// Parses `30s`, `5m`, `2h`, `1d`, `1w`, plain seconds, or `off`.
pub fn parse_duration(s: &str) -> Result<Option<u64>, String> {
    let s = s.trim().to_lowercase();
    if s == "off" || s == "0" {
        return Ok(None);
    }
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some('w') => (&s[..s.len() - 1], 604_800),
        _ => (s.as_str(), 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("can't read '{s}' as a duration"))?;
    Ok(Some(n * mult))
}

impl Engine {
    /// Handles one line typed by the user.
    pub fn handle_line(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let result = if let Some(rest) = line.strip_prefix("//") {
            self.send_to_view(&format!("/{rest}"))
        } else if let Some((cmd, args)) = parse_command(line) {
            self.run_command(cmd, args, line)
        } else {
            self.send_to_view(line)
        };
        if let Err(e) = result {
            self.error(e);
        }
    }

    fn view_place(&self) -> Result<Place, String> {
        self.view.ok_or_else(|| "open a channel or DM first (/open, /dm, /help)".to_string())
    }

    fn view_community(&self) -> Result<CommunityId, String> {
        match self.view {
            Some(Place::Channel(c, _)) => Ok(c),
            _ => Err("open a community channel first".into()),
        }
    }

    fn send_to_view(&mut self, text: &str) -> Result<(), String> {
        let place = self.view_place()?;
        self.post_text(place, text, None)
    }

    /// Finds someone by display name, alias, or key prefix.
    pub fn resolve(&self, who: &str) -> Result<DeviceKey, String> {
        if let Ok(k) = who.parse::<DeviceKey>() {
            return Ok(k);
        }
        let w = who.trim_start_matches('@').to_lowercase();
        let mut candidates: Vec<(DeviceKey, String)> = Vec::new();
        // Current community first, then everyone else we know.
        let current = self.view_community().ok();
        let communities = current
            .into_iter()
            .chain(self.store.communities.keys().copied().filter(|c| Some(*c) != current));
        for c in communities {
            for (d, m) in &self.store.communities[&c].state.members {
                candidates.push((*d, m.display_name.to_lowercase()));
            }
        }
        for (d, c) in &self.store.contacts {
            if let Some(a) = &c.alias {
                candidates.push((*d, a.to_lowercase()));
            }
        }
        for d in self.store.dms.keys() {
            candidates.push((*d, String::new()));
        }
        let mut hits: Vec<DeviceKey> = candidates
            .iter()
            .filter(|(d, name)| *name == w || (w.len() >= 4 && d.to_string().starts_with(&w)))
            .map(|(d, _)| *d)
            .collect();
        hits.dedup();
        hits.sort();
        hits.dedup();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no one called '{who}'")),
            _ => Err(format!("'{who}' matches several people; use part of their key")),
        }
    }

    fn resolve_message(&self, prefix: &str) -> Result<MessageId, String> {
        let place = self.view_place()?;
        self.history(place)
            .and_then(|h| h.find_prefix(prefix))
            .map(|m| m.id)
            .ok_or_else(|| format!("no single message matching '{prefix}' here"))
    }

    fn resolve_community(&self, name: &str) -> Result<CommunityId, String> {
        let n = name.to_lowercase();
        let hits: Vec<_> = self
            .store
            .communities
            .iter()
            .filter(|(id, c)| c.state.name.to_lowercase() == n || id.to_string().starts_with(&n))
            .map(|(id, _)| *id)
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no community called '{name}'")),
            _ => Err(format!("'{name}' matches several communities")),
        }
    }

    fn open_channel(&mut self, community: CommunityId, channel: Option<&str>) -> Result<(), String> {
        let c = &self.store.communities[&community];
        let ch = match channel {
            Some(name) => c.state.channel_by_name(name).ok_or(format!("no channel #{name}"))?,
            None => &c.state.channels[0],
        };
        let place = Place::Channel(community, ch.id);
        let topic = if !ch.topic.is_empty() { format!(" — {}", ch.topic) } else { Default::default() };
        let timer = ch.disappearing_secs.map(|s| format!(" ⏳{}", describe_timer(Some(s)))).unwrap_or_default();
        self.view = Some(place);
        self.info(format!("now in {}{topic}{timer}", self.place_label(place)));
        self.show_history(place, 20);
        Ok(())
    }

    fn show_history(&mut self, place: Place, n: usize) {
        let lines: Vec<String> = self
            .history(place)
            .map(|h| {
                let skip = h.messages.len().saturating_sub(n);
                h.messages[skip..].iter().map(|m| self.format_message(place, m)).collect()
            })
            .unwrap_or_default();
        for line in lines {
            self.info(line);
        }
    }

    fn chat_event(&mut self, event: ChatEvent) -> Result<(), String> {
        let place = self.view_place()?;
        self.send_chat(place, event)
    }

    fn run_command(&mut self, cmd: &str, args: &str, line: &str) -> Result<(), String> {
        let mut words = args.split_whitespace();
        let mut first = || words.next().ok_or_else(|| format!("usage: see /help for /{cmd}"));
        let rest_after_first = || args.split_once(char::is_whitespace).map(|(_, r)| r.trim()).unwrap_or("");

        match cmd {
            "help" => self.info(HELP),
            "whoami" => {
                let me = self.me();
                self.info(format!("{} {}", self.store.display_name, me));
            }
            "nick" => {
                if args.is_empty() {
                    return Err("usage: /nick <name>".into());
                }
                self.store.display_name = args.to_string();
                if let Ok(c) = self.view_community() {
                    self.send_op(c, Op::SetNick { display_name: args.to_string() })?;
                }
                self.info(format!("you're now {args}"));
            }

            // communities
            "create" => {
                if args.is_empty() {
                    return Err("usage: /create <name>".into());
                }
                self.create_community(args)?;
            }
            "communities" | "servers" => {
                let lines: Vec<String> = self
                    .store
                    .communities
                    .iter()
                    .map(|(id, c)| format!("{} ({} members) {}", c.state.name, c.state.members.len(), id.short()))
                    .collect();
                if lines.is_empty() {
                    self.info("no communities yet: /create <name> or /join <invite>");
                }
                for l in lines {
                    self.info(l);
                }
            }
            "open" => {
                let name = first()?;
                let channel = words.next();
                let c = self.resolve_community(name)?;
                self.open_channel(c, channel)?;
            }
            "invite" => {
                let c = self.view_community()?;
                let hours = words.next().map(|h| h.parse().map_err(|_| "hours must be a number")).transpose()?;
                let uses = words.next().map(|u| u.parse().map_err(|_| "uses must be a number")).transpose()?;
                let link = self.create_invite(c, hours.unwrap_or(24 * 7), uses)?;
                self.info(format!("invite link (share it privately):\n{link}"));
            }
            "join" => self.join(first()?)?,
            "leave" => {
                let c = self.view_community()?;
                self.send_op(c, Op::Leave)?;
            }
            "rename" => {
                let c = self.view_community()?;
                self.send_op(c, Op::Rename { name: args.to_string() })?;
            }

            // channels
            "channels" => {
                let c = self.view_community()?;
                let lines: Vec<String> = self.store.communities[&c]
                    .state
                    .channels
                    .iter()
                    .map(|ch| {
                        let timer = ch.disappearing_secs.map(|s| format!(" ⏳{}", describe_timer(Some(s)))).unwrap_or_default();
                        format!("#{}{timer} {}", ch.name, ch.topic).trim_end().to_string()
                    })
                    .collect();
                for l in lines {
                    self.info(l);
                }
            }
            "ch" => {
                let c = self.view_community()?;
                self.open_channel(c, Some(first()?))?;
            }
            "newchannel" => {
                let c = self.view_community()?;
                let id = tt_core::ChannelId::random();
                self.send_op(c, Op::CreateChannel { id, name: args.to_string() })?;
            }
            "renamechannel" | "delchannel" | "topic" => {
                let Some(Place::Channel(c, id)) = self.view else { return Err("open a channel first".into()) };
                let op = match cmd {
                    "renamechannel" => Op::RenameChannel { id, name: args.to_string() },
                    "delchannel" => Op::DeleteChannel { id },
                    _ => Op::SetTopic { id, topic: args.to_string() },
                };
                self.send_op(c, op)?;
            }
            "timer" => {
                let secs = parse_duration(first()?)?;
                match self.view_place()? {
                    Place::Dm(peer) => self.set_dm_timer(peer, secs),
                    Place::Channel(c, id) => self.send_op(c, Op::SetChannelTimer { id, secs })?,
                }
            }

            // members
            "members" => {
                let c = self.view_community()?;
                let state = &self.store.communities[&c].state;
                let mut members: Vec<_> = state.members.iter().collect();
                members.sort_by(|a, b| b.1.role.cmp(&a.1.role).then(a.1.display_name.cmp(&b.1.display_name)));
                let lines: Vec<String> = members
                    .iter()
                    .map(|(d, m)| {
                        let verified = self.store.contacts.get(d).is_some_and(|c| c.verified);
                        format!("{} ({}){} {}", m.display_name, m.role, if verified { " ✓" } else { "" }, d.short())
                    })
                    .collect();
                for l in lines {
                    self.info(l);
                }
            }
            "role" => {
                let c = self.view_community()?;
                let device = self.resolve(first()?)?;
                let role: Role = first()?.parse()?;
                self.send_op(c, Op::SetRole { device, role })?;
            }
            "kick" | "ban" | "transfer" => {
                let c = self.view_community()?;
                let device = self.resolve(first()?)?;
                let op = match cmd {
                    "kick" => Op::Kick { device },
                    "ban" => Op::Ban { device },
                    _ => Op::TransferOwnership { device },
                };
                self.send_op(c, op)?;
            }
            "unban" => {
                let c = self.view_community()?;
                let device = first()?.parse().map_err(|e| format!("need their full key: {e}"))?;
                self.send_op(c, Op::Unban { device })?;
            }
            "inviterole" => {
                let c = self.view_community()?;
                let role: Role = first()?.parse()?;
                self.send_op(c, Op::SetInviteRole { role })?;
            }

            // DMs
            "dm" => {
                let peer = self.resolve(first()?)?;
                if peer == self.me() {
                    return Err("that's you".into());
                }
                let place = Place::Dm(peer);
                self.view = Some(place);
                let text = rest_after_first();
                if text.is_empty() {
                    let timer = self.store.dms.get(&peer).and_then(|c| c.timer_secs);
                    self.info(format!("now in {} (disappearing: {})", self.place_label(place), describe_timer(timer)));
                    self.show_history(place, 20);
                } else {
                    self.post_text(place, text, None)?;
                }
            }
            "dms" => {
                let lines: Vec<String> = self
                    .store
                    .dms
                    .keys()
                    .map(|d| format!("@{} {}", self.name_of(None, d), d.short()))
                    .collect();
                for l in lines {
                    self.info(l);
                }
            }
            "alias" => {
                let who = self.resolve(first()?)?;
                let name = rest_after_first();
                self.store.contacts.entry(who).or_default().alias = (!name.is_empty()).then(|| name.to_string());
            }

            // messages
            "reply" => {
                let id = self.resolve_message(first()?)?;
                let place = self.view_place()?;
                self.post_text(place, rest_after_first(), Some(id))?;
            }
            "edit" => {
                let id = self.resolve_message(first()?)?;
                self.chat_event(ChatEvent::Edit { id, text: rest_after_first().to_string() })?;
            }
            "delete" => {
                let id = self.resolve_message(first()?)?;
                self.chat_event(ChatEvent::Delete { id })?;
            }
            "react" | "unreact" => {
                let id = self.resolve_message(first()?)?;
                let emoji = first()?.to_string();
                self.chat_event(ChatEvent::React { id, emoji, on: cmd == "react" })?;
            }
            "pin" | "unpin" => {
                let id = self.resolve_message(first()?)?;
                self.chat_event(ChatEvent::Pin { id, on: cmd == "pin" })?;
            }
            "pins" => {
                let place = self.view_place()?;
                let lines: Vec<String> = self
                    .history(place)
                    .map(|h| h.messages.iter().filter(|m| m.pinned).map(|m| self.format_message(place, m)).collect())
                    .unwrap_or_default();
                for l in lines {
                    self.info(l);
                }
            }
            "history" => {
                let n = words.next().and_then(|n| n.parse().ok()).unwrap_or(20);
                let place = self.view_place()?;
                self.show_history(place, n);
            }

            // security
            "safety" => {
                let who = self.resolve(first()?)?;
                let name = self.name_of(None, &who);
                let number = safety_number(&self.me(), &who);
                self.info(format!("safety number with {name}:\n{number}\nCompare it with them in person or on a call, then /verify {name}"));
            }
            "verify" => {
                let who = self.resolve(first()?)?;
                self.store.contacts.entry(who).or_default().verified = true;
                let name = self.name_of(None, &who);
                self.info(format!("marked {name} as verified"));
            }

            "plugins" => {
                let lines: Vec<String> = self
                    .plugins()
                    .plugins()
                    .map(|p| format!("{}: {}", p.name(), p.description()))
                    .collect();
                for l in lines {
                    self.info(l);
                }
            }

            // Not built in: maybe a plugin owns it.
            other => {
                if !self.plugins().handles(other) {
                    return Err(format!("unknown command /{other} (try /help)"));
                }
                let place = self.view_place()?;
                let me = self.me();
                self.run_plugins(place, me, line);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Ok(Some(30)));
        assert_eq!(parse_duration("5m"), Ok(Some(300)));
        assert_eq!(parse_duration("2h"), Ok(Some(7200)));
        assert_eq!(parse_duration("1d"), Ok(Some(86_400)));
        assert_eq!(parse_duration("90"), Ok(Some(90)));
        assert_eq!(parse_duration("off"), Ok(None));
        assert!(parse_duration("soon").is_err());
    }
}
