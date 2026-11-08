# Security review

Research code. This is a self-review, not an audit.

## Review 1 (2026-11)

Scope: the whole codebase after PR #2. Threats: other members, DM contacts,
anyone holding an invite link, and the relay.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Terminal escape injection via message text, reactions, topics, invite name hints, relay errors | Medium | **Fixed** |
| 2 | Integer overflow from attacker-chosen numbers (DM timer, sender-key iteration, dice modifier): panics in debug builds | Medium | **Fixed** |
| 3 | A newcomer fully trusts the state in the inviter's `Welcome` | Medium | Open (design) |
| 4 | A member can freeze a community's stream, or make members' states diverge, by withholding sender keys | Medium | Open (design) |
| 5 | Login signature wasn't bound to the relay, so one relay could replay it at another | Low | **Fixed** |
| 6 | No rate limiting: prekey draining, mailbox filling, community log flooding | Low | Open |
| 7 | Store file briefly world-readable during save; folder not private | Low | **Fixed** |
| 8 | Display names aren't unique, so members can impersonate each other in the UI | Low | **Mitigated** |

### What held up

The relay can't forge messages or pretend to be another member (sender-key
signatures + associated data binding community and sender). Tampered prekey
bundles are rejected. DM and channel replays are rejected. Forged messages
don't break sessions. Removed members can't read new messages once the others
rotate. Permissions give the same result on every member's copy.

### Fixes

1. **Escapes.** `tt_core::text` rejects control and text-direction characters in
   message text, reactions, topics and names when they arrive, and
   `Notice`'s `Display` strips them again when printed. Remote strings that skip
   the input checks (relay errors, invite hints, join-refusal reasons) are sanitized.
   Tests: `rejects_terminal_escapes`, `rejects_escapes_in_topics_and_names`,
   `printing_strips_control_characters`, `catches_escapes_and_overrides`.
2. **Overflow.** DM timers from peers must be off or 5 s to 1 year (as channel
   timers already were); expiry maths saturates; sender-key and ratchet
   counters use checked arithmetic; dice modifiers are capped; durations and
   invite lifetimes are bounded. Tests: `huge_timer_does_not_overflow`,
   `hostile_iteration_does_not_overflow`, `ignores_out_of_range_timers_from_peers`,
   `parses_specs`, `durations`.
3. Open.
4. Open.
5. **Relay binding.** The challenge now names the relay's URL and the client
   signs `label || len || url || nonce`. A client refuses to sign a challenge for
   a relay other than the one it dialed. Relays behind a proxy set `--public-url`.
   Tests: `refuses_challenges_for_another_relay`, `auth_message_binds_the_relay`.
6. Open.
7. **Store.** The temp file is created 0600 (a stale one is removed first) and
   the folder 0700. Test: `store_and_folder_are_owner_only`.
8. **Names.** When a display name is shared in a community, or matches your own,
   messages show the start of the author's key (`alice#58ac`). Verify people
   with `/safety` for real assurance. Test: `shared_names_get_a_key_suffix`.

### Open: ideas for fixing 3, 4 and 6

- **3, trusting the Welcome.** Options: have admins sign state snapshots and
   leave them on the relay, so newcomers can check the inviter's copy; or have a
   newcomer fetch the state from a second member and compare. Until then, only
   join communities through people you trust, or set `/inviterole moderator`.
- **4, withheld keys.** Options: skip per sender instead of blocking the whole
   stream; warn about members whose keys never arrive; have members
   periodically post a hash of their state so divergence is noticed.
- **6, rate limits.** Options: per-device token buckets on the relay; cap how
   many one-time prekeys a client will generate; require a small proof of work
   (or an invite) before a device can post to a community log.

Other known gaps (unencrypted store, no PQXDH, no sealed sender, …) are listed in
[`ENCRYPTION.md`](ENCRYPTION.md#not-done-yet) and
[`ARCHITECTURE.md`](ARCHITECTURE.md#known-gaps).
