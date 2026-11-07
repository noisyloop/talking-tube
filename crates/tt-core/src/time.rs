use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Formats a timestamp as `HH:MM` (UTC). Good enough for a terminal client.
pub fn hhmm(ms: u64) -> String {
    let secs = (ms / 1000) % 86_400;
    format!("{:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}
