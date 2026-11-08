//! Keeps hostile text from controlling the terminal.
//!
//! Everything other people write ends up printed. Control characters (ESC,
//! BEL, newlines, …) let them clear the screen, fake lines from other
//! people, or, in some terminals, write to the clipboard (OSC 52).
//! Bidirectional overrides (U+202E and friends) let them make text read
//! differently from how it's stored.
//!
//! Two layers: [`check`] rejects such text when it arrives, and [`sanitize`]
//! cleans anything printed that didn't go through [`check`] (relay errors,
//! invite name hints).

/// Characters we never accept from other people.
pub fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200E}' | '\u{200F}'            // LRM, RLM
            | '\u{202A}'..='\u{202E}'          // embeddings and overrides
            | '\u{2066}'..='\u{2069}'          // isolates
            | '\u{061C}'                       // Arabic letter mark
        )
}

/// Errors if `s` contains anything [`is_unsafe`].
pub fn check(s: &str) -> Result<(), &'static str> {
    if s.chars().any(is_unsafe) {
        Err("contains control or text-direction characters")
    } else {
        Ok(())
    }
}

/// Replaces unsafe characters with U+FFFD so they show up instead of acting.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if is_unsafe(c) { '\u{FFFD}' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catches_escapes_and_overrides() {
        for bad in ["\x1b[2J", "\x07", "a\nb", "\u{202E}evil", "x\u{2066}y", "\r"] {
            assert!(check(bad).is_err(), "{bad:?} should be rejected");
            assert!(!sanitize(bad).chars().any(is_unsafe));
        }
        for good in ["hello", "café 🔥", "日本語", "👋🏽"] {
            assert_eq!(check(good), Ok(()));
            assert_eq!(sanitize(good), good);
        }
    }
}
