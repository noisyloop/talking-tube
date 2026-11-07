//! Safety numbers: compare these in person (or over a call) to make sure
//! nobody, including the relay, swapped someone's key.

use sha2::{Digest, Sha512};
use tt_core::DeviceKey;

/// 60 digits in 12 groups of 5. The same for both people.
pub fn safety_number(a: &DeviceKey, b: &DeviceKey) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha512::new();
    h.update(b"tt-safety-number-v1");
    h.update(lo.as_bytes());
    h.update(hi.as_bytes());
    let digest = h.finalize();
    digest
        .chunks(5)
        .take(12)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric() {
        let a = DeviceKey::random();
        let b = DeviceKey::random();
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
        assert_eq!(safety_number(&a, &b).len(), 12 * 5 + 11);
    }
}
