//! Pads plaintext to a multiple of [`BLOCK`] bytes before encryption, so the
//! relay learns less from message sizes. Format: data, `0x80`, then zeros
//! (ISO/IEC 7816-4, the same idea Signal uses).

use crate::CryptoError;

pub const BLOCK: usize = 256;

pub fn pad(data: &[u8]) -> Vec<u8> {
    let len = (data.len() / BLOCK + 1) * BLOCK;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(len, 0);
    out
}

pub fn unpad(data: &[u8]) -> Result<&[u8], CryptoError> {
    let end = data.iter().rposition(|&b| b != 0).ok_or(CryptoError::BadPadding)?;
    if data[end] != 0x80 {
        return Err(CryptoError::BadPadding);
    }
    Ok(&data[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for len in [0, 1, 255, 256, 1000] {
            let data = vec![7u8; len];
            let padded = pad(&data);
            assert_eq!(padded.len() % BLOCK, 0);
            assert_eq!(unpad(&padded).unwrap(), &data[..]);
        }
    }
}
