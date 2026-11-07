#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("bad signature")]
    BadSignature,
    #[error("decryption failed")]
    Decrypt,
    #[error("unknown sender or missing key")]
    UnknownSender,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),
}
