#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("bad signature")]
    BadSignature,
    #[error("bad public key")]
    BadKey,
    #[error("decryption failed")]
    Decrypt,
    #[error("Diffie-Hellman output was all zeros (low-order point)")]
    WeakKey,
    #[error("no sending chain yet")]
    NoSendingChain,
    #[error("too many skipped messages")]
    TooManySkipped,
    #[error("message is older than our key (already used or never had it)")]
    OldMessage,
    #[error("unknown key generation")]
    UnknownGeneration,
    #[error("bad padding")]
    BadPadding,
}
