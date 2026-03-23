/// Errors that can occur in the symbios multiuser plugin.
#[derive(Debug, thiserror::Error)]
pub enum SymbiosError {
    /// Failed to serialize a message for network transmission.
    #[error("serialization failed: {0}")]
    Serialization(#[from] bincode::Error),

    /// Failed to send a message because the network channel is closed.
    #[error("network channel closed")]
    ChannelClosed,

    /// Failed to connect to the signaling server.
    #[error("signaling connection failed: {0}")]
    SignalingFailed(String),

    /// ATProto authentication failed.
    #[cfg(feature = "client")]
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// An HTTP request failed.
    #[cfg(feature = "client")]
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
}
