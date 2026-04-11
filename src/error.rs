//! Error types for the symbios multiuser plugin.
//!
//! [`SymbiosError`] is the unified error enum returned by client-side operations
//! (authentication, serialization, signaling) and relay-side JWT validation.
//! Feature-gated variants are only available when the corresponding feature
//! (`client` or `relay`) is enabled.

/// Errors that can occur in the symbios multiuser plugin.
#[derive(Debug, thiserror::Error)]
pub enum SymbiosError {
    /// Failed to serialize a message for network transmission.
    #[error("serialization failed: {0}")]
    Serialization(#[from] bincode::Error),

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

    /// JWT validation failed on the relay.
    #[cfg(feature = "relay")]
    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),
}
