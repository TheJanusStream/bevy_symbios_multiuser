//! Runs the XRPC Relay signaling server.
//!
//! This is the signaling broker that WebRTC peers connect to for SDP
//! exchange and ICE candidate routing.
//!
//! Run with:
//! ```sh
//! cargo run --example relay_server --features relay
//! ```

fn main() {
    #[cfg(feature = "relay")]
    {
        use bevy_symbios_multiuser::relay::{RelayConfig, run_relay};

        // Initialise tracing so `tracing::info!` / `debug!` etc. are written
        // to stderr (picked up by journald when running as a systemd service).
        // Log level is controlled by the RUST_LOG env var; defaults to `info`.
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
        rt.block_on(async {
            let config = RelayConfig {
                bind_addr: "0.0.0.0:3536".to_string(),
                auth_required: false,
                max_peers: 512,
                service_did: None,
            };

            tracing::info!("Starting relay server on {}", config.bind_addr);
            if let Err(e) = run_relay(config).await {
                tracing::error!("Relay server error: {e}");
            }
        });
    }

    #[cfg(not(feature = "relay"))]
    {
        eprintln!("This example requires the `relay` feature.");
        eprintln!("Run with: cargo run --example relay_server --features relay");
    }
}
