use bevy_symbios_multiuser::events::{ChannelKind, PeerConnectionState};

#[test]
fn channel_kind_default_is_reliable() {
    let kind: ChannelKind = Default::default();
    assert_eq!(kind, ChannelKind::Reliable);
}

#[test]
fn channel_kind_variants_are_distinct() {
    assert_ne!(ChannelKind::Reliable, ChannelKind::Unreliable);
}

#[test]
fn peer_connection_state_equality() {
    assert_eq!(
        PeerConnectionState::Connected,
        PeerConnectionState::Connected
    );
    assert_eq!(
        PeerConnectionState::Disconnected,
        PeerConnectionState::Disconnected
    );
    assert_ne!(
        PeerConnectionState::Connected,
        PeerConnectionState::Disconnected
    );
}

#[test]
fn peer_connection_state_clone() {
    let state = PeerConnectionState::Connected;
    let cloned = state;
    assert_eq!(state, cloned);
}

#[test]
fn channel_kind_clone() {
    let kind = ChannelKind::Unreliable;
    let cloned = kind;
    assert_eq!(kind, cloned);
}
