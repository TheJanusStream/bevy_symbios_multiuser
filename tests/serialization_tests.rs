use bevy_symbios_multiuser::systems::bincode_options;
use bincode::Options;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum TestMessage {
    Move { x: f32, y: f32 },
    Chat(String),
    StateUpdate { id: u64, data: Vec<u8> },
}

#[test]
fn roundtrip_move_message() {
    let msg = TestMessage::Move { x: 1.5, y: -3.0 };
    let bytes = bincode_options().serialize(&msg).unwrap();
    let decoded: TestMessage = bincode_options().deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_chat_message() {
    let msg = TestMessage::Chat("Hello, ATProto world!".to_string());
    let bytes = bincode_options().serialize(&msg).unwrap();
    let decoded: TestMessage = bincode_options().deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_state_update_message() {
    let msg = TestMessage::StateUpdate {
        id: 42,
        data: vec![0, 1, 2, 3, 4, 5],
    };
    let bytes = bincode_options().serialize(&msg).unwrap();
    let decoded: TestMessage = bincode_options().deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_empty_data() {
    let msg = TestMessage::StateUpdate {
        id: 0,
        data: vec![],
    };
    let bytes = bincode_options().serialize(&msg).unwrap();
    let decoded: TestMessage = bincode_options().deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_large_payload() {
    let msg = TestMessage::StateUpdate {
        id: u64::MAX,
        data: vec![0xAB; 4096],
    };
    let bytes = bincode_options().serialize(&msg).unwrap();
    let decoded: TestMessage = bincode_options().deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn deserialize_corrupted_data_returns_error() {
    let garbage = vec![0xFF, 0xFE, 0xFD];
    let result = bincode_options().deserialize::<TestMessage>(&garbage);
    assert!(result.is_err());
}

#[test]
fn deserialize_empty_data_returns_error() {
    let result = bincode_options().deserialize::<TestMessage>(&[]);
    assert!(result.is_err());
}

#[test]
fn rejects_oversized_payload() {
    // Production bincode_options() enforces a 1 MiB limit. A payload exceeding
    // that must fail deserialization even if structurally valid.
    let oversized = TestMessage::StateUpdate {
        id: 1,
        data: vec![0u8; 2 * 1024 * 1024], // 2 MiB
    };
    let bytes = bincode_options().serialize(&oversized);
    assert!(bytes.is_err(), "serialization should reject oversized payloads");
}
