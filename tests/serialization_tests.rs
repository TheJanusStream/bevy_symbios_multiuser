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
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded: TestMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_chat_message() {
    let msg = TestMessage::Chat("Hello, ATProto world!".to_string());
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded: TestMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_state_update_message() {
    let msg = TestMessage::StateUpdate {
        id: 42,
        data: vec![0, 1, 2, 3, 4, 5],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded: TestMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_empty_data() {
    let msg = TestMessage::StateUpdate {
        id: 0,
        data: vec![],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded: TestMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_large_payload() {
    let msg = TestMessage::StateUpdate {
        id: u64::MAX,
        data: vec![0xAB; 4096],
    };
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded: TestMessage = bincode::deserialize(&bytes).unwrap();
    assert_eq!(msg, decoded);
}

#[test]
fn deserialize_corrupted_data_returns_error() {
    let garbage = vec![0xFF, 0xFE, 0xFD];
    let result = bincode::deserialize::<TestMessage>(&garbage);
    assert!(result.is_err());
}

#[test]
fn deserialize_empty_data_returns_error() {
    let result = bincode::deserialize::<TestMessage>(&[]);
    assert!(result.is_err());
}
