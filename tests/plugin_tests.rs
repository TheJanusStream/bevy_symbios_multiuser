use bevy::prelude::*;
use bevy_symbios_multiuser::messages::{Broadcast, ChannelKind};
use bevy_symbios_multiuser::plugin::{SymbiosMultiuserConfig, SymbiosMultiuserPlugin};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Serialize, Deserialize, Debug, Clone)]
enum TestMsg {
    Ping,
    Pong,
}

#[test]
fn plugin_registers_messages_and_resources() {
    let mut app = App::new();
    app.add_plugins(MinimalPlugins);
    app.add_plugins(SymbiosMultiuserPlugin::<TestMsg>::new(
        "wss://example.invalid/test_room",
    ));

    // The config resource should be inserted.
    let config = app.world().get_resource::<SymbiosMultiuserConfig<TestMsg>>();
    assert!(config.is_some());
    assert_eq!(config.unwrap().room_url, "wss://example.invalid/test_room");
}

#[test]
fn config_with_custom_url() {
    let config = SymbiosMultiuserConfig {
        room_url: "wss://custom.server/room".to_string(),
        ice_servers: None,
        _marker: PhantomData::<TestMsg>,
    };
    let plugin = SymbiosMultiuserPlugin::<TestMsg>::with_config(config);

    let mut app = App::new();
    app.add_plugins(MinimalPlugins);
    app.add_plugins(plugin);

    let stored = app
        .world()
        .get_resource::<SymbiosMultiuserConfig<TestMsg>>()
        .unwrap();
    assert_eq!(stored.room_url, "wss://custom.server/room");
}

#[test]
fn deferred_plugin_has_no_config_initially() {
    let mut app = App::new();
    app.add_plugins(MinimalPlugins);
    app.add_plugins(SymbiosMultiuserPlugin::<TestMsg>::deferred());

    let config = app.world().get_resource::<SymbiosMultiuserConfig<TestMsg>>();
    assert!(config.is_none(), "deferred plugin should not insert config");
}

#[test]
fn broadcast_message_fields() {
    let msg = Broadcast {
        payload: TestMsg::Ping,
        channel: ChannelKind::Reliable,
    };
    assert_eq!(msg.channel, ChannelKind::Reliable);
}

#[test]
fn broadcast_message_unreliable_channel() {
    let msg = Broadcast {
        payload: TestMsg::Pong,
        channel: ChannelKind::Unreliable,
    };
    assert_eq!(msg.channel, ChannelKind::Unreliable);
}
