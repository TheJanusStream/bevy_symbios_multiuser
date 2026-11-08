//! The Bevy-side handle on a `matchbox_socket` WebRTC socket.
//!
//! This is the crate's own copy of the socket wrapper that `bevy_matchbox`
//! used to provide. `bevy_matchbox` stopped at Bevy 0.18 (its wrapper is
//! `#[derive(Resource, Component)]`, which Bevy 0.19 forbids outright), and
//! everything this crate consumed from it fits here: a resource newtype that
//! derefs to [`WebRtcSocket`], keeps the socket's message loop alive on the
//! [`IoTaskPool`], and two `Commands` extensions to open and close it. The
//! rest — signalling server plumbing — this crate never used; the relay is
//! its own service.
//!
//! Derived from `bevy_matchbox` 0.14 `socket.rs` by Johan Helsing and
//! contributors, MIT OR Apache-2.0.
//!
//! # Lifetime of the message loop
//!
//! [`MatchboxSocket`] owns the [`Task`] driving the socket's message loop.
//! Dropping the resource drops the task, and since Bevy 0.19 a dropped task is
//! cancelled on every platform — including wasm, where earlier Bevy versions
//! silently let it run on. Removing the resource is therefore the one way to
//! stop the loop, and the plugin's reopen path relies on exactly that.

use bevy::ecs::system::Command;
use bevy::prelude::{Commands, Resource, World};
use bevy::tasks::{IoTaskPool, Task};
use matchbox_socket::{MessageLoopFuture, WebRtcSocket, WebRtcSocketBuilder};
use std::ops::{Deref, DerefMut};

/// A [`WebRtcSocket`] whose message loop runs on Bevy's [`IoTaskPool`].
///
/// Inserted as a resource by [`OpenSocketExt::open_socket`]; derefs to the
/// underlying socket for sending, receiving and peer bookkeeping.
#[derive(Resource)]
pub struct MatchboxSocket {
    socket: WebRtcSocket,
    /// Held so the loop outlives the socket's insertion, dropped with it so
    /// the loop stops when the resource goes.
    _message_loop: Task<Result<(), matchbox_socket::Error>>,
}

impl std::fmt::Debug for MatchboxSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchboxSocket")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl Deref for MatchboxSocket {
    type Target = WebRtcSocket;

    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}

impl DerefMut for MatchboxSocket {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.socket
    }
}

impl From<WebRtcSocketBuilder> for MatchboxSocket {
    fn from(builder: WebRtcSocketBuilder) -> Self {
        Self::from(builder.build())
    }
}

impl From<(WebRtcSocket, MessageLoopFuture)> for MatchboxSocket {
    fn from((socket, message_loop): (WebRtcSocket, MessageLoopFuture)) -> Self {
        let _message_loop = IoTaskPool::get().spawn(message_loop);
        Self {
            socket,
            _message_loop,
        }
    }
}

impl MatchboxSocket {
    /// Opens an unreliable (UDP-like) socket to `room_url`.
    pub fn new_unreliable(room_url: impl Into<String>) -> Self {
        Self::from(WebRtcSocket::new_unreliable(room_url))
    }

    /// Opens a reliable (TCP-like) socket to `room_url`.
    pub fn new_reliable(room_url: impl Into<String>) -> Self {
        Self::from(WebRtcSocket::new_reliable(room_url))
    }
}

struct OpenSocket(WebRtcSocketBuilder);

impl Command for OpenSocket {
    type Out = ();

    fn apply(self, world: &mut World) {
        world.insert_resource(MatchboxSocket::from(self.0));
    }
}

/// `Commands` extension that builds a socket and inserts it as the
/// [`MatchboxSocket`] resource.
pub trait OpenSocketExt {
    /// Builds `socket_builder` and inserts the result as [`MatchboxSocket`],
    /// replacing any socket already open.
    fn open_socket(&mut self, socket_builder: WebRtcSocketBuilder);
}

impl OpenSocketExt for Commands<'_, '_> {
    fn open_socket(&mut self, socket_builder: WebRtcSocketBuilder) {
        self.queue(OpenSocket(socket_builder));
    }
}

struct CloseSocket;

impl Command for CloseSocket {
    type Out = ();

    fn apply(self, world: &mut World) {
        world.remove_resource::<MatchboxSocket>();
    }
}

/// `Commands` extension that removes the [`MatchboxSocket`] resource, which
/// drops the socket and cancels its message loop.
pub trait CloseSocketExt {
    /// Removes the [`MatchboxSocket`] resource if one is open.
    fn close_socket(&mut self);
}

impl CloseSocketExt for Commands<'_, '_> {
    fn close_socket(&mut self) {
        self.queue(CloseSocket);
    }
}
