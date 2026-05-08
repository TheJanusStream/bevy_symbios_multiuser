//! Demonstrates the [`bevy_symbios_multiuser::smoother`] jitter buffer with
//! synthetic packet jitter — bursts, drops, and clock-skew — so the
//! smoothing/clamping behaviour can be inspected without a real network.
//!
//! Two cubes track a moving "sender":
//!  * `raw` (red) — reads the latest sample directly via `latest_snap`.
//!  * `smoothed` (blue) — reads the Hermite-interpolated playout via
//!    `smoothed_at`.
//!
//! Run with:
//! ```sh
//! cargo run --example smoother_demo --features client
//! ```
//!
//! Expected: the red cube juddered/teleports each time the synthetic
//! "network" delivers a burst or drops a packet; the blue cube glides
//! smoothly, lagging by `SmootherConfig::render_delay_secs`.

use bevy::prelude::*;
use bevy_symbios_multiuser::prelude::{SmootherConfig, TransformBuffer};

#[derive(Component)]
struct Sender;

#[derive(Component)]
struct RawCube;

#[derive(Component)]
struct SmoothedCube;

#[derive(Resource, Default)]
struct Cfg(SmootherConfig);

fn main() {
    App::new()
        .add_plugins(DefaultPlugins)
        .init_resource::<Cfg>()
        .add_systems(Startup, setup)
        .add_systems(
            Update,
            (synthetic_network, drive_raw, drive_smoothed).chain(),
        )
        .run();
}

fn setup(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut mats: ResMut<Assets<StandardMaterial>>,
) {
    let cube = meshes.add(Cuboid::from_size(Vec3::splat(0.6)));
    let red = mats.add(Color::srgb(0.9, 0.2, 0.2));
    let blue = mats.add(Color::srgb(0.2, 0.4, 0.9));
    let grey = mats.add(Color::srgb(0.6, 0.6, 0.6));

    // Visible "sender" position so you can see what the smoother chases.
    commands.spawn((
        Mesh3d(cube.clone()),
        MeshMaterial3d(grey),
        Transform::default(),
        Sender,
    ));

    // Two consumer cubes share the same buffer feed — the demo writes the
    // same synthetic samples into each, but reads them back differently.
    commands.spawn((
        Mesh3d(cube.clone()),
        MeshMaterial3d(red),
        Transform::from_xyz(0.0, 1.5, 0.0),
        TransformBuffer::default(),
        RawCube,
    ));
    commands.spawn((
        Mesh3d(cube),
        MeshMaterial3d(blue),
        Transform::from_xyz(0.0, -1.5, 0.0),
        TransformBuffer::default(),
        SmoothedCube,
    ));

    commands.spawn((
        Camera3d::default(),
        Transform::from_xyz(6.0, 4.0, 10.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
    commands.spawn((
        DirectionalLight::default(),
        Transform::from_xyz(4.0, 6.0, 4.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
}

/// Generate a sine-wave "remote sender" position and push it into both
/// peers' buffers, with intentional bursts and drops so the Hermite
/// smoother has something interesting to do.
fn synthetic_network(
    time: Res<Time>,
    cfg: Res<Cfg>,
    mut sender: Query<&mut Transform, With<Sender>>,
    mut raw: Query<&mut TransformBuffer, (With<RawCube>, Without<SmoothedCube>)>,
    mut smoothed: Query<&mut TransformBuffer, With<SmoothedCube>>,
    mut next_send_at: Local<f64>,
    mut tick: Local<u32>,
) {
    let now = time.elapsed_secs_f64();
    let pos = Vec3::new(
        (now * 1.5).sin() as f32 * 3.0,
        0.0,
        (now * 1.5).cos() as f32 * 3.0,
    );
    if let Ok(mut tf) = sender.single_mut() {
        tf.translation = pos;
    }
    if now < *next_send_at {
        return;
    }
    *next_send_at = now + cfg.0.expected_send_interval_secs;
    *tick += 1;

    // Drop one in seven packets to simulate occasional loss.
    if (*tick).is_multiple_of(7) {
        return;
    }

    // Every 30th tick, deliver three packets in the same frame
    // (a same-frame burst). Without the playout-timestamp clamp inside
    // push_sample, this would collapse the spline's dt to ~0.
    let burst = (*tick).is_multiple_of(30);
    let copies = if burst { 3 } else { 1 };

    if let Ok(mut buf) = raw.single_mut() {
        for _ in 0..copies {
            buf.push_sample(pos, Quat::IDENTITY, now, &cfg.0);
        }
    }
    if let Ok(mut buf) = smoothed.single_mut() {
        for _ in 0..copies {
            buf.push_sample(pos, Quat::IDENTITY, now, &cfg.0);
        }
    }
}

fn drive_raw(mut q: Query<(&mut Transform, &mut TransformBuffer), With<RawCube>>) {
    for (mut tf, mut buf) in &mut q {
        if let Some((p, r)) = buf.latest_snap() {
            tf.translation = p + Vec3::Y * 1.5;
            tf.rotation = r;
        }
    }
}

fn drive_smoothed(
    time: Res<Time>,
    cfg: Res<Cfg>,
    mut q: Query<(&mut Transform, &mut TransformBuffer), With<SmoothedCube>>,
) {
    let now = time.elapsed_secs_f64();
    for (mut tf, mut buf) in &mut q {
        if let Some((p, r)) = buf.smoothed_at(now, &cfg.0) {
            tf.translation = p - Vec3::Y * 1.5;
            tf.rotation = r;
        }
    }
}
