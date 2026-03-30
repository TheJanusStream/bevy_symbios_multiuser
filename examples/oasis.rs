//! The Symbios Oasis - Multiplayer Sandbox with ATProto Identity
//! Run with: cargo run --example oasis

use bevy::prelude::*;
use bevy_egui::{EguiContexts, EguiPlugin, EguiPrimaryContextPass, egui};
use bevy_symbios_multiuser::auth::{AtprotoCredentials, AtprotoSession, create_session, get_service_auth};
use bevy_symbios_multiuser::signaller::{TokenSource, TokenSourceRes};
use bevy_symbios_multiuser::prelude::*;
use serde::{Deserialize, Serialize};

// --- Protocol ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum OasisMessage {
    Transform { position: [f32; 3] },
    Identity { did: String },
}

// --- State & Components ---

#[derive(States, Default, Debug, Clone, PartialEq, Eq, Hash)]
enum AppState {
    #[default]
    Login,
    InGame,
}

#[derive(Clone)]
struct LoginData {
    pds: String,
    handle: String,
    pass: String,
    error: Option<String>,
}

impl Default for LoginData {
    fn default() -> Self {
        Self {
            pds: "https://bsky.social".into(),
            handle: "".into(),
            pass: "".into(),
            error: None,
        }
    }
}

#[derive(Component)]
struct LocalPlayer;

#[derive(Component)]
struct RemotePeer {
    peer_id: PeerId,
    did: Option<String>,
}

/// The relay's service DID, derived from its hostname.
/// Used as the `aud` claim when requesting a service auth token.
const RELAY_SERVICE_DID: &str = "did:web:<relay ip addr>.nip.io";

/// Result of a completed login: the ATProto session plus a service token
/// signed by the user's `#atproto` key (for relay authentication).
struct LoginResult {
    session: AtprotoSession,
    service_token: String,
}

#[derive(Component)]
struct AuthTask(bevy::tasks::Task<Result<LoginResult, SymbiosError>>);

#[derive(Component)]
struct AvatarFetchTask(bevy::tasks::Task<Option<Vec<u8>>>);

// --- Setup ---

fn main() {
    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(EguiPlugin::default())
        // DEFERRED: The socket won't open until we log in and insert the config
        .add_plugins(SymbiosMultiuserPlugin::<OasisMessage>::deferred())
        .init_state::<AppState>()
        .add_systems(Startup, setup_world)
        // UI (egui pass)
        .add_systems(EguiPrimaryContextPass, login_ui)
        .add_systems(Update, (poll_auth_task).run_if(in_state(AppState::Login)))
        .add_systems(OnEnter(AppState::InGame), spawn_local_player)
        .add_systems(
            Update,
            (
                handle_peer_connections,
                handle_incoming_messages,
                broadcast_local_state,
                move_local_player,
                poll_avatar_tasks,
            )
                .run_if(in_state(AppState::InGame)),
        )
        .run();
}

fn setup_world(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // The Canvas
    commands.spawn((
        Mesh3d(meshes.add(Plane3d::default().mesh().size(50.0, 50.0))),
        MeshMaterial3d(materials.add(StandardMaterial {
            base_color: Color::srgb(0.15, 0.2, 0.15),
            ..default()
        })),
        Transform::from_xyz(0.0, 0.0, 0.0),
    ));

    // Illumination
    commands.spawn((
        PointLight {
            intensity: 3_000_000.0,
            shadows_enabled: true,
            ..default()
        },
        Transform::from_xyz(4.0, 10.0, 4.0),
    ));

    commands.spawn((
        Camera3d::default(),
        Transform::from_xyz(0.0, 5.0, 10.0).looking_at(Vec3::ZERO, Vec3::Y),
    ));
}

// --- Authentication (Login State) ---

fn login_ui(
    mut contexts: EguiContexts,
    mut commands: Commands,
    mut login_data: Local<LoginData>,
    query_tasks: Query<&AuthTask>,
) {
    egui::Window::new("The Sovereign Broker")
        .collapsible(false)
        .resizable(false)
        .show(contexts.ctx_mut().unwrap(), |ui| {
            ui.label("Authenticate via ATProto to enter The Oasis.");
            ui.add_space(10.0);

            ui.horizontal(|ui| {
                ui.label("PDS:");
                ui.text_edit_singleline(&mut login_data.pds);
            });
            ui.horizontal(|ui| {
                ui.label("Handle:");
                ui.text_edit_singleline(&mut login_data.handle);
            });
            ui.horizontal(|ui| {
                ui.label("App Password:");
                ui.add(egui::TextEdit::singleline(&mut login_data.pass).password(true));
            });

            ui.add_space(10.0);

            if query_tasks.is_empty() {
                if ui.button("Ignite Connection").clicked() {
                    login_data.error = None;
                    let creds = AtprotoCredentials {
                        pds_url: login_data.pds.clone(),
                        identifier: login_data.handle.clone(),
                        password: login_data.pass.clone(),
                    };

                    let pool = bevy::tasks::AsyncComputeTaskPool::get();
                    let task = pool.spawn(async move {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(async move {
                                let client = reqwest::Client::new();
                                let session = create_session(&client, &creds).await?;
                                // Service auth tokens are signed with the user's
                                // #atproto key, which the relay can verify against
                                // the user's DID document. The access_jwt from
                                // createSession is signed by the PDS service key —
                                // unusable for third-party verification.
                                let service_token = get_service_auth(
                                    &client,
                                    &session,
                                    &creds.pds_url,
                                    RELAY_SERVICE_DID,
                                )
                                .await?;
                                Ok(LoginResult { session, service_token })
                            })
                    });
                    commands.spawn(AuthTask(task));
                }
            } else {
                ui.spinner();
                ui.label("Negotiating Cryptographic Identity...");
            }

            if let Some(err) = &login_data.error {
                ui.colored_label(egui::Color32::RED, err);
            }
        });
}

fn poll_auth_task(
    mut commands: Commands,
    mut tasks: Query<(Entity, &mut AuthTask)>,
    mut next_state: ResMut<NextState<AppState>>,
    mut login_data: Local<LoginData>,
) {
    for (entity, mut task) in &mut tasks {
        if let Some(result) =
            futures_lite::future::block_on(futures_lite::future::poll_once(&mut task.0))
        {
            match result {
                Ok(LoginResult { session, service_token }) => {
                    info!("Successfully authenticated as: {}", session.did);
                    // Insert the session for identity use (avatar fetch, etc.)
                    commands.insert_resource(session);
                    // Wrap the service token in a TokenSource so the signaller
                    // uses it for relay authentication. The plugin prefers
                    // TokenSourceRes over AtprotoSession when both are present.
                    let source: TokenSource =
                        std::sync::Arc::new(std::sync::RwLock::new(Some(service_token)));
                    commands.insert_resource(TokenSourceRes(source));

                    // Inserting the config triggers the plugin to open the WebSocket.
                    commands.insert_resource(SymbiosMultiuserConfig::<OasisMessage> {
                        room_url: "wss://<relay ip addr>.nip.io/oasis".into(),
                        ice_servers: None,
                        _marker: std::marker::PhantomData,
                    });

                    next_state.set(AppState::InGame);
                }
                Err(e) => {
                    login_data.error = Some(e.to_string());
                }
            }
            commands.entity(entity).despawn();
        }
    }
}

// --- The Oasis (InGame State) ---

fn spawn_local_player(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    session: Res<AtprotoSession>,
) {
    // The Local Player
    let player_ent = commands
        .spawn((
            Mesh3d(meshes.add(Cuboid::new(1.0, 1.0, 1.0))),
            MeshMaterial3d(materials.add(StandardMaterial {
                base_color: Color::WHITE,
                ..default()
            })),
            Transform::from_xyz(0.0, 0.5, 0.0),
            LocalPlayer,
        ))
        .id();

    // Fetch our OWN avatar
    let pool = bevy::tasks::AsyncComputeTaskPool::get();
    let did = session.did.clone();
    let task = pool.spawn(async move {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fetch_avatar_bytes(did))
    });
    commands.entity(player_ent).insert(AvatarFetchTask(task));
}

fn handle_peer_connections(
    mut commands: Commands,
    mut peer_events: ResMut<PeerStateQueue<OasisMessage>>,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    query: Query<(Entity, &RemotePeer)>,
) {
    for event in peer_events.drain() {
        match event.state {
            PeerConnectionState::Connected => {
                // Spawn a blank ghost. It will get its texture when they broadcast their Identity.
                commands.spawn((
                    Mesh3d(meshes.add(Cuboid::new(1.0, 1.0, 1.0))),
                    MeshMaterial3d(materials.add(StandardMaterial {
                        base_color: Color::srgb(0.3, 0.3, 0.3), // Unidentified Grey
                        ..default()
                    })),
                    Transform::from_xyz(0.0, 0.5, 0.0),
                    RemotePeer {
                        peer_id: event.peer,
                        did: None,
                    },
                ));
            }
            PeerConnectionState::Disconnected => {
                for (entity, remote_peer) in query.iter() {
                    if remote_peer.peer_id == event.peer {
                        commands.entity(entity).despawn();
                    }
                }
            }
        }
    }
}

fn handle_incoming_messages(
    mut commands: Commands,
    mut queue: ResMut<NetworkQueue<OasisMessage>>,
    mut query: Query<(Entity, &mut RemotePeer, &mut Transform)>,
) {
    for msg in queue.drain() {
        match msg.payload {
            OasisMessage::Transform { position } => {
                for (_, peer, mut transform) in query.iter_mut() {
                    if peer.peer_id == msg.sender {
                        transform.translation = Vec3::from_array(position);
                    }
                }
            }
            OasisMessage::Identity { did } => {
                for (entity, mut peer, _) in query.iter_mut() {
                    if peer.peer_id == msg.sender {
                        if peer.did.as_ref() != Some(&did) {
                            peer.did = Some(did.clone());
                            info!("Peer {} identified as {}", msg.sender, did);

                            // Spawn task to fetch their avatar
                            let pool = bevy::tasks::AsyncComputeTaskPool::get();
                            let did_clone = did.clone();
                            let task = pool.spawn(async move {
                                tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .unwrap()
                                    .block_on(fetch_avatar_bytes(did_clone))
                            });
                            commands.entity(entity).insert(AvatarFetchTask(task));
                        }
                    }
                }
            }
        }
    }
}

fn broadcast_local_state(
    query: Query<&Transform, With<LocalPlayer>>,
    session: Option<Res<AtprotoSession>>,
    mut writer: MessageWriter<Broadcast<OasisMessage>>,
    mut tick: Local<u32>,
) {
    *tick += 1;
    if let Ok(transform) = query.single() {
        // 60 fps Transform broadcast
        writer.write(Broadcast {
            payload: OasisMessage::Transform {
                position: transform.translation.to_array(),
            },
            channel: ChannelKind::Unreliable,
        });

        // Broadcast our identity periodically so new arrivals know who we are
        if *tick % 60 == 0 {
            if let Some(sess) = &session {
                writer.write(Broadcast {
                    payload: OasisMessage::Identity {
                        did: sess.did.clone(),
                    },
                    channel: ChannelKind::Reliable,
                });
            }
        }
    }
}

fn move_local_player(
    keyboard: Res<ButtonInput<KeyCode>>,
    mut query: Query<&mut Transform, With<LocalPlayer>>,
    time: Res<Time>,
) {
    if let Ok(mut transform) = query.single_mut() {
        let speed = 5.0 * time.delta_secs();
        if keyboard.pressed(KeyCode::KeyW) {
            transform.translation.z -= speed;
        }
        if keyboard.pressed(KeyCode::KeyS) {
            transform.translation.z += speed;
        }
        if keyboard.pressed(KeyCode::KeyA) {
            transform.translation.x -= speed;
        }
        if keyboard.pressed(KeyCode::KeyD) {
            transform.translation.x += speed;
        }
    }
}

// --- Decentralized Avatar Loading ---

#[derive(Deserialize)]
struct BskyProfile {
    avatar: Option<String>,
}

async fn fetch_avatar_bytes(did: String) -> Option<Vec<u8>> {
    let client = reqwest::Client::new();

    // 1. Ask the public ATProto network for their profile
    let profile_url = format!(
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}",
        did
    );
    let resp = client.get(&profile_url).send().await.ok()?;
    let profile = resp.json::<BskyProfile>().await.ok()?;
    let avatar_url = profile.avatar?;

    // 2. Download the raw image bytes from their PDS CDN
    let img_resp = client.get(&avatar_url).send().await.ok()?;
    let bytes = img_resp.bytes().await.ok()?;
    Some(bytes.to_vec())
}

fn poll_avatar_tasks(
    mut commands: Commands,
    mut tasks: Query<(Entity, &mut AvatarFetchTask)>,
    mut images: ResMut<Assets<Image>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    mut mesh_materials: Query<&mut MeshMaterial3d<StandardMaterial>>,
) {
    for (entity, mut task) in &mut tasks {
        if let Some(result) =
            futures_lite::future::block_on(futures_lite::future::poll_once(&mut task.0))
        {
            commands.entity(entity).remove::<AvatarFetchTask>();

            if let Some(bytes) = result {
                // Let the `image` crate figure out if it's a JPEG, PNG, WEBP, etc.
                if let Ok(dyn_img) = image::load_from_memory(&bytes) {
                    let img = Image::from_dynamic(
                        dyn_img,
                        true,
                        bevy_asset::RenderAssetUsages::MAIN_WORLD
                            | bevy_asset::RenderAssetUsages::RENDER_WORLD,
                    );
                    let handle = images.add(img);

                    // Apply the texture to the cube
                    if let Ok(mut mat_handle) = mesh_materials.get_mut(entity) {
                        let new_mat = StandardMaterial {
                            base_color_texture: Some(handle),
                            base_color: Color::WHITE,
                            ..default()
                        };
                        mat_handle.0 = materials.add(new_mat);
                    }
                }
            }
        }
    }
}
