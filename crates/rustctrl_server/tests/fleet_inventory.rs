use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    CreateStaffAccountRequest, CreateTargetRequest, ListFleetDevicesRequest, LoginRequest,
    RemoveTargetRequest, ReplaceTemporaryPasswordRequest, StaffStatusRequest,
    UpdateFleetDeviceRequest, UpdateTargetRequest, staff_auth_client::StaffAuthClient,
};
use rustctrl_protocol::bootstrap::HeartbeatRequest;
use rustctrl_server::{
    config::{FleetConfig, ServerConfig, TlsConfig},
    pki::{PkiOptions, initialize},
    service,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request, transport::Channel};

fn client_config(root: &Path, endpoint: &str, role: &str) -> ClientConfig {
    let dir = root.join("clients").join(role);
    ClientConfig {
        endpoint: endpoint.into(),
        domain_name: "localhost".into(),
        ca_certificate: dir.join("ca.pem"),
        certificate: dir.join("cert.pem"),
        private_key: dir.join("key.pem"),
    }
}

struct RunningServer {
    endpoint: String,
    stop: CancellationToken,
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl RunningServer {
    async fn start(root: &Path, database: PathBuf) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let tls = root.join("server");
        let config = ServerConfig {
            listen: address,
            database,
            tls: TlsConfig {
                certificate: tls.join("cert.pem"),
                private_key: tls.join("key.pem"),
                client_ca: tls.join("ca.pem"),
            },
            staff_session: Default::default(),
            fleet: FleetConfig {
                offline_after_secs: 1,
            },
        };
        let stop = CancellationToken::new();
        let signal = stop.clone();
        let handle = tokio::spawn(service::serve_on(
            config,
            listener,
            signal.cancelled_owned(),
        ));
        let endpoint = format!("https://localhost:{}", address.port());
        let config = client_config(root, &endpoint, "controller");
        for _ in 0..50 {
            if let Ok(mut client) = rustctrl_network::connect(&config).await
                && client
                    .get_health(rustctrl_protocol::bootstrap::HealthRequest {})
                    .await
                    .is_ok()
            {
                return Ok(Self {
                    endpoint,
                    stop,
                    handle,
                });
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        stop.cancel();
        anyhow::bail!("server failed to become healthy");
    }
    async fn shutdown(self) -> Result<()> {
        self.stop.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.handle).await???;
        Ok(())
    }
}

fn authorized<T>(token: &str, message: T) -> Request<T> {
    let mut req = Request::new(message);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

async fn connect(root: &Path, endpoint: &str) -> Result<StaffAuthClient<Channel>> {
    rustctrl_network::connect_staff_auth(&client_config(root, endpoint, "controller")).await
}

async fn login(
    client: &mut StaffAuthClient<Channel>,
    username: &str,
    password: &str,
) -> Result<String> {
    let reply = client
        .login(LoginRequest {
            username: username.into(),
            password: password.into(),
            remember: false,
        })
        .await?
        .into_inner();
    Ok(reply.session_token)
}

async fn bootstrap_admin(exe: &str, config: &Path, username: &str, temp: &str) {
    let output = tokio::task::spawn_blocking({
        let exe = exe.to_string();
        let config = config.to_path_buf();
        let username = username.to_string();
        let temp = temp.to_string();
        move || {
            Command::new(&exe)
                .arg("bootstrap-admin")
                .arg("--username")
                .arg(&username)
                .arg("--temporary-password")
                .arg(&temp)
                .arg("--config")
                .arg(&config)
                .output()
                .expect("run rustctrl-server CLI")
        }
    })
    .await
    .expect("join bootstrap");
    assert!(
        output.status.success(),
        "bootstrap-admin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn agent_heartbeat(root: &Path, endpoint: &str, device_id: DeviceId) -> Result<()> {
    agent_heartbeat_with_name(root, endpoint, device_id, "Test Windows PC", "0.1.0").await
}

async fn agent_heartbeat_with_name(
    root: &Path,
    endpoint: &str,
    device_id: DeviceId,
    name: &str,
    version: &str,
) -> Result<()> {
    let mut agent = rustctrl_network::connect(&client_config(root, endpoint, "agent")).await?;
    agent
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: name.into(),
            agent_version: version.into(),
        })
        .await?;
    Ok(())
}

async fn list_activity(exe: &str, config: &Path) -> String {
    let output = tokio::task::spawn_blocking({
        let exe = exe.to_string();
        let config = config.to_path_buf();
        move || {
            Command::new(&exe)
                .arg("list-activity")
                .arg("--config")
                .arg(&config)
                .output()
                .expect("run rustctrl-server list-activity CLI")
        }
    })
    .await
    .expect("join list-activity");
    assert!(
        output.status.success(),
        "list-activity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[tokio::test]
async fn fleet_inventory_shows_shared_devices_with_real_heartbeat_status() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    let device_id = DeviceId::new();
    initialize(&PkiOptions {
        output: pki_dir.clone(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id,
    })?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    let boot = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;
    let alice_session = login(&mut admin, "alice", "AlicePermanent123!").await?;

    admin
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp12345!".into(),
            },
        ))
        .await?;
    let bob_boot = admin
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobTemp12345!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &bob_boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "BobPermanent123!".into(),
            },
        ))
        .await?;

    // Unauthenticated callers and component certificates without a Staff
    // Session cannot read the staff inventory API.
    let unauthenticated = admin
        .list_fleet_devices(Request::new(ListFleetDevicesRequest {}))
        .await
        .unwrap_err();
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);

    let mut component_client =
        rustctrl_network::connect_staff_auth(&client_config(&pki_dir, &server.endpoint, "agent"))
            .await?;
    let component_err = component_client
        .list_fleet_devices(Request::new(ListFleetDevicesRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        component_err.code(),
        Code::Unauthenticated,
        "agent certificate must not read the staff inventory: {component_err}"
    );

    // No devices yet: an authorized read returns an empty list.
    let empty = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert!(empty.devices.is_empty());

    // The authorized Agent heartbeat fills the inventory.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    // Admin and Operator see the same complete inventory.
    let admin_view = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    let mut operator_client = connect(&pki_dir, &server.endpoint).await?;
    let bob_session = login(&mut operator_client, "bob", "BobPermanent123!").await?;
    let operator_view = operator_client
        .list_fleet_devices(authorized(&bob_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(admin_view.devices.len(), 1);
    assert_eq!(admin_view.devices, operator_view.devices);

    let device = &admin_view.devices[0];
    assert_eq!(device.device_id, device_id.to_string());
    assert_eq!(device.display_name, "Test Windows PC");
    assert_eq!(device.device_type, "windows");
    assert!(
        device.last_address.starts_with("127.0.0.1:"),
        "observed address must be recorded: {}",
        device.last_address
    );
    assert!(device.online, "a fresh heartbeat must show online");
    assert!(device.last_seen_unix_ms > 0);

    // Repeated heartbeats over new connections update the same identity
    // without duplicating entries.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;
    let after_repeats = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(after_repeats.devices.len(), 1);
    let status = admin
        .get_staff_status(authorized(&alice_session, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(status.registered_devices, 1);

    // Offline is derived from heartbeat freshness, not fabricated: after the
    // configured window the Device stays visible but reports offline.
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    let stale = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(stale.devices.len(), 1);
    assert!(
        !stale.devices[0].online,
        "stale heartbeat must show offline"
    );

    // A fresh heartbeat brings the same identity back online.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;
    let fresh = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(fresh.devices.len(), 1);
    assert!(fresh.devices[0].online);

    // Inventory data survives a Server restart with the same identity.
    drop(operator_client);
    drop(component_client);
    drop(admin);
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut client, "alice", "AlicePermanent123!").await?;
    // Let the pre-restart heartbeat age past the freshness window.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let restored = client
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(restored.devices.len(), 1);
    assert_eq!(restored.devices[0].device_id, device_id.to_string());
    assert_eq!(restored.devices[0].display_name, "Test Windows PC");
    assert!(
        !restored.devices[0].online,
        "no heartbeat arrived after restart"
    );

    // A Server outage is a connectivity problem, not an offline Fleet.
    restarted.shutdown().await?;
    let outage = connect(&pki_dir, "https://localhost:1").await;
    assert!(
        outage.is_err(),
        "a stopped Server must fail the connection instead of listing Devices offline"
    );

    Ok(())
}

#[tokio::test]
async fn controller_cli_lists_fleet_devices() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    let device_id = DeviceId::new();
    initialize(&PkiOptions {
        output: pki_dir.clone(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id,
    })?;
    let config_path = pki_dir.join("server.toml");
    let controller_config_path = pki_dir.join("clients/controller/config.toml");
    let db_path = temp.path().join("rustctrl.db");

    let server_exe = env!("CARGO_BIN_EXE_rustctrl-server");
    let ext = std::env::consts::EXE_SUFFIX;
    let controller_exe = Path::new(server_exe)
        .parent()
        .unwrap()
        .join(format!("rustctrl-controller{ext}"));
    if !controller_exe.is_file() {
        eprintln!(
            "Skipping controller CLI test: binary not found at {:?}",
            controller_exe
        );
        return Ok(());
    }

    bootstrap_admin(server_exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let controller_toml = format!(
        "[server]\nendpoint = \"{}\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        server.endpoint
    );
    std::fs::write(&controller_config_path, controller_toml)?;

    let run_controller = |args: &[&str]| {
        let exe = controller_exe.clone();
        let config = controller_config_path.clone();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut cmd = Command::new(&exe);
                cmd.arg("--config").arg(&config);
                for arg in &args {
                    cmd.arg(arg);
                }
                cmd.output().expect("run rustctrl-controller CLI")
            })
            .await
            .expect("join rustctrl-controller CLI")
        }
    };

    // Establish the account, create an Operator, and register the Device.
    let bootstrap = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AliceTemp123!",
        "--replace-password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(bootstrap.status.success());

    let mut admin = connect(&pki_dir, &server.endpoint).await?;
    let alice_session = login(&mut admin, "alice", "AlicePermanent123!").await?;
    admin
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp12345!".into(),
            },
        ))
        .await?;
    drop(admin);
    let bob_replace = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobTemp12345!",
        "--replace-password",
        "BobPermanent123!",
    ])
    .await;
    assert!(bob_replace.status.success());

    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    // An Operator reads the Fleet through the Controller CLI.
    let listed = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(
        listed.status.success(),
        "controller list-devices failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let out = String::from_utf8_lossy(&listed.stdout);
    assert!(
        out.contains("Fleet Devices (1)"),
        "must report one device: {out}"
    );
    assert!(
        out.contains("name=Test Windows PC")
            && out.contains("type=windows")
            && out.contains("status=online"),
        "must show identity, type, and derived status: {out}"
    );
    assert!(
        out.contains(&format!("device={device_id}")),
        "must show the stable identity: {out}"
    );

    // Admin edits device display name and location via Controller CLI.
    let edit_res = run_controller(&[
        "edit-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
        "--display-name",
        "Office Workstation 42",
        "--location",
        "Room 101",
    ])
    .await;
    assert!(
        edit_res.status.success(),
        "admin edit-device must succeed: {}",
        String::from_utf8_lossy(&edit_res.stderr)
    );

    // Operator observes the edited name and location via Controller CLI.
    let listed_after_edit = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(listed_after_edit.status.success());
    let edited_out = String::from_utf8_lossy(&listed_after_edit.stdout);
    assert!(
        edited_out.contains("name=Office Workstation 42")
            && edited_out.contains("location=Room 101"),
        "operator must see edited name and location: {edited_out}"
    );

    // Operator cannot edit device: CLI fails with permission denial.
    let op_edit_res = run_controller(&[
        "edit-device",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--device-id",
        &device_id.to_string(),
        "--display-name",
        "Unauthorized Edit",
    ])
    .await;
    assert!(
        !op_edit_res.status.success(),
        "operator edit-device must fail"
    );

    // After the freshness window the same Device reports offline.
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    let stale = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(stale.status.success());
    let stale_out = String::from_utf8_lossy(&stale.stdout);
    assert!(
        stale_out.contains("status=offline"),
        "stale device must report offline: {stale_out}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_can_edit_device_display_name_and_location_and_survives_heartbeats_and_restart()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    let device_id = DeviceId::new();
    initialize(&PkiOptions {
        output: pki_dir.clone(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id,
    })?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let mut admin_client = connect(&pki_dir, &server.endpoint).await?;

    let boot = admin_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin_client
        .replace_temporary_password(authorized(
            &boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;
    let alice_session = login(&mut admin_client, "alice", "AlicePermanent123!").await?;

    // Create an Operator account for Bob.
    admin_client
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp12345!".into(),
            },
        ))
        .await?;
    let mut operator_client = connect(&pki_dir, &server.endpoint).await?;
    let bob_boot = operator_client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobTemp12345!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    operator_client
        .replace_temporary_password(authorized(
            &bob_boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "BobPermanent123!".into(),
            },
        ))
        .await?;
    let bob_session = login(&mut operator_client, "bob", "BobPermanent123!").await?;

    // Newly seen Windows device starts with its reported hostname and no location.
    agent_heartbeat_with_name(
        &pki_dir,
        &server.endpoint,
        device_id,
        "ORIGINAL-HOSTNAME-1234",
        "1.0.0",
    )
    .await?;

    let initial_view = admin_client
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(initial_view.devices.len(), 1);
    let dev = &initial_view.devices[0];
    assert_eq!(dev.device_id, device_id.to_string());
    assert_eq!(dev.display_name, "ORIGINAL-HOSTNAME-1234");
    assert_eq!(dev.location, None);

    // Operator cannot edit device metadata: denied with PermissionDenied.
    let op_err = operator_client
        .update_fleet_device(authorized(
            &bob_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "Operator Attempt".into(),
                location: Some("Secret Room".into()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        op_err.code(),
        Code::PermissionDenied,
        "operator must be denied editing device metadata: {op_err}"
    );

    // Validation: empty display name rejected.
    let empty_name_err = admin_client
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "   ".into(),
                location: Some("Room 101".into()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(empty_name_err.code(), Code::InvalidArgument);

    // Validation: non-existent device returns NotFound.
    let fake_id = DeviceId::new();
    let not_found_err = admin_client
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: fake_id.to_string(),
                display_name: "Ghost Device".into(),
                location: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(not_found_err.code(), Code::NotFound);

    // Admin edits display name and adds optional location.
    let update_reply = admin_client
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "Reception Front Desk".into(),
                location: Some("Building A - Floor 1".into()),
            },
        ))
        .await?
        .into_inner();
    let updated_dev = update_reply.device.expect("device in reply");
    assert_eq!(updated_dev.device_id, device_id.to_string());
    assert_eq!(updated_dev.display_name, "Reception Front Desk");
    assert_eq!(updated_dev.location, Some("Building A - Floor 1".into()));

    // Other Controllers (like Bob's operator client) observe the saved metadata.
    let bob_view = operator_client
        .list_fleet_devices(authorized(&bob_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(bob_view.devices.len(), 1);
    assert_eq!(bob_view.devices[0].display_name, "Reception Front Desk");
    assert_eq!(
        bob_view.devices[0].location,
        Some("Building A - Floor 1".into())
    );

    // Subsequent Agent heartbeats with a different reported hostname, newer version,
    // and new IP do NOT overwrite Admin-curated display name and location!
    agent_heartbeat_with_name(
        &pki_dir,
        &server.endpoint,
        device_id,
        "REPORTED-HOSTNAME-OVERWRITE-ATTEMPT",
        "1.1.0",
    )
    .await?;

    let after_heartbeat_view = admin_client
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(after_heartbeat_view.devices.len(), 1);
    assert_eq!(
        after_heartbeat_view.devices[0].display_name, "Reception Front Desk",
        "heartbeat must not overwrite curated display name"
    );
    assert_eq!(
        after_heartbeat_view.devices[0].location,
        Some("Building A - Floor 1".into()),
        "heartbeat must not overwrite curated location"
    );

    // Admin can clear the location (None or empty).
    let cleared_loc_reply = admin_client
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "Reception Front Desk".into(),
                location: None,
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        cleared_loc_reply.device.unwrap().location,
        None,
        "clearing location must set it to None"
    );

    // Set location to Room 204.
    admin_client
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "Reception Front Desk".into(),
                location: Some("Room 204".into()),
            },
        ))
        .await?;

    // Verify activity recording through the operator-supported observation boundary:
    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=update_fleet_device")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&device_id.to_string()),
        "must record successful update_fleet_device with actor, device identity, outcome: {activity}"
    );
    assert!(
        activity.contains("action=update_fleet_device")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&device_id.to_string()),
        "must record rejected unauthorized update_fleet_device with actor, device identity, outcome: {activity}"
    );

    // Saved metadata survives Server restart.
    drop(operator_client);
    drop(admin_client);
    server.shutdown().await?;

    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut client, "alice", "AlicePermanent123!").await?;

    let restored_view = client
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(restored_view.devices.len(), 1);
    assert_eq!(
        restored_view.devices[0].display_name, "Reception Front Desk",
        "display name must survive restart"
    );
    assert_eq!(
        restored_view.devices[0].location,
        Some("Room 204".into()),
        "location must survive restart"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_android_tv_connection_targets_as_unverified_inventory_entries() -> Result<()>
{
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    let win_device_id = DeviceId::new();
    initialize(&PkiOptions {
        output: pki_dir.clone(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id: win_device_id,
    })?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let mut admin_client = connect(&pki_dir, &server.endpoint).await?;

    let boot = admin_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin_client
        .replace_temporary_password(authorized(
            &boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;
    let alice_session = login(&mut admin_client, "alice", "AlicePermanent123!").await?;

    // Create Operator account for Bob.
    admin_client
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp12345!".into(),
            },
        ))
        .await?;
    let mut operator_client = connect(&pki_dir, &server.endpoint).await?;
    let bob_boot = operator_client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobTemp12345!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    operator_client
        .replace_temporary_password(authorized(
            &bob_boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "BobPermanent123!".into(),
            },
        ))
        .await?;
    let bob_session = login(&mut operator_client, "bob", "BobPermanent123!").await?;

    // Operator cannot create a target: rejected with PermissionDenied.
    let op_create_err = operator_client
        .create_target(authorized(
            &bob_session,
            CreateTargetRequest {
                display_name: "Operator Attempt TV".into(),
                address: "192.168.1.100:5555".into(),
                location: Some("Lobby".into()),
                target_type: Some("android_tv".into()),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_create_err.code(), Code::PermissionDenied);

    // Unauthenticated caller cannot create a target.
    let unauth_err = admin_client
        .create_target(Request::new(CreateTargetRequest {
            display_name: "Unauth TV".into(),
            address: "192.168.1.100".into(),
            location: None,
            target_type: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(unauth_err.code(), Code::Unauthenticated);

    // Validation: empty display name or address rejected.
    let empty_name_err = admin_client
        .create_target(authorized(
            &alice_session,
            CreateTargetRequest {
                display_name: "   ".into(),
                address: "192.168.1.100:5555".into(),
                location: None,
                target_type: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(empty_name_err.code(), Code::InvalidArgument);

    let empty_addr_err = admin_client
        .create_target(authorized(
            &alice_session,
            CreateTargetRequest {
                display_name: "Boardroom TV".into(),
                address: "   ".into(),
                location: None,
                target_type: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(empty_addr_err.code(), Code::InvalidArgument);

    // Admin creates an Android TV target.
    let create_reply = admin_client
        .create_target(authorized(
            &alice_session,
            CreateTargetRequest {
                display_name: "Boardroom TV".into(),
                address: "192.168.1.150:5555".into(),
                location: Some("Building B - Room 301".into()),
                target_type: Some("android_tv".into()),
            },
        ))
        .await?
        .into_inner();
    let target = create_reply.target.expect("target present in reply");
    assert!(!target.device_id.is_empty());
    let target_id = target.device_id.clone();
    assert_eq!(target.display_name, "Boardroom TV");
    assert_eq!(target.device_type, "android_tv");
    assert_eq!(
        target.configured_address,
        Some("192.168.1.150:5555".into()),
        "configured target address must be recorded"
    );
    assert!(
        target.last_address.is_empty(),
        "TV target must not have observed agent address"
    );
    assert!(
        !target.online,
        "TV target must not claim online status without permanent agent"
    );
    assert_eq!(
        target.status, "unverified",
        "TV target must be marked unverified"
    );
    assert_eq!(
        target.last_seen_unix_ms, 0,
        "TV target must not fabricate a last-seen timestamp"
    );
    assert_eq!(target.location, Some("Building B - Room 301".into()));

    // Both Admin and Operator read the same target from ListFleetDevices.
    let admin_view = admin_client
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    let op_view = operator_client
        .list_fleet_devices(authorized(&bob_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(admin_view.devices.len(), 1);
    assert_eq!(admin_view.devices, op_view.devices);
    assert_eq!(admin_view.devices[0].device_id, target_id);
    assert_eq!(admin_view.devices[0].status, "unverified");

    // Connect a Windows agent: now inventory contains both Windows and Android TV target.
    agent_heartbeat(&pki_dir, &server.endpoint, win_device_id).await?;

    let multi_view = admin_client
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(multi_view.devices.len(), 2);
    let win_entry = multi_view
        .devices
        .iter()
        .find(|d| d.device_type == "windows")
        .expect("windows device found");
    let tv_entry = multi_view
        .devices
        .iter()
        .find(|d| d.device_type == "android_tv")
        .expect("tv target found");
    assert_eq!(win_entry.device_id, win_device_id.to_string());
    assert!(win_entry.online);
    assert_eq!(win_entry.status, "online");
    assert!(win_entry.last_address.starts_with("127.0.0.1:"));
    assert_eq!(win_entry.configured_address, None);

    assert_eq!(tv_entry.device_id, target_id);
    assert!(!tv_entry.online);
    assert_eq!(tv_entry.status, "unverified");
    assert_eq!(
        tv_entry.configured_address,
        Some("192.168.1.150:5555".into())
    );
    assert!(tv_entry.last_address.is_empty());
    assert_eq!(tv_entry.last_seen_unix_ms, 0);

    // Operator cannot edit or remove the target.
    let op_update_err = operator_client
        .update_target(authorized(
            &bob_session,
            UpdateTargetRequest {
                target_id: target_id.clone(),
                display_name: "Hacked TV".into(),
                address: "10.0.0.1".into(),
                location: None,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_update_err.code(), Code::PermissionDenied);

    let op_remove_err = operator_client
        .remove_target(authorized(
            &bob_session,
            RemoveTargetRequest {
                target_id: target_id.clone(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_remove_err.code(), Code::PermissionDenied);

    // Admin edits the target.
    let update_reply = admin_client
        .update_target(authorized(
            &alice_session,
            UpdateTargetRequest {
                target_id: target_id.clone(),
                display_name: "Executive Boardroom TV".into(),
                address: "192.168.1.155:5555".into(),
                location: Some("Building B - Room 302".into()),
            },
        ))
        .await?
        .into_inner();
    let updated_tv = update_reply.target.expect("updated target in reply");
    assert_eq!(updated_tv.device_id, target_id);
    assert_eq!(updated_tv.display_name, "Executive Boardroom TV");
    assert_eq!(
        updated_tv.configured_address,
        Some("192.168.1.155:5555".into())
    );
    assert_eq!(updated_tv.location, Some("Building B - Room 302".into()));
    assert_eq!(updated_tv.status, "unverified");
    assert_eq!(updated_tv.last_seen_unix_ms, 0);

    // Server restart preserves the target data.
    drop(admin_client);
    drop(operator_client);
    server.shutdown().await?;

    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut client, "alice", "AlicePermanent123!").await?;

    let restarted_view = client
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(restarted_view.devices.len(), 2);
    let restarted_tv = restarted_view
        .devices
        .iter()
        .find(|d| d.device_type == "android_tv")
        .expect("tv target found after restart");
    assert_eq!(restarted_tv.device_id, target_id);
    assert_eq!(restarted_tv.display_name, "Executive Boardroom TV");
    assert_eq!(
        restarted_tv.configured_address,
        Some("192.168.1.155:5555".into())
    );
    assert_eq!(restarted_tv.location, Some("Building B - Room 302".into()));
    assert_eq!(restarted_tv.status, "unverified");
    assert_eq!(restarted_tv.last_seen_unix_ms, 0);

    // Admin removes the target.
    let remove_reply = client
        .remove_target(authorized(
            &alice_restarted,
            RemoveTargetRequest {
                target_id: target_id.clone(),
            },
        ))
        .await?
        .into_inner();
    assert!(remove_reply.success);
    assert_eq!(remove_reply.target_id, target_id);

    // After removal, only the Windows device remains.
    let after_removal_view = client
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(after_removal_view.devices.len(), 1);
    assert_eq!(after_removal_view.devices[0].device_type, "windows");

    // Removing non-existent target returns NotFound.
    let remove_nonexistent_err = client
        .remove_target(authorized(
            &alice_restarted,
            RemoveTargetRequest {
                target_id: target_id.clone(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(remove_nonexistent_err.code(), Code::NotFound);

    // Activity log contains target actions and rejections.
    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=create_target")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&target_id),
        "activity must log create_target success: {activity}"
    );
    assert!(
        activity.contains("action=create_target")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected"),
        "activity must log rejected create_target: {activity}"
    );
    assert!(
        activity.contains("action=update_target")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&target_id),
        "activity must log update_target success: {activity}"
    );
    assert!(
        activity.contains("action=update_target")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&target_id),
        "activity must log rejected update_target: {activity}"
    );
    assert!(
        activity.contains("action=remove_target")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&target_id),
        "activity must log remove_target success: {activity}"
    );
    assert!(
        activity.contains("action=remove_target")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&target_id),
        "activity must log rejected remove_target: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_targets_via_controller_cli() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    let device_id = DeviceId::new();
    initialize(&PkiOptions {
        output: pki_dir.clone(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id,
    })?;
    let config_path = pki_dir.join("server.toml");
    let controller_config_path = pki_dir.join("clients/controller/config.toml");
    let db_path = temp.path().join("rustctrl.db");

    let server_exe = env!("CARGO_BIN_EXE_rustctrl-server");
    let ext = std::env::consts::EXE_SUFFIX;
    let controller_exe = Path::new(server_exe)
        .parent()
        .unwrap()
        .join(format!("rustctrl-controller{ext}"));
    if !controller_exe.is_file() {
        eprintln!(
            "Skipping controller CLI test: binary not found at {:?}",
            controller_exe
        );
        return Ok(());
    }

    bootstrap_admin(server_exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let controller_toml = format!(
        "[server]\nendpoint = \"{}\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        server.endpoint
    );
    std::fs::write(&controller_config_path, controller_toml)?;

    let run_controller = |args: &[&str]| {
        let exe = controller_exe.clone();
        let config = controller_config_path.clone();
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        async move {
            tokio::task::spawn_blocking(move || {
                let mut cmd = Command::new(&exe);
                cmd.arg("--config").arg(&config);
                for arg in &args {
                    cmd.arg(arg);
                }
                cmd.output().expect("run rustctrl-controller CLI")
            })
            .await
            .expect("join rustctrl-controller CLI")
        }
    };

    // Alice logs in and replaces password.
    let bootstrap = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AliceTemp123!",
        "--replace-password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(bootstrap.status.success());

    // Alice creates operator Bob.
    let mut admin = connect(&pki_dir, &server.endpoint).await?;
    let alice_session = login(&mut admin, "alice", "AlicePermanent123!").await?;
    admin
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp12345!".into(),
            },
        ))
        .await?;
    drop(admin);

    let bob_replace = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobTemp12345!",
        "--replace-password",
        "BobPermanent123!",
    ])
    .await;
    assert!(bob_replace.status.success());

    // Operator Bob cannot add targets.
    let op_add = run_controller(&[
        "add-target",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--display-name",
        "Operator Target",
        "--address",
        "192.168.1.50:5555",
    ])
    .await;
    assert!(
        !op_add.status.success(),
        "operator add-target must fail: {}",
        String::from_utf8_lossy(&op_add.stdout)
    );

    // Admin Alice adds Android TV target.
    let admin_add = run_controller(&[
        "add-target",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--display-name",
        "Breakroom TV",
        "--address",
        "192.168.1.200:5555",
        "--location",
        "Breakroom",
    ])
    .await;
    assert!(
        admin_add.status.success(),
        "admin add-target must succeed: {}",
        String::from_utf8_lossy(&admin_add.stderr)
    );
    let add_out = String::from_utf8_lossy(&admin_add.stdout);
    assert!(
        add_out.contains("Added target ") && add_out.contains("name=Breakroom TV"),
        "unexpected add output: {add_out}"
    );
    let target_id = add_out
        .split("Added target ")
        .nth(1)
        .and_then(|s| s.split(':').next())
        .map(|s| s.trim().to_string())
        .expect("target id parsed from output");

    // Operator Bob lists devices and sees the new target as unverified.
    let list_view = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_view.status.success());
    let list_out = String::from_utf8_lossy(&list_view.stdout);
    assert!(
        list_out.contains(&target_id)
            && list_out.contains("name=Breakroom TV")
            && list_out.contains("type=android_tv")
            && list_out.contains("location=Breakroom")
            && list_out.contains("last_address=-")
            && list_out.contains("configured_address=192.168.1.200:5555")
            && list_out.contains("status=unverified")
            && list_out.contains("last_seen_unix_ms=-"),
        "operator must see target details with unverified status: {list_out}"
    );

    // Operator Bob cannot edit targets.
    let op_edit = run_controller(&[
        "edit-target",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--target-id",
        &target_id,
        "--display-name",
        "Hacked TV",
        "--address",
        "10.0.0.1:5555",
    ])
    .await;
    assert!(!op_edit.status.success());

    // Admin Alice edits target.
    let admin_edit = run_controller(&[
        "edit-target",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--target-id",
        &target_id,
        "--display-name",
        "Cafeteria TV",
        "--address",
        "192.168.1.201:5555",
        "--location",
        "Cafeteria",
    ])
    .await;
    assert!(
        admin_edit.status.success(),
        "admin edit-target must succeed: {}",
        String::from_utf8_lossy(&admin_edit.stderr)
    );

    // Operator Bob observes the edited target.
    let list_after_edit = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_after_edit.status.success());
    let edit_out = String::from_utf8_lossy(&list_after_edit.stdout);
    assert!(
        edit_out.contains("name=Cafeteria TV")
            && edit_out.contains("location=Cafeteria")
            && edit_out.contains("configured_address=192.168.1.201:5555")
            && edit_out.contains("status=unverified"),
        "operator must see updated target: {edit_out}"
    );

    // Operator Bob cannot remove targets.
    let op_remove = run_controller(&[
        "remove-target",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--target-id",
        &target_id,
    ])
    .await;
    assert!(!op_remove.status.success());

    // Admin Alice removes target.
    let admin_remove = run_controller(&[
        "remove-target",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--target-id",
        &target_id,
    ])
    .await;
    assert!(
        admin_remove.status.success(),
        "admin remove-target must succeed: {}",
        String::from_utf8_lossy(&admin_remove.stderr)
    );

    // Operator Bob lists devices and target is gone.
    let list_after_remove = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_after_remove.status.success());
    let remove_out = String::from_utf8_lossy(&list_after_remove.stdout);
    assert!(
        !remove_out.contains(&target_id),
        "target must not appear after removal: {remove_out}"
    );

    server.shutdown().await?;
    Ok(())
}
