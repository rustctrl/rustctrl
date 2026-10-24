use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    CreateStaffAccountRequest, ListFleetDevicesRequest, LoginRequest,
    ReplaceTemporaryPasswordRequest, StaffStatusRequest, UpdateFleetDeviceRequest,
    staff_auth_client::StaffAuthClient,
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
