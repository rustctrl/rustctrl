use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    BlockDeviceRequest, CleanOfflineDeviceRequest, CreateStaffAccountRequest, CreateTargetRequest,
    ListFleetDevicesRequest, LoginRequest, RemoveTargetRequest, ReplaceFleetDeviceRequest,
    ReplaceTemporaryPasswordRequest, StaffStatusRequest, UnblockDeviceRequest,
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

fn issue_agent_identity(pki_dir: &Path, agent_dir: &Path, device_id: DeviceId) -> Result<()> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use std::fs;

    let ca_dir = pki_dir.join("ca");
    let ca_cert_pem = fs::read_to_string(ca_dir.join("cert.pem"))?;
    let ca_key_pem = fs::read_to_string(ca_dir.join("key.pem"))?;

    let key_pair = KeyPair::from_pem(&ca_key_pem)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair)?;

    fs::create_dir_all(agent_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(agent_dir, fs::Permissions::from_mode(0o700))?;
    }

    let client_key = KeyPair::generate()?;
    let identity = device_id.certificate_name();
    let mut client_params = CertificateParams::default();
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, &identity);
    client_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    client_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params
        .subject_alt_names
        .push(SanType::DnsName(identity.try_into()?));

    let certificate = client_params.signed_by(&client_key, &issuer)?;
    fs::write(agent_dir.join("cert.pem"), certificate.pem().as_bytes())?;
    fs::write(
        agent_dir.join("key.pem"),
        client_key.serialize_pem().as_bytes(),
    )?;
    fs::write(agent_dir.join("ca.pem"), ca_cert_pem.as_bytes())?;
    Ok(())
}

fn agent_config_for_dir(dir: &Path, endpoint: &str) -> ClientConfig {
    ClientConfig {
        endpoint: endpoint.into(),
        domain_name: "localhost".into(),
        ca_certificate: dir.join("ca.pem"),
        certificate: dir.join("cert.pem"),
        private_key: dir.join("key.pem"),
    }
}

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

    let status_after_target = admin_client
        .get_staff_status(authorized(&alice_session, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(
        status_after_target.registered_devices, 1,
        "fleet count must include connection targets"
    );

    // Connect a Windows agent: now inventory contains both Windows and Android TV target.
    agent_heartbeat(&pki_dir, &server.endpoint, win_device_id).await?;

    let multi_view = admin_client
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(multi_view.devices.len(), 2);
    let status_multi = admin_client
        .get_staff_status(authorized(&alice_session, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(
        status_multi.registered_devices, 2,
        "fleet count must include both bootstrap devices and connection targets"
    );
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
    let status_after_removal = client
        .get_staff_status(authorized(&alice_restarted, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(
        status_after_removal.registered_devices, 1,
        "fleet count must decrease when a target is removed"
    );

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

#[tokio::test]
async fn admin_blocks_and_unblocks_device_denying_agent_calls_even_on_established_tls_channel_and_survives_restart()
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

    // Alice creates operator Bob.
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

    // 1. Establish an agent TLS channel and register initial heartbeat.
    let mut agent =
        rustctrl_network::connect(&client_config(&pki_dir, &server.endpoint, "agent")).await?;
    agent
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation 1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // Device is visible in inventory as online and not blocked.
    let list_initial = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_initial.devices.len(), 1);
    let dev = &list_initial.devices[0];
    assert_eq!(dev.device_id, device_id.to_string());
    assert_eq!(dev.status, "online");
    assert!(!dev.blocked);
    let initial_last_seen = dev.last_seen_unix_ms;
    assert!(initial_last_seen > 0);

    // 2. Operator Bob attempts to block the device -> rejected.
    let op_block_err = operator_client
        .block_device(authorized(
            &bob_session,
            BlockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_block_err.code(), Code::PermissionDenied);

    // 3. Admin Alice blocks the device.
    let block_reply = admin
        .block_device(authorized(
            &alice_session,
            BlockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await?
        .into_inner();
    let blocked_dev = block_reply.device.expect("device returned");
    assert_eq!(blocked_dev.status, "blocked");
    assert!(blocked_dev.blocked);

    // Inventory lists device as blocked while preserving heartbeat freshness.
    let list_blocked = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_blocked.devices.len(), 1);
    assert_eq!(list_blocked.devices[0].status, "blocked");
    assert!(list_blocked.devices[0].blocked);
    assert_eq!(
        list_blocked.devices[0].last_seen_unix_ms, initial_last_seen,
        "blocked device must retain its previous heartbeat freshness timestamp"
    );

    // Operator Bob also sees the device as blocked.
    let op_view_blocked = operator_client
        .list_fleet_devices(authorized(&bob_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(op_view_blocked.devices[0].status, "blocked");
    assert!(op_view_blocked.devices[0].blocked);

    // 4. Operational call rejection over EXISTING TLS channel.
    let existing_channel_err = agent
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation 1".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(existing_channel_err.code(), Code::PermissionDenied);
    assert!(
        existing_channel_err.message().contains("device is blocked"),
        "error must indicate device is blocked: {existing_channel_err}"
    );

    // 5. Operational call rejection over RECONNECTING / fresh channel.
    let mut fresh_agent =
        rustctrl_network::connect(&client_config(&pki_dir, &server.endpoint, "agent")).await?;
    let reconnect_err = fresh_agent
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation 1".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(reconnect_err.code(), Code::PermissionDenied);
    assert!(
        reconnect_err.message().contains("device is blocked"),
        "reconnecting agent must still be denied: {reconnect_err}"
    );

    // 6. Certificate identity check precedence: if certificate SAN does not match payload device_id,
    // the certificate check must fail first with certificate mismatch.
    let fake_id = DeviceId::new();
    let cert_mismatch_err = fresh_agent
        .send_heartbeat(HeartbeatRequest {
            device_id: fake_id.to_string(),
            name: "Spoofed".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(cert_mismatch_err.code(), Code::PermissionDenied);
    assert!(
        cert_mismatch_err
            .message()
            .contains("certificate does not identify this device"),
        "certificate SAN check must take precedence: {cert_mismatch_err}"
    );

    // 7. Restart Server and verify persistence.
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut admin_restarted = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut admin_restarted, "alice", "AlicePermanent123!").await?;

    let list_after_restart = admin_restarted
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_after_restart.devices[0].status, "blocked");
    assert!(list_after_restart.devices[0].blocked);

    // Agent heartbeat after server restart is STILL denied.
    let mut agent_after_restart =
        rustctrl_network::connect(&client_config(&pki_dir, &restarted.endpoint, "agent")).await?;
    let restart_hb_err = agent_after_restart
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation 1".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(restart_hb_err.code(), Code::PermissionDenied);
    assert!(restart_hb_err.message().contains("device is blocked"));

    // 8. Operator Bob cannot unblock.
    let mut op_restarted = connect(&pki_dir, &restarted.endpoint).await?;
    let bob_restarted = login(&mut op_restarted, "bob", "BobPermanent123!").await?;
    let op_unblock_err = op_restarted
        .unblock_device(authorized(
            &bob_restarted,
            UnblockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_unblock_err.code(), Code::PermissionDenied);

    // 9. Admin Alice unblocks the device.
    let unblock_reply = admin_restarted
        .unblock_device(authorized(
            &alice_restarted,
            UnblockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await?
        .into_inner();
    let unblocked_dev = unblock_reply.device.expect("device returned");
    assert!(!unblocked_dev.blocked);

    // 10. Agent can now successfully send heartbeat!
    agent_after_restart
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation 1".into(),
            agent_version: "0.1.1".into(),
        })
        .await?;

    // Device is back to online with updated timestamp.
    let list_restored = admin_restarted
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_restored.devices[0].status, "online");
    assert!(!list_restored.devices[0].blocked);
    assert!(list_restored.devices[0].last_seen_unix_ms >= initial_last_seen);

    // 11. Activity log verification: allowed and rejected actions logged with actor and device attribution.
    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=block_device")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&device_id.to_string()),
        "activity log must record alice block_device success: {activity}"
    );
    assert!(
        activity.contains("action=block_device")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&device_id.to_string()),
        "activity log must record bob block_device rejection: {activity}"
    );
    assert!(
        activity.contains("action=unblock_device")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&device_id.to_string()),
        "activity log must record alice unblock_device success: {activity}"
    );
    assert!(
        activity.contains("action=unblock_device")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&device_id.to_string()),
        "activity log must record bob unblock_device rejection: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_device_block_via_controller_cli() -> Result<()> {
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

    // Agent registers device via heartbeat.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    // Operator Bob cannot block device.
    let op_block = run_controller(&[
        "block-device",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        !op_block.status.success(),
        "operator block-device must fail: {}",
        String::from_utf8_lossy(&op_block.stdout)
    );

    // Admin Alice blocks device.
    let admin_block = run_controller(&[
        "block-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        admin_block.status.success(),
        "admin block-device must succeed: {}",
        String::from_utf8_lossy(&admin_block.stderr)
    );
    let block_out = String::from_utf8_lossy(&admin_block.stdout);
    assert!(
        block_out.contains("Blocked device ") && block_out.contains("status=blocked"),
        "unexpected block output: {block_out}"
    );

    // Operator Bob lists devices and observes status=blocked.
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
        list_out.contains(&device_id.to_string()) && list_out.contains("status=blocked"),
        "device must be listed with status=blocked: {list_out}"
    );

    // Real Agent heartbeat is denied while blocked via Controller CLI action.
    let blocked_hb_res = agent_heartbeat(&pki_dir, &server.endpoint, device_id).await;
    assert!(
        blocked_hb_res.is_err(),
        "Agent heartbeat must be denied after Controller blocks the device"
    );

    // Operator Bob cannot unblock device.
    let op_unblock = run_controller(&[
        "unblock-device",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(!op_unblock.status.success());

    // Admin Alice unblocks device.
    let admin_unblock = run_controller(&[
        "unblock-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        admin_unblock.status.success(),
        "admin unblock-device must succeed: {}",
        String::from_utf8_lossy(&admin_unblock.stderr)
    );
    let unblock_out = String::from_utf8_lossy(&admin_unblock.stdout);
    assert!(
        unblock_out.contains("Unblocked device "),
        "unexpected unblock output: {unblock_out}"
    );

    // Real Agent heartbeat succeeds after Controller unblocks the device.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    // Operator Bob lists devices and device is no longer blocked.
    let list_after_unblock = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_after_unblock.status.success());
    let unblock_list_out = String::from_utf8_lossy(&list_after_unblock.stdout);
    assert!(
        !unblock_list_out.contains("status=blocked"),
        "device must not have status=blocked after unblock: {unblock_list_out}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_cleans_offline_device_and_restores_on_agent_reconnect_and_survives_restart()
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

    // Alice creates operator Bob.
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

    // 1. Establish an agent TLS channel and run real Agent heartbeat loop.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let agent_stop = CancellationToken::new();
    let agent_task = {
        let stop = agent_stop.clone();
        let pki_dir = pki_dir.clone();
        let endpoint = server.endpoint.clone();
        tokio::spawn(async move {
            let mut agent =
                rustctrl_network::connect(&client_config(&pki_dir, &endpoint, "agent")).await?;
            agent
                .send_heartbeat(HeartbeatRequest {
                    device_id: device_id.to_string(),
                    name: "Workstation Offline Test".into(),
                    agent_version: "0.1.0".into(),
                })
                .await?;
            let _ = ready_tx.send(());
            while !stop.is_cancelled() {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(150)) => {}
                }
                if stop.is_cancelled() {
                    break;
                }
                agent
                    .send_heartbeat(HeartbeatRequest {
                        device_id: device_id.to_string(),
                        name: "Workstation Offline Test".into(),
                        agent_version: "0.1.0".into(),
                    })
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        })
    };

    ready_rx.await.expect("agent loop sent initial heartbeat");

    // Alice curates device metadata.
    admin
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: device_id.to_string(),
                display_name: "Floor 3 PC".into(),
                location: Some("Room 301".into()),
            },
        ))
        .await?;

    // 2. While device is still ONLINE, Admin cleanup attempt MUST fail.
    let online_clean_err = admin
        .clean_offline_device(authorized(
            &alice_session,
            CleanOfflineDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(online_clean_err.code(), Code::FailedPrecondition);
    assert!(online_clean_err.message().contains("online"));

    // 3. Stop running Agent (simulating real Agent stop/disconnect).
    agent_stop.cancel();
    agent_task.await??;

    // Wait for offline threshold (server offline_after_secs is 1 second).
    tokio::time::sleep(Duration::from_millis(1_600)).await;

    // Verify device is now offline in inventory.
    let list_offline = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_offline.devices.len(), 1);
    assert_eq!(list_offline.devices[0].status, "offline");
    assert!(!list_offline.devices[0].online);

    // 4. Operator Bob attempts cleanup -> MUST fail with permission denied.
    let op_clean_err = operator_client
        .clean_offline_device(authorized(
            &bob_session,
            CleanOfflineDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_clean_err.code(), Code::PermissionDenied);

    // 5. Admin Alice blocks the offline device.
    admin
        .block_device(authorized(
            &alice_session,
            BlockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await?;

    // Attempting cleanup on blocked device MUST fail.
    let blocked_clean_err = admin
        .clean_offline_device(authorized(
            &alice_session,
            CleanOfflineDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(blocked_clean_err.code(), Code::FailedPrecondition);
    assert!(blocked_clean_err.message().contains("blocked"));

    // Verify blocked device remains visible as blocked in inventory.
    let list_blocked = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(list_blocked.devices.len(), 1);
    assert_eq!(list_blocked.devices[0].status, "blocked");
    assert!(list_blocked.devices[0].blocked);

    // 6. Admin Alice unblocks device -> it is offline again.
    admin
        .unblock_device(authorized(
            &alice_session,
            UnblockDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await?;

    // 7. Admin Alice cleans up the offline device -> succeeds!
    let clean_reply = admin
        .clean_offline_device(authorized(
            &alice_session,
            CleanOfflineDeviceRequest {
                device_id: device_id.to_string(),
            },
        ))
        .await?
        .into_inner();
    assert!(clean_reply.success);
    assert_eq!(clean_reply.device_id, device_id.to_string());

    // Inventory is now empty (visible entry removed).
    let list_after_clean = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert!(
        list_after_clean.devices.is_empty(),
        "cleaned device must not appear in inventory"
    );

    // 8. Server restart -> cleanup persists across restart.
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut admin_restarted = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut admin_restarted, "alice", "AlicePermanent123!").await?;

    let list_after_restart = admin_restarted
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert!(
        list_after_restart.devices.is_empty(),
        "cleaned device must remain removed after restart"
    );

    // Server outage distinction: stopped server connectivity fails rather than falsely reporting fleet offline.
    let outage = connect(&pki_dir, "https://localhost:1").await;
    assert!(outage.is_err(), "stopped server must fail connection");

    // 9. Still-authorized Agent reconnects with the SAME identity -> restores entry!
    let mut reconnecting_agent =
        rustctrl_network::connect(&client_config(&pki_dir, &restarted.endpoint, "agent")).await?;
    reconnecting_agent
        .send_heartbeat(HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Workstation Reconnected".into(),
            agent_version: "0.1.1".into(),
        })
        .await?;

    let list_restored = admin_restarted
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(
        list_restored.devices.len(),
        1,
        "exactly one device must be present; no duplicates"
    );
    let restored = &list_restored.devices[0];
    assert_eq!(restored.device_id, device_id.to_string());
    assert_eq!(restored.status, "online");
    assert!(!restored.blocked);

    // 10. Verify activity log records cleanup attempts (allowed and rejected) with actor and device attribution.
    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=clean_offline_device")
            && activity.contains("actor=alice")
            && activity.contains("result=rejected")
            && activity.contains(&device_id.to_string()),
        "activity log must record alice online clean rejection: {activity}"
    );
    assert!(
        activity.contains("action=clean_offline_device")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected")
            && activity.contains(&device_id.to_string()),
        "activity log must record bob clean rejection: {activity}"
    );
    assert!(
        activity.contains("action=clean_offline_device")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&device_id.to_string()),
        "activity log must record alice clean success: {activity}"
    );
    assert!(
        activity.contains("action=update_fleet_device")
            && activity.contains(&device_id.to_string()),
        "historical activity attribution must be preserved: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_device_cleanup_via_controller_cli() -> Result<()> {
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

    // Agent registers device via heartbeat.
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    // Wait until device goes offline (offline_after_secs is 1 second).
    tokio::time::sleep(Duration::from_millis(1_600)).await;

    // Operator Bob cannot clean offline device.
    let op_clean = run_controller(&[
        "clean-offline-device",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        !op_clean.status.success(),
        "operator clean-offline-device must fail: {}",
        String::from_utf8_lossy(&op_clean.stdout)
    );

    // Admin Alice blocks device.
    let admin_block = run_controller(&[
        "block-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(admin_block.status.success());

    // Admin Alice tries to clean blocked device -> fails.
    let admin_clean_blocked = run_controller(&[
        "clean-offline-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        !admin_clean_blocked.status.success(),
        "cleaning blocked device must fail"
    );

    // Admin Alice unblocks device.
    let admin_unblock = run_controller(&[
        "unblock-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(admin_unblock.status.success());

    // Admin Alice cleans offline device -> succeeds!
    let admin_clean = run_controller(&[
        "clean-offline-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &device_id.to_string(),
    ])
    .await;
    assert!(
        admin_clean.status.success(),
        "admin clean-offline-device must succeed: {}",
        String::from_utf8_lossy(&admin_clean.stderr)
    );
    let clean_out = String::from_utf8_lossy(&admin_clean.stdout);
    assert!(
        clean_out.contains("Cleaned offline device ") && clean_out.contains(&device_id.to_string()),
        "unexpected clean output: {clean_out}"
    );

    // Operator Bob lists devices -> device is gone!
    let list_empty = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_empty.status.success());
    let list_out = String::from_utf8_lossy(&list_empty.stdout);
    assert!(
        !list_out.contains(&device_id.to_string()),
        "device must not appear in list-devices after cleanup: {list_out}"
    );

    // Reconnecting Agent sends heartbeat -> restores entry!
    agent_heartbeat(&pki_dir, &server.endpoint, device_id).await?;

    let list_restored = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(list_restored.status.success());
    let restored_out = String::from_utf8_lossy(&list_restored.stdout);
    assert!(
        restored_out.contains(&device_id.to_string()) && restored_out.contains("status=online"),
        "restored device must appear with status=online: {restored_out}"
    );

    server.shutdown().await?;

    // Server outage distinction: when server is down, Controller CLI fails connection rather than reporting fleet offline.
    let outage_cli = run_controller(&[
        "list-devices",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(
        !outage_cli.status.success(),
        "Controller CLI must report connection failure during server outage"
    );

    Ok(())
}

#[tokio::test]
async fn admin_replaces_inventory_entry_after_device_identity_loss_with_preserved_attribution_and_blocks()
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
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    let alice_login = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &alice_login.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;
    let alice_session = login(&mut admin, "alice", "AlicePermanent123!").await?;

    // Create an Operator (Bob) to test access restrictions.
    admin
        .create_staff_account(authorized(
            &alice_session,
            CreateStaffAccountRequest {
                username: "bob".into(),
                role: "operator".into(),
                temporary_password: "BobTemp123!".into(),
            },
        ))
        .await?;
    let bob_login = admin
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &bob_login.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "BobPermanent123!".into(),
            },
        ))
        .await?;
    let mut operator_client = connect(&pki_dir, &server.endpoint).await?;
    let bob_session = login(&mut operator_client, "bob", "BobPermanent123!").await?;

    // 1. Two independently provisioned Agent identities with the SAME hostname/address.
    let prior_id = DeviceId::new();
    let replacement_id = DeviceId::new();
    let agent1_dir = temp.path().join("agent1");
    let agent2_dir = temp.path().join("agent2");
    issue_agent_identity(&pki_dir, &agent1_dir, prior_id)?;
    issue_agent_identity(&pki_dir, &agent2_dir, replacement_id)?;

    // Register prior device (simulating machine before Windows reinstall).
    let mut agent1 =
        rustctrl_network::connect(&agent_config_for_dir(&agent1_dir, &server.endpoint)).await?;
    agent1
        .send_heartbeat(HeartbeatRequest {
            device_id: prior_id.to_string(),
            name: "WORKSTATION-01".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // Admin Alice edits prior device display name and location.
    admin
        .update_fleet_device(authorized(
            &alice_session,
            UpdateFleetDeviceRequest {
                device_id: prior_id.to_string(),
                display_name: "Reception PC".into(),
                location: Some("Floor 1 Reception".into()),
            },
        ))
        .await?;

    // Admin Alice blocks prior device (to verify that block is preserved across replacement).
    admin
        .block_device(authorized(
            &alice_session,
            BlockDeviceRequest {
                device_id: prior_id.to_string(),
            },
        ))
        .await?;

    // Now, Windows is reinstalled on the computer, losing its identity and generating a new Agent identity.
    // The new Agent registers with the SAME hostname ("WORKSTATION-01").
    let mut agent2 =
        rustctrl_network::connect(&agent_config_for_dir(&agent2_dir, &server.endpoint)).await?;
    agent2
        .send_heartbeat(HeartbeatRequest {
            device_id: replacement_id.to_string(),
            name: "WORKSTATION-01".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // 2. Acceptance Criterion: A different valid Device identity creates a distinct entry even when
    // hostname/IP matches a previously known Device. No hardware-fingerprint or hostname/IP auto-merge is introduced.
    let list_distinct = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert_eq!(
        list_distinct.devices.len(),
        2,
        "both prior and replacement devices must exist as distinct entries"
    );
    let dev1_entry = list_distinct
        .devices
        .iter()
        .find(|d| d.device_id == prior_id.to_string())
        .expect("prior device must be listed");
    assert_eq!(dev1_entry.display_name, "Reception PC");
    assert!(dev1_entry.blocked);
    assert_eq!(dev1_entry.status, "blocked");

    let dev2_entry = list_distinct
        .devices
        .iter()
        .find(|d| d.device_id == replacement_id.to_string())
        .expect("replacement device must be listed");
    assert_eq!(dev2_entry.display_name, "WORKSTATION-01");
    assert!(!dev2_entry.blocked);
    assert_eq!(dev2_entry.status, "online");

    // 3. Operator Bob attempts replacement -> MUST fail with permission denied.
    let op_err = operator_client
        .replace_fleet_device(authorized(
            &bob_session,
            ReplaceFleetDeviceRequest {
                prior_device_id: prior_id.to_string(),
                replacement_device_id: replacement_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(op_err.code(), Code::PermissionDenied);

    // 4. Invalid replacement requests by Admin Alice:
    // a. Same device ID -> invalid argument.
    let same_err = admin
        .replace_fleet_device(authorized(
            &alice_session,
            ReplaceFleetDeviceRequest {
                prior_device_id: prior_id.to_string(),
                replacement_device_id: prior_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(same_err.code(), Code::InvalidArgument);

    // b. Non-existent prior device ID -> not found.
    let missing_err = admin
        .replace_fleet_device(authorized(
            &alice_session,
            ReplaceFleetDeviceRequest {
                prior_device_id: DeviceId::new().to_string(),
                replacement_device_id: replacement_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(missing_err.code(), Code::NotFound);

    // c. Connection target as prior or replacement -> failed precondition.
    let target = admin
        .create_target(authorized(
            &alice_session,
            CreateTargetRequest {
                display_name: "Lobby TV".into(),
                address: "192.168.1.55:5555".into(),
                location: None,
                target_type: Some("android_tv".into()),
            },
        ))
        .await?
        .into_inner();
    let target_err = admin
        .replace_fleet_device(authorized(
            &alice_session,
            ReplaceFleetDeviceRequest {
                prior_device_id: target.target.unwrap().device_id,
                replacement_device_id: replacement_id.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(target_err.code(), Code::FailedPrecondition);

    // 5. Admin Alice executes explicit reconciliation replacement operation.
    let replace_reply = admin
        .replace_fleet_device(authorized(
            &alice_session,
            ReplaceFleetDeviceRequest {
                prior_device_id: prior_id.to_string(),
                replacement_device_id: replacement_id.to_string(),
            },
        ))
        .await?
        .into_inner();

    assert_eq!(replace_reply.prior_device_id, prior_id.to_string());
    assert_eq!(
        replace_reply.replacement_device_id,
        replacement_id.to_string()
    );
    let reconciled = replace_reply.device.expect("reconciled device entry");
    assert_eq!(reconciled.device_id, replacement_id.to_string());
    assert_eq!(
        reconciled.display_name, "Reception PC",
        "curated display name must transfer to replacement device"
    );
    assert_eq!(
        reconciled.location.as_deref(),
        Some("Floor 1 Reception"),
        "curated location must transfer"
    );
    assert!(
        reconciled.blocked,
        "Device Block must be preserved on replacement, not silently cleared"
    );
    assert_eq!(reconciled.status, "blocked");

    // 6. Visible Fleet Inventory reconciliation:
    // Only the replacement device is present; the prior device is no longer visible!
    let list_after_replace = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert!(
        !list_after_replace
            .devices
            .iter()
            .any(|d| d.device_id == prior_id.to_string()),
        "prior device must be removed from visible inventory"
    );
    let rep_in_list = list_after_replace
        .devices
        .iter()
        .find(|d| d.device_id == replacement_id.to_string())
        .expect("replacement device must be in inventory");
    assert_eq!(rep_in_list.display_name, "Reception PC");
    assert!(rep_in_list.blocked);

    // 7. Replaced prior agent CANNOT reconnect or send heartbeats!
    let prior_hb_err = agent1
        .send_heartbeat(HeartbeatRequest {
            device_id: prior_id.to_string(),
            name: "WORKSTATION-01".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert!(
        prior_hb_err.message().contains("replaced"),
        "heartbeat from replaced prior device must be rejected: {prior_hb_err}"
    );

    // 8. Unblock the replacement device explicitly via Admin action.
    admin
        .unblock_device(authorized(
            &alice_session,
            UnblockDeviceRequest {
                device_id: replacement_id.to_string(),
            },
        ))
        .await?;

    // Agent 2 sends heartbeat under its own operational identity -> succeeds and updates status to online.
    agent2
        .send_heartbeat(HeartbeatRequest {
            device_id: replacement_id.to_string(),
            name: "WORKSTATION-01".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    let list_unblocked = admin
        .list_fleet_devices(authorized(&alice_session, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    let rep_unblocked = list_unblocked
        .devices
        .iter()
        .find(|d| d.device_id == replacement_id.to_string())
        .unwrap();
    assert_eq!(rep_unblocked.status, "online");
    assert!(!rep_unblocked.blocked);

    // 9. Server restart -> replacement and association persist across Server restart.
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut admin_restarted = connect(&pki_dir, &restarted.endpoint).await?;
    let alice_restarted = login(&mut admin_restarted, "alice", "AlicePermanent123!").await?;

    let list_persisted = admin_restarted
        .list_fleet_devices(authorized(&alice_restarted, ListFleetDevicesRequest {}))
        .await?
        .into_inner();
    assert!(
        !list_persisted
            .devices
            .iter()
            .any(|d| d.device_id == prior_id.to_string()),
        "prior device must remain removed across server restart"
    );
    let rep_persisted = list_persisted
        .devices
        .iter()
        .find(|d| d.device_id == replacement_id.to_string())
        .expect("replacement device must persist across server restart");
    assert_eq!(rep_persisted.display_name, "Reception PC");
    assert_eq!(rep_persisted.location.as_deref(), Some("Floor 1 Reception"));

    // Replaced prior agent heartbeat still rejected after server restart.
    let mut agent1_restarted =
        rustctrl_network::connect(&agent_config_for_dir(&agent1_dir, &restarted.endpoint)).await?;
    let prior_hb_restarted_err = agent1_restarted
        .send_heartbeat(HeartbeatRequest {
            device_id: prior_id.to_string(),
            name: "WORKSTATION-01".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert!(prior_hb_restarted_err.message().contains("replaced"));

    // 10. Verify central activity log records actor, both identities, server time, result, and preserves past attribution.
    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=replace_fleet_device")
            && activity.contains("actor=alice")
            && activity.contains("result=success")
            && activity.contains(&prior_id.to_string())
            && activity.contains(&replacement_id.to_string()),
        "activity log must record alice replace_fleet_device success with both identities: {activity}"
    );
    assert!(
        activity.contains("action=replace_fleet_device")
            && activity.contains("actor=bob")
            && activity.contains("result=rejected"),
        "activity log must record bob replace_fleet_device rejection: {activity}"
    );
    assert!(
        activity.contains("action=update_fleet_device") && activity.contains(&prior_id.to_string()),
        "historical activity attribution for prior_id must be preserved: {activity}"
    );
    assert!(
        !activity.contains("AlicePermanent123!") && !activity.contains("BobPermanent123!"),
        "activity log must not contain credentials or secrets"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_device_replacement_via_controller_cli() -> Result<()> {
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
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    let alice_login = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &alice_login.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;

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

    let prior_id = DeviceId::new();
    let replacement_id = DeviceId::new();
    let agent1_dir = temp.path().join("agent1");
    let agent2_dir = temp.path().join("agent2");
    issue_agent_identity(&pki_dir, &agent1_dir, prior_id)?;
    issue_agent_identity(&pki_dir, &agent2_dir, replacement_id)?;

    // Register prior device and set display name.
    let mut agent1 =
        rustctrl_network::connect(&agent_config_for_dir(&agent1_dir, &server.endpoint)).await?;
    agent1
        .send_heartbeat(HeartbeatRequest {
            device_id: prior_id.to_string(),
            name: "FINANCE-DESKTOP".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    let edit_res = run_controller(&[
        "edit-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--device-id",
        &prior_id.to_string(),
        "--display-name",
        "Finance PC",
        "--location",
        "Floor 2 Finance",
    ])
    .await;
    assert!(edit_res.status.success());

    // Register replacement device with same hostname.
    let mut agent2 =
        rustctrl_network::connect(&agent_config_for_dir(&agent2_dir, &server.endpoint)).await?;
    agent2
        .send_heartbeat(HeartbeatRequest {
            device_id: replacement_id.to_string(),
            name: "FINANCE-DESKTOP".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // Admin replaces device via Controller CLI.
    let replace_res = run_controller(&[
        "replace-device",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--prior-device-id",
        &prior_id.to_string(),
        "--replacement-device-id",
        &replacement_id.to_string(),
    ])
    .await;
    assert!(
        replace_res.status.success(),
        "controller replace-device failed: {}",
        String::from_utf8_lossy(&replace_res.stderr)
    );
    let replace_out = String::from_utf8_lossy(&replace_res.stdout);
    assert!(
        replace_out.contains(&prior_id.to_string())
            && replace_out.contains(&replacement_id.to_string())
            && replace_out.contains("name=Finance PC"),
        "unexpected replace output: {replace_out}"
    );

    // List devices via Controller CLI -> prior is gone, replacement is present with Finance PC.
    let list_res = run_controller(&[
        "list-devices",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(list_res.status.success());
    let list_out = String::from_utf8_lossy(&list_res.stdout);
    assert!(
        !list_out.contains(&prior_id.to_string()),
        "prior device must not appear in list-devices: {list_out}"
    );
    assert!(
        list_out.contains(&replacement_id.to_string()) && list_out.contains("Finance PC"),
        "replacement device must appear in list-devices: {list_out}"
    );

    server.shutdown().await?;
    Ok(())
}
