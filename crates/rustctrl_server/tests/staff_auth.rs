use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    ChangeStaffRoleRequest, CreateStaffAccountRequest, ListStaffAccountsRequest, LoginRequest,
    ReplaceTemporaryPasswordRequest, StaffStatusRequest,
};
use rustctrl_protocol::bootstrap::HealthRequest;
use rustctrl_server::{
    config::{ServerConfig, TlsConfig},
    pki::{PkiOptions, initialize},
    service,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request};

fn pki_options(root: &std::path::Path) -> PkiOptions {
    PkiOptions {
        output: root.to_owned(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id: DeviceId::new(),
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
                && client.get_health(HealthRequest {}).await.is_ok()
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

#[test]
fn bootstrap_admin_creates_initial_admin_and_rejects_repeated_bootstrap() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");

    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // First bootstrap should succeed
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("alice")
        .arg("--temporary-password")
        .arg("TempSecret123!")
        .output()?;

    assert!(
        output.status.success(),
        "bootstrap-admin failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Repeated bootstrap must fail
    let repeated = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("bob")
        .arg("--temporary-password")
        .arg("AnotherTemp456!")
        .output()?;

    assert!(
        !repeated.status.success(),
        "repeated bootstrap-admin should have failed"
    );
    let stderr = String::from_utf8_lossy(&repeated.stderr);
    assert!(
        stderr.contains("already") || stderr.contains("exists"),
        "stderr should explain admin already exists: {stderr}"
    );

    Ok(())
}

#[test]
fn activity_observation_boundary_lists_durable_records_without_secrets() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");

    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // Bootstrap admin
    let temp_pass = "TempSecret999!";
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("carol")
        .arg("--temporary-password")
        .arg(temp_pass)
        .output()?;
    assert!(output.status.success());

    // Observe activity
    let activity_output = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;

    assert!(
        activity_output.status.success(),
        "list-activity failed: stderr={}",
        String::from_utf8_lossy(&activity_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&activity_output.stdout);
    assert!(
        stdout.contains("bootstrap_admin"),
        "stdout must contain action: {stdout}"
    );
    assert!(
        stdout.contains("local"),
        "stdout must contain actor: {stdout}"
    );
    assert!(
        stdout.contains("success"),
        "stdout must contain result: {stdout}"
    );
    assert!(
        stdout.contains("carol"),
        "stdout must contain account name: {stdout}"
    );
    assert!(
        !stdout.contains(temp_pass),
        "stdout must not contain password: {stdout}"
    );
    assert!(
        !stdout.contains("$pbkdf2"),
        "stdout must not contain password hash: {stdout}"
    );

    // Trigger rejected action
    let repeated = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("dan")
        .arg("--temporary-password")
        .arg("AnotherTempPass!")
        .output()?;
    assert!(!repeated.status.success());

    // Observe activity again
    let activity_output2 = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    assert!(activity_output2.status.success());
    let stdout2 = String::from_utf8_lossy(&activity_output2.stdout);
    assert!(
        stdout2.contains("rejected"),
        "stdout must contain rejected record: {stdout2}"
    );
    assert!(
        !stdout2.contains("AnotherTempPass!"),
        "stdout must not contain password: {stdout2}"
    );

    Ok(())
}

#[tokio::test]
async fn staff_login_enforces_temporary_password_restrictions_and_records_activity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");

    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // Bootstrap initial admin
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("alice")
        .arg("--temporary-password")
        .arg("TempSecret123!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let controller_config = client_config(&pki_dir, &server.endpoint, "controller");
    let mut auth_client = rustctrl_network::connect_staff_auth(&controller_config).await?;

    // Calling protected GetStaffStatus without session token should be Unauthenticated
    let err = auth_client
        .get_staff_status(StaffStatusRequest {})
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);

    // Login with wrong password should fail and be recorded
    let login_fail = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "WrongPassword!".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(login_fail.code(), Code::Unauthenticated);

    // Verify activity record shows failed login
    let act_out = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    let act_str = String::from_utf8_lossy(&act_out.stdout);
    assert!(
        act_str.contains("action=login"),
        "must record login action: {act_str}"
    );
    assert!(
        act_str.contains("result=failed"),
        "must record failed login: {act_str}"
    );
    assert!(
        !act_str.contains("WrongPassword!"),
        "must not log password: {act_str}"
    );

    // Login with valid temporary password succeeds
    let login_ok = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "TempSecret123!".into(),
        })
        .await?
        .into_inner();

    assert_eq!(login_ok.username, "alice");
    assert_eq!(login_ok.role, "admin");
    assert!(login_ok.must_change_password);
    assert!(!login_ok.session_token.is_empty());

    // Verify activity record shows success login
    let act_out2 = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    let act_str2 = String::from_utf8_lossy(&act_out2.stdout);
    assert!(
        act_str2.contains("result=success"),
        "must record success login: {act_str2}"
    );
    assert!(
        !act_str2.contains("TempSecret123!"),
        "must not log temp password: {act_str2}"
    );

    // Using temporary session token for protected GetStaffStatus must be PermissionDenied
    let mut req = Request::new(StaffStatusRequest {});
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_ok.session_token).parse()?,
    );
    let status_err = auth_client.get_staff_status(req).await.unwrap_err();
    assert_eq!(
        status_err.code(),
        Code::PermissionDenied,
        "temporary password session cannot access ordinary protected operations: {status_err}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn replace_temporary_password_unblocks_protected_operations_and_updates_credentials()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");

    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // Bootstrap initial admin
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("alice")
        .arg("--temporary-password")
        .arg("InitialTempPass1!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let controller_config = client_config(&pki_dir, &server.endpoint, "controller");
    let mut auth_client = rustctrl_network::connect_staff_auth(&controller_config).await?;

    // Log in with temporary password
    let login_resp = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "InitialTempPass1!".into(),
        })
        .await?
        .into_inner();
    assert!(login_resp.must_change_password);

    // Call ReplaceTemporaryPassword with invalid short password
    let mut short_req = Request::new(rustctrl_protocol::auth::ReplaceTemporaryPasswordRequest {
        new_password: "short".into(),
    });
    short_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_resp.session_token).parse()?,
    );
    let short_err = auth_client
        .replace_temporary_password(short_req)
        .await
        .unwrap_err();
    assert_eq!(short_err.code(), Code::InvalidArgument);

    // Call ReplaceTemporaryPassword with valid permanent password
    let new_pass = "PermanentSecurePass123!";
    let mut valid_req = Request::new(rustctrl_protocol::auth::ReplaceTemporaryPasswordRequest {
        new_password: new_pass.into(),
    });
    valid_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_resp.session_token).parse()?,
    );
    let rep_resp = auth_client
        .replace_temporary_password(valid_req)
        .await?
        .into_inner();
    assert!(rep_resp.success);

    // Activity log must record password replacement without leaking password
    let act_out = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    let act_str = String::from_utf8_lossy(&act_out.stdout);
    assert!(
        act_str.contains("action=replace_temporary_password"),
        "must record action: {act_str}"
    );
    assert!(
        act_str.contains("result=success"),
        "must record success: {act_str}"
    );
    assert!(
        !act_str.contains(new_pass),
        "must not log new password: {act_str}"
    );

    // The existing session token must now be allowed to call GetStaffStatus!
    let mut status_req = Request::new(StaffStatusRequest {});
    status_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_resp.session_token).parse()?,
    );
    let status = auth_client.get_staff_status(status_req).await?.into_inner();
    assert_eq!(status.username, "alice");
    assert_eq!(status.role, "admin");
    assert!(status.authenticated);

    // Login with previous temporary password must now fail
    let old_login_err = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "InitialTempPass1!".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(old_login_err.code(), Code::Unauthenticated);

    // Login with new permanent password must succeed with must_change_password = false
    let new_login = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: new_pass.into(),
        })
        .await?
        .into_inner();
    assert_eq!(new_login.username, "alice");
    assert!(!new_login.must_change_password);

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn logout_invalidates_session_on_open_channel_and_state_survives_server_restart() -> Result<()>
{
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

    // Bootstrap initial admin
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("admin")
        .arg("--temporary-password")
        .arg("InitPass123!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;

    // Agent registers a device
    let agent_cfg = client_config(&pki_dir, &server.endpoint, "agent");
    let mut agent = rustctrl_network::connect(&agent_cfg).await?;
    agent
        .send_heartbeat(rustctrl_protocol::bootstrap::HeartbeatRequest {
            device_id: device_id.to_string(),
            name: "Test Windows PC".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // Controller connects
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut auth_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // Login 1
    let login_1 = auth_client
        .login(LoginRequest {
            username: "admin".into(),
            password: "InitPass123!".into(),
        })
        .await?
        .into_inner();

    // Replace temporary password
    let mut rep_req = Request::new(rustctrl_protocol::auth::ReplaceTemporaryPasswordRequest {
        new_password: "PermanentPass123!".into(),
    });
    rep_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_1.session_token).parse()?,
    );
    auth_client.replace_temporary_password(rep_req).await?;

    // Login 2 (independent session)
    let login_2 = auth_client
        .login(LoginRequest {
            username: "admin".into(),
            password: "PermanentPass123!".into(),
        })
        .await?
        .into_inner();
    assert_ne!(login_1.session_token, login_2.session_token);

    // Logout session 1 over the open channel
    let mut logout_req = Request::new(rustctrl_protocol::auth::LogoutRequest {});
    logout_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_1.session_token).parse()?,
    );
    let logout_resp = auth_client.logout(logout_req).await?.into_inner();
    assert!(logout_resp.success);

    // Subsequent call with session 1 on the SAME open channel MUST fail
    let mut reuse_req = Request::new(StaffStatusRequest {});
    reuse_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_1.session_token).parse()?,
    );
    let reuse_err = auth_client.get_staff_status(reuse_req).await.unwrap_err();
    assert_eq!(reuse_err.code(), Code::Unauthenticated);

    // But session 2 remains valid!
    let mut session_2_req = Request::new(StaffStatusRequest {});
    session_2_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_2.session_token).parse()?,
    );
    let status_2 = auth_client
        .get_staff_status(session_2_req)
        .await?
        .into_inner();
    assert_eq!(status_2.username, "admin");
    assert_eq!(status_2.registered_devices, 1);

    // Shut down server and restart with the SAME database
    drop(agent);
    drop(auth_client);
    server.shutdown().await?;

    let restarted = RunningServer::start(&pki_dir, db_path).await?;

    // Verify existing bootstrap device record survived restart
    let mut agent_restarted =
        rustctrl_network::connect(&client_config(&pki_dir, &restarted.endpoint, "agent")).await?;
    let health = agent_restarted
        .get_health(HealthRequest {})
        .await?
        .into_inner();
    assert_eq!(health.registered_devices, 1);

    // Connect controller to restarted server
    let mut auth_restarted = rustctrl_network::connect_staff_auth(&client_config(
        &pki_dir,
        &restarted.endpoint,
        "controller",
    ))
    .await?;

    // Session 1 remains revoked across restart
    let mut revoked_check = Request::new(StaffStatusRequest {});
    revoked_check.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_1.session_token).parse()?,
    );
    let err_after_restart = auth_restarted
        .get_staff_status(revoked_check)
        .await
        .unwrap_err();
    assert_eq!(err_after_restart.code(), Code::Unauthenticated);

    // Logging in with permanent password succeeds on restarted server
    let login_after_restart = auth_restarted
        .login(LoginRequest {
            username: "admin".into(),
            password: "PermanentPass123!".into(),
        })
        .await?
        .into_inner();
    assert_eq!(login_after_restart.username, "admin");
    assert!(!login_after_restart.must_change_password);

    // Check activity log via observation boundary CLI
    let act_out = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    let act_str = String::from_utf8_lossy(&act_out.stdout);
    assert!(act_str.contains("action=bootstrap_admin"));
    assert!(act_str.contains("action=login"));
    assert!(act_str.contains("action=replace_temporary_password"));
    assert!(act_str.contains("action=logout"));
    assert!(!act_str.contains("InitPass123!"));
    assert!(!act_str.contains("PermanentPass123!"));

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn controller_login_cli_flow_exercises_complete_lifecycle() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
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

    // Bootstrap initial admin
    let output = Command::new(server_exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("admin")
        .arg("--temporary-password")
        .arg("TempPass1234!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path).await?;

    // Update controller config with real server endpoint
    let controller_toml = format!(
        "[server]\nendpoint = \"{}\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        server.endpoint
    );
    std::fs::write(&controller_config_path, controller_toml)?;

    // 1. Initial login with temporary password (without replace)
    let c_exe = controller_exe.clone();
    let c_cfg = controller_config_path.clone();
    let out1 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe)
            .arg("--config")
            .arg(c_cfg)
            .arg("login")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("TempPass1234!")
            .output()
    })
    .await??;

    assert!(
        out1.status.success(),
        "controller login failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let str1 = String::from_utf8_lossy(&out1.stdout);
    assert!(
        str1.contains("must_change_password=true"),
        "must show must_change_password: {str1}"
    );
    assert!(
        str1.contains("temporary password must be replaced"),
        "must warn temp pass: {str1}"
    );

    // 2. Login with temporary password, replace password, check protected status, and logout
    let c_exe2 = controller_exe.clone();
    let c_cfg2 = controller_config_path.clone();
    let out2 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe2)
            .arg("--config")
            .arg(c_cfg2)
            .arg("login")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("TempPass1234!")
            .arg("--replace-password")
            .arg("PermanentPass999!")
            .arg("--logout")
            .output()
    })
    .await??;

    assert!(
        out2.status.success(),
        "controller login+replace failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let str2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        str2.contains("Temporary password successfully replaced."),
        "must show replaced: {str2}"
    );
    assert!(
        str2.contains("Protected status: authenticated=true"),
        "must show protected status: {str2}"
    );
    assert!(str2.contains("Logout success."), "must show logout: {str2}");

    // 3. Login with old temporary password must now fail
    let c_exe3 = controller_exe.clone();
    let c_cfg3 = controller_config_path.clone();
    let out3 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe3)
            .arg("--config")
            .arg(c_cfg3)
            .arg("login")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("TempPass1234!")
            .output()
    })
    .await??;
    assert!(
        !out3.status.success(),
        "login with old password should fail"
    );

    // 4. Login with new permanent password succeeds
    let c_exe4 = controller_exe.clone();
    let c_cfg4 = controller_config_path.clone();
    let out4 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe4)
            .arg("--config")
            .arg(c_cfg4)
            .arg("login")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .output()
    })
    .await??;

    assert!(
        out4.status.success(),
        "login with new password failed: {}",
        String::from_utf8_lossy(&out4.stderr)
    );
    let str4 = String::from_utf8_lossy(&out4.stdout);
    assert!(
        str4.contains("must_change_password=false"),
        "must be permanent pass: {str4}"
    );
    assert!(
        str4.contains("Protected status: authenticated=true"),
        "must show protected status: {str4}"
    );

    // 5. Admin creates account 'tech1' via controller CLI
    let c_exe5 = controller_exe.clone();
    let c_cfg5 = controller_config_path.clone();
    let out5 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe5)
            .arg("--config")
            .arg(c_cfg5)
            .arg("create-account")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .arg("--target-username")
            .arg("tech1")
            .arg("--target-role")
            .arg("operator")
            .arg("--temporary-password")
            .arg("Tech1Temp123!")
            .output()
    })
    .await??;
    assert!(
        out5.status.success(),
        "controller create-account failed: {}",
        String::from_utf8_lossy(&out5.stderr)
    );
    let str5 = String::from_utf8_lossy(&out5.stdout);
    assert!(
        str5.contains("username=tech1 role=operator temporary=true"),
        "must show created account: {str5}"
    );

    // 6. Admin lists accounts via controller CLI
    let c_exe6 = controller_exe.clone();
    let c_cfg6 = controller_config_path.clone();
    let out6 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe6)
            .arg("--config")
            .arg(c_cfg6)
            .arg("list-accounts")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .output()
    })
    .await??;
    assert!(
        out6.status.success(),
        "controller list-accounts failed: {}",
        String::from_utf8_lossy(&out6.stderr)
    );
    let str6 = String::from_utf8_lossy(&out6.stdout);
    assert!(
        str6.contains("username=admin role=admin"),
        "must list admin: {str6}"
    );
    assert!(
        str6.contains("username=tech1 role=operator"),
        "must list tech1: {str6}"
    );

    // 7. Admin changes role of tech1 to admin via controller CLI
    let c_exe7 = controller_exe.clone();
    let c_cfg7 = controller_config_path.clone();
    let out7 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe7)
            .arg("--config")
            .arg(c_cfg7)
            .arg("change-role")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .arg("--target-username")
            .arg("tech1")
            .arg("--new-role")
            .arg("admin")
            .output()
    })
    .await??;
    assert!(
        out7.status.success(),
        "controller change-role failed: {}",
        String::from_utf8_lossy(&out7.stderr)
    );

    // 8. Admin demotes tech1 back to operator via controller CLI
    let c_exe8 = controller_exe.clone();
    let c_cfg8 = controller_config_path.clone();
    let out8 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe8)
            .arg("--config")
            .arg(c_cfg8)
            .arg("change-role")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .arg("--target-username")
            .arg("tech1")
            .arg("--new-role")
            .arg("operator")
            .output()
    })
    .await??;
    assert!(out8.status.success());

    // 9. Admin attempts to demote the last active admin (admin) -> should fail
    let c_exe9 = controller_exe.clone();
    let c_cfg9 = controller_config_path.clone();
    let out9 = tokio::task::spawn_blocking(move || {
        Command::new(c_exe9)
            .arg("--config")
            .arg(c_cfg9)
            .arg("change-role")
            .arg("--username")
            .arg("admin")
            .arg("--password")
            .arg("PermanentPass999!")
            .arg("--target-username")
            .arg("admin")
            .arg("--new-role")
            .arg("operator")
            .output()
    })
    .await??;
    assert!(
        !out9.status.success(),
        "demoting last admin via CLI should fail"
    );
    let stderr9 = String::from_utf8_lossy(&out9.stderr);
    assert!(
        stderr9.contains("last active admin"),
        "stderr should mention last active admin: {stderr9}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_manages_staff_accounts_and_roles_with_operator_and_last_admin_protections()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // 1. Bootstrap initial admin alice
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("alice")
        .arg("--temporary-password")
        .arg("AliceTemp123!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_config = client_config(&pki_dir, &server.endpoint, "controller");
    let mut auth_client = rustctrl_network::connect_staff_auth(&controller_config).await?;

    // 2. Alice logs in and sets permanent password
    let login_alice = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
        })
        .await?
        .into_inner();
    let mut rep_req = Request::new(ReplaceTemporaryPasswordRequest {
        new_password: "AlicePermanent123!".into(),
    });
    rep_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", login_alice.session_token).parse()?,
    );
    auth_client.replace_temporary_password(rep_req).await?;

    let alice_session = auth_client
        .login(LoginRequest {
            username: "alice".into(),
            password: "AlicePermanent123!".into(),
        })
        .await?
        .into_inner()
        .session_token;

    // 3. Alice creates Operator 'bob'
    let mut create_bob_req = Request::new(CreateStaffAccountRequest {
        username: "bob".into(),
        role: "operator".into(),
        temporary_password: "BobTempPassword123!".into(),
    });
    create_bob_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {alice_session}").parse()?);
    let bob_created = auth_client
        .create_staff_account(create_bob_req)
        .await?
        .into_inner()
        .account
        .expect("created account");
    assert_eq!(bob_created.username, "bob");
    assert_eq!(bob_created.role, "operator");
    assert!(bob_created.must_change_password);

    // 4. Alice creates Admin 'charlie'
    let mut create_charlie_req = Request::new(CreateStaffAccountRequest {
        username: "charlie".into(),
        role: "admin".into(),
        temporary_password: "CharlieTempPass123!".into(),
    });
    create_charlie_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {alice_session}").parse()?);
    let charlie_created = auth_client
        .create_staff_account(create_charlie_req)
        .await?
        .into_inner()
        .account
        .expect("created account");
    assert_eq!(charlie_created.username, "charlie");
    assert_eq!(charlie_created.role, "admin");
    assert!(charlie_created.must_change_password);

    // 5. Alice lists accounts
    let mut list_req = Request::new(ListStaffAccountsRequest {});
    list_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {alice_session}").parse()?);
    let accounts = auth_client
        .list_staff_accounts(list_req)
        .await?
        .into_inner()
        .accounts;
    assert_eq!(accounts.len(), 3);
    assert!(
        accounts
            .iter()
            .any(|a| a.username == "alice" && a.role == "admin")
    );
    assert!(
        accounts
            .iter()
            .any(|a| a.username == "bob" && a.role == "operator")
    );
    assert!(
        accounts
            .iter()
            .any(|a| a.username == "charlie" && a.role == "admin")
    );

    // 6. Bob logs in with temporary password. Attempting to list accounts must be denied before changing password
    let bob_login1 = auth_client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobTempPassword123!".into(),
        })
        .await?
        .into_inner();
    assert!(bob_login1.must_change_password);

    let mut list_before_change = Request::new(ListStaffAccountsRequest {});
    list_before_change.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", bob_login1.session_token).parse()?,
    );
    let err_unreplaced = auth_client
        .list_staff_accounts(list_before_change)
        .await
        .unwrap_err();
    assert_eq!(err_unreplaced.code(), Code::PermissionDenied);

    // Bob sets permanent password
    let mut bob_rep = Request::new(ReplaceTemporaryPasswordRequest {
        new_password: "BobPermanentPassword123!".into(),
    });
    bob_rep.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", bob_login1.session_token).parse()?,
    );
    auth_client.replace_temporary_password(bob_rep).await?;

    let bob_session = auth_client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobPermanentPassword123!".into(),
        })
        .await?
        .into_inner()
        .session_token;

    // 7. Bob (Operator) cannot list accounts, create accounts, or change roles
    let mut bob_list = Request::new(ListStaffAccountsRequest {});
    bob_list
        .metadata_mut()
        .insert("authorization", format!("Bearer {bob_session}").parse()?);
    let op_err1 = auth_client.list_staff_accounts(bob_list).await.unwrap_err();
    assert_eq!(op_err1.code(), Code::PermissionDenied);

    let mut bob_create = Request::new(CreateStaffAccountRequest {
        username: "hacker".into(),
        role: "admin".into(),
        temporary_password: "HackerPass123!".into(),
    });
    bob_create
        .metadata_mut()
        .insert("authorization", format!("Bearer {bob_session}").parse()?);
    let op_err2 = auth_client
        .create_staff_account(bob_create)
        .await
        .unwrap_err();
    assert_eq!(op_err2.code(), Code::PermissionDenied);

    let mut bob_role = Request::new(ChangeStaffRoleRequest {
        username: "bob".into(),
        new_role: "admin".into(),
    });
    bob_role
        .metadata_mut()
        .insert("authorization", format!("Bearer {bob_session}").parse()?);
    let op_err3 = auth_client.change_staff_role(bob_role).await.unwrap_err();
    assert_eq!(op_err3.code(), Code::PermissionDenied);

    // Operator can still get staff status
    let mut bob_status = Request::new(StaffStatusRequest {});
    bob_status
        .metadata_mut()
        .insert("authorization", format!("Bearer {bob_session}").parse()?);
    let status_reply = auth_client.get_staff_status(bob_status).await?.into_inner();
    assert_eq!(status_reply.role, "operator");

    // 8. Charlie logs in as Admin
    let charlie_login1 = auth_client
        .login(LoginRequest {
            username: "charlie".into(),
            password: "CharlieTempPass123!".into(),
        })
        .await?
        .into_inner();
    let mut charlie_rep = Request::new(ReplaceTemporaryPasswordRequest {
        new_password: "CharliePermanentPass123!".into(),
    });
    charlie_rep.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", charlie_login1.session_token).parse()?,
    );
    auth_client.replace_temporary_password(charlie_rep).await?;

    let charlie_session = auth_client
        .login(LoginRequest {
            username: "charlie".into(),
            password: "CharliePermanentPass123!".into(),
        })
        .await?
        .into_inner()
        .session_token;

    // Verify Charlie can initially list accounts
    let mut charlie_list = Request::new(ListStaffAccountsRequest {});
    charlie_list.metadata_mut().insert(
        "authorization",
        format!("Bearer {charlie_session}").parse()?,
    );
    assert!(auth_client.list_staff_accounts(charlie_list).await.is_ok());

    // 9. Alice demotes Charlie to Operator
    let mut demote_charlie = Request::new(ChangeStaffRoleRequest {
        username: "charlie".into(),
        new_role: "operator".into(),
    });
    demote_charlie
        .metadata_mut()
        .insert("authorization", format!("Bearer {alice_session}").parse()?);
    let demote_reply = auth_client
        .change_staff_role(demote_charlie)
        .await?
        .into_inner();
    assert_eq!(demote_reply.role, "operator");

    // 10. Role change takes effect immediately on Charlie's existing session!
    let mut charlie_list2 = Request::new(ListStaffAccountsRequest {});
    charlie_list2.metadata_mut().insert(
        "authorization",
        format!("Bearer {charlie_session}").parse()?,
    );
    let charlie_err = auth_client
        .list_staff_accounts(charlie_list2)
        .await
        .unwrap_err();
    assert_eq!(
        charlie_err.code(),
        Code::PermissionDenied,
        "role change must take effect immediately on active session"
    );

    // 11. Alice is now the only active Admin. Demoting Alice must be rejected atomically!
    let mut demote_last_admin = Request::new(ChangeStaffRoleRequest {
        username: "alice".into(),
        new_role: "operator".into(),
    });
    demote_last_admin
        .metadata_mut()
        .insert("authorization", format!("Bearer {alice_session}").parse()?);
    let last_admin_err = auth_client
        .change_staff_role(demote_last_admin)
        .await
        .unwrap_err();
    assert!(
        last_admin_err.code() == Code::FailedPrecondition
            || last_admin_err.code() == Code::PermissionDenied
            || last_admin_err.code() == Code::InvalidArgument
    );
    assert!(
        last_admin_err.message().contains("last active admin"),
        "error must mention last active admin: {last_admin_err}"
    );

    // 12. Shutdown server and restart with the same database
    server.shutdown().await?;

    let server2 = RunningServer::start(&pki_dir, db_path).await?;
    let controller_config2 = client_config(&pki_dir, &server2.endpoint, "controller");
    let mut auth_client2 = rustctrl_network::connect_staff_auth(&controller_config2).await?;

    // Alice logs in again on restarted server
    let alice_login_restarted = auth_client2
        .login(LoginRequest {
            username: "alice".into(),
            password: "AlicePermanent123!".into(),
        })
        .await?
        .into_inner();
    let mut list_restarted = Request::new(ListStaffAccountsRequest {});
    list_restarted.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", alice_login_restarted.session_token).parse()?,
    );
    let accounts_restarted = auth_client2
        .list_staff_accounts(list_restarted)
        .await?
        .into_inner()
        .accounts;
    assert_eq!(accounts_restarted.len(), 3);
    assert!(
        accounts_restarted
            .iter()
            .any(|a| a.username == "alice" && a.role == "admin")
    );
    assert!(
        accounts_restarted
            .iter()
            .any(|a| a.username == "bob" && a.role == "operator")
    );
    assert!(
        accounts_restarted
            .iter()
            .any(|a| a.username == "charlie" && a.role == "operator")
    );

    server2.shutdown().await?;

    // 13. Verify activity observation boundary
    let act_out = Command::new(exe)
        .arg("list-activity")
        .arg("--config")
        .arg(&config_path)
        .output()?;
    assert!(act_out.status.success());
    let act_str = String::from_utf8_lossy(&act_out.stdout);

    assert!(act_str.contains("action=create_staff_account"));
    assert!(act_str.contains("action=change_staff_role"));
    assert!(act_str.contains("result=success"));
    assert!(act_str.contains("result=rejected"));
    assert!(act_str.contains("actor=alice"));
    assert!(act_str.contains("actor=bob"));
    assert!(!act_str.contains("BobTempPassword123!"));
    assert!(!act_str.contains("CharlieTempPass123!"));
    assert!(!act_str.contains("AlicePermanent123!"));

    Ok(())
}

#[tokio::test]
async fn concurrent_demotions_cannot_leave_zero_active_admins() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    // Bootstrap initial admin
    let output = Command::new(exe)
        .arg("bootstrap-admin")
        .arg("--config")
        .arg(&config_path)
        .arg("--username")
        .arg("admin1")
        .arg("--temporary-password")
        .arg("Admin1TempPass123!")
        .output()?;
    assert!(output.status.success());

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let controller_config = client_config(&pki_dir, &server.endpoint, "controller");
    let mut auth_client = rustctrl_network::connect_staff_auth(&controller_config).await?;

    // Admin1 replaces temporary password
    let l1 = auth_client
        .login(LoginRequest {
            username: "admin1".into(),
            password: "Admin1TempPass123!".into(),
        })
        .await?
        .into_inner();
    let mut rep = Request::new(ReplaceTemporaryPasswordRequest {
        new_password: "Admin1PermanentPass123!".into(),
    });
    rep.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", l1.session_token).parse()?,
    );
    auth_client.replace_temporary_password(rep).await?;

    let session1 = auth_client
        .login(LoginRequest {
            username: "admin1".into(),
            password: "Admin1PermanentPass123!".into(),
        })
        .await?
        .into_inner()
        .session_token;

    // Admin1 creates Admin2
    let mut create2 = Request::new(CreateStaffAccountRequest {
        username: "admin2".into(),
        role: "admin".into(),
        temporary_password: "Admin2TempPass123!".into(),
    });
    create2
        .metadata_mut()
        .insert("authorization", format!("Bearer {session1}").parse()?);
    auth_client.create_staff_account(create2).await?;

    // Now there are 2 active Admins: admin1 and admin2.
    // Concurrently attempt to demote admin1 to operator and admin2 to operator.
    let cfg1 = controller_config.clone();
    let tok1 = session1.clone();
    let t1 = tokio::spawn(async move {
        let mut client = rustctrl_network::connect_staff_auth(&cfg1).await?;
        let mut req = Request::new(ChangeStaffRoleRequest {
            username: "admin1".into(),
            new_role: "operator".into(),
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {tok1}").parse()?);
        let res = client.change_staff_role(req).await;
        Ok::<_, anyhow::Error>(res.is_ok())
    });

    let cfg2 = controller_config.clone();
    let tok2 = session1.clone();
    let t2 = tokio::spawn(async move {
        let mut client = rustctrl_network::connect_staff_auth(&cfg2).await?;
        let mut req = Request::new(ChangeStaffRoleRequest {
            username: "admin2".into(),
            new_role: "operator".into(),
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {tok2}").parse()?);
        let res = client.change_staff_role(req).await;
        Ok::<_, anyhow::Error>(res.is_ok())
    });

    let (res1, res2) = tokio::try_join!(t1, t2)?;
    let ok1 = res1?;
    let ok2 = res2?;

    // Exactly one should succeed, and one should fail because the last active admin cannot be demoted!
    assert!(
        (ok1 && !ok2) || (!ok1 && ok2),
        "concurrent demotions must allow at most one admin demotion, ok1={ok1}, ok2={ok2}"
    );

    // Verify there is still at least 1 Admin
    let mut list_req = Request::new(ListStaffAccountsRequest {});
    let admin_count = {
        let accounts = if ok2 {
            // admin2 was demoted, admin1 is still admin!
            list_req
                .metadata_mut()
                .insert("authorization", format!("Bearer {session1}").parse()?);
            auth_client
                .list_staff_accounts(list_req)
                .await?
                .into_inner()
                .accounts
        } else {
            // admin1 was demoted, admin2 is still admin. Login as admin2.
            let l2 = auth_client
                .login(LoginRequest {
                    username: "admin2".into(),
                    password: "Admin2TempPass123!".into(),
                })
                .await?
                .into_inner();
            let mut rep2 = Request::new(ReplaceTemporaryPasswordRequest {
                new_password: "Admin2PermanentPass123!".into(),
            });
            rep2.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", l2.session_token).parse()?,
            );
            auth_client.replace_temporary_password(rep2).await?;
            let s2 = auth_client
                .login(LoginRequest {
                    username: "admin2".into(),
                    password: "Admin2PermanentPass123!".into(),
                })
                .await?
                .into_inner()
                .session_token;
            list_req
                .metadata_mut()
                .insert("authorization", format!("Bearer {s2}").parse()?);
            auth_client
                .list_staff_accounts(list_req)
                .await?
                .into_inner()
                .accounts
        };
        accounts.iter().filter(|a| a.role == "admin").count()
    };
    assert_eq!(admin_count, 1, "exactly one admin must remain");

    server.shutdown().await?;
    Ok(())
}
