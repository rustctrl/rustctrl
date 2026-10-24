use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    CreateStaffAccountRequest, DeactivateStaffAccountRequest, LoginRequest, LogoutRequest,
    ReplaceTemporaryPasswordRequest, ResetStaffPasswordRequest, StaffStatusRequest,
    staff_auth_client::StaffAuthClient,
};
use rustctrl_server::{
    config::{ServerConfig, StaffSessionConfig, TlsConfig},
    pki::{PkiOptions, initialize},
    service,
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request, transport::Channel};

fn pki_options(root: &Path) -> PkiOptions {
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
    async fn start(root: &Path, database: PathBuf, lifetime_secs: u64) -> Result<Self> {
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
            staff_session: StaffSessionConfig {
                remembered_lifetime_secs: lifetime_secs,
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
    remember: bool,
) -> Result<String> {
    let reply = client
        .login(LoginRequest {
            username: username.into(),
            password: password.into(),
            remember,
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

#[tokio::test]
async fn remembered_session_restores_across_restart_and_expires_deterministically() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    // Five-second remembered lifetime keeps the restart inside the window
    // while still expiring quickly for a deterministic assertion.
    let server = RunningServer::start(&pki_dir, db_path.clone(), 5).await?;
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

    let started = Instant::now();
    let remembered = login(&mut admin, "alice", "AlicePermanent123!", true).await?;
    let ordinary = login(&mut admin, "alice", "AlicePermanent123!", false).await?;
    assert_ne!(remembered, ordinary);

    // A second Controller validates the remembered session like any login.
    let mut other = connect(&pki_dir, &server.endpoint).await?;
    assert!(
        other
            .get_staff_status(authorized(&remembered, StaffStatusRequest {}))
            .await
            .is_ok()
    );

    // Restart with the same database: the remembered session survives.
    drop(other);
    drop(admin);
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path, 5).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;
    let restored = client
        .get_staff_status(authorized(&remembered, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(restored.username, "alice");

    // After the configured lifetime the remembered session is gone, while the
    // ordinary session without expiry stays valid; reopening never extended it.
    let remaining = Duration::from_secs(5).saturating_sub(started.elapsed());
    tokio::time::sleep(remaining + Duration::from_millis(600)).await;
    let expired = client
        .get_staff_status(authorized(&remembered, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        expired.code(),
        Code::Unauthenticated,
        "remembered session must expire after the configured lifetime: {expired}"
    );
    assert!(
        client
            .get_staff_status(authorized(&ordinary, StaffStatusRequest {}))
            .await
            .is_ok(),
        "ordinary session has no expiry and must stay valid"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn logout_ends_only_the_current_controller_session() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path, 3_600).await?;
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

    // Two independent remembered sessions on separate Controller channels.
    let mut controller_one = connect(&pki_dir, &server.endpoint).await?;
    let mut controller_two = connect(&pki_dir, &server.endpoint).await?;
    let remembered_one = login(&mut controller_one, "alice", "AlicePermanent123!", true).await?;
    let remembered_two = login(&mut controller_two, "alice", "AlicePermanent123!", true).await?;
    assert_ne!(remembered_one, remembered_two);

    controller_one
        .logout(authorized(&remembered_one, LogoutRequest {}))
        .await?;
    let dead = controller_one
        .get_staff_status(authorized(&remembered_one, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(dead.code(), Code::Unauthenticated);

    // The other Controller keeps working with its own session.
    let alive = controller_two
        .get_staff_status(authorized(&remembered_two, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(alive.username, "alice");

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn reset_and_deactivation_invalidate_remembered_sessions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "carol", "CarolTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path, 3_600).await?;
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    let boot = admin
        .login(LoginRequest {
            username: "carol".into(),
            password: "CarolTemp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "CarolPermanent123!".into(),
            },
        ))
        .await?;
    let carol_session = login(&mut admin, "carol", "CarolPermanent123!", false).await?;

    // Alice holds a remembered session; Carol resets her password.
    admin
        .create_staff_account(authorized(
            &carol_session,
            CreateStaffAccountRequest {
                username: "alice".into(),
                role: "operator".into(),
                temporary_password: "AliceTemp12345!".into(),
            },
        ))
        .await?;
    let alice_boot = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp12345!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &alice_boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "AlicePermanent123!".into(),
            },
        ))
        .await?;
    let alice_remembered = login(&mut admin, "alice", "AlicePermanent123!", true).await?;
    assert!(
        admin
            .get_staff_status(authorized(&alice_remembered, StaffStatusRequest {}))
            .await
            .is_ok()
    );

    admin
        .reset_staff_password(authorized(
            &carol_session,
            ResetStaffPasswordRequest {
                username: "alice".into(),
                temporary_password: "AliceResetTemp123!".into(),
            },
        ))
        .await?;
    let reset_dead = admin
        .get_staff_status(authorized(&alice_remembered, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        reset_dead.code(),
        Code::Unauthenticated,
        "password reset must end remembered sessions without a separate authority"
    );

    // Bob holds a remembered session; Carol deactivates his account.
    admin
        .create_staff_account(authorized(
            &carol_session,
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
    let bob_remembered = login(&mut admin, "bob", "BobPermanent123!", true).await?;

    admin
        .deactivate_staff_account(authorized(
            &carol_session,
            DeactivateStaffAccountRequest {
                username: "bob".into(),
            },
        ))
        .await?;
    let deactivated_dead = admin
        .get_staff_status(authorized(&bob_remembered, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        deactivated_dead.code(),
        Code::Unauthenticated,
        "deactivation must end remembered sessions without a separate authority"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn controller_cli_saves_restores_and_clears_remembered_sessions() -> Result<()> {
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

    bootstrap_admin(server_exe, &config_path, "alice", "AliceTemp123!").await;

    // Session persistence across a Server restart is covered by the gRPC
    // restart test; this flow exercises the Controller process restarting.
    let server = RunningServer::start(&pki_dir, db_path, 3_600).await?;
    let controller_toml = format!(
        "[server]\nendpoint = \"{}\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        server.endpoint
    );
    std::fs::write(&controller_config_path, controller_toml)?;
    let session_path = pki_dir.join("clients/controller/session.toml");

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

    // Without remember, no credential is stored.
    let plain = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AliceTemp123!",
        "--replace-password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(plain.status.success());
    assert!(
        !session_path.exists(),
        "ordinary login must not store a credential"
    );

    // Remembered login stores the token only, never the password.
    let remembered = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--remember",
    ])
    .await;
    assert!(
        remembered.status.success(),
        "remembered login failed: {}",
        String::from_utf8_lossy(&remembered.stderr)
    );
    assert!(session_path.exists(), "saved session file must exist");
    let stored = std::fs::read_to_string(&session_path)?;
    assert!(
        stored.contains("username = \"alice\"") && stored.contains("session_token"),
        "stored credential must name the account and token: {stored}"
    );
    assert!(
        !stored.contains("AlicePermanent123!"),
        "stored credential must not contain the password: {stored}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&session_path)?.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "saved credential must be user-only readable"
        );
    }

    // A fresh Controller process restores the remembered session.
    let restored = run_controller(&["restore-session"]).await;
    assert!(
        restored.status.success(),
        "restore-session failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    let restored_out = String::from_utf8_lossy(&restored.stdout);
    assert!(
        restored_out.contains("Restored session: username=alice role=admin"),
        "restore must report the account: {restored_out}"
    );

    // Invalidating the saved session through the public logout operation means
    // reopening cannot regain access: the credential is refused and removed.
    let token = stored
        .lines()
        .find_map(|line| line.trim().strip_prefix("session_token = "))
        .map(|value| value.trim_matches('"').to_string())
        .expect("session token in saved file");
    let mut api = connect(&pki_dir, &server.endpoint).await?;
    api.logout(authorized(&token, LogoutRequest {})).await?;
    let refused = run_controller(&["restore-session"]).await;
    assert!(
        !refused.status.success(),
        "revoked saved session must not restore"
    );
    let refused_err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused_err.contains("expired or was revoked"),
        "restore must explain the dead credential: {refused_err}"
    );
    assert!(
        !session_path.exists(),
        "dead credential must be removed so reopening cannot retry it"
    );

    // A remembered login followed by logout clears the stored credential.
    let again = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--remember",
        "--logout",
    ])
    .await;
    assert!(again.status.success());
    assert!(
        !session_path.exists(),
        "logout must clear this controller's saved credential"
    );
    let none = run_controller(&["restore-session"]).await;
    assert!(none.status.success());
    assert!(
        String::from_utf8_lossy(&none.stdout).contains("No saved session."),
        "restore must report no saved session: {}",
        String::from_utf8_lossy(&none.stdout)
    );

    server.shutdown().await?;
    Ok(())
}
