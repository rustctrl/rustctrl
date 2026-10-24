use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    ChangeOwnPasswordRequest, CreateStaffAccountRequest, LoginRequest,
    ReplaceTemporaryPasswordRequest, ResetStaffPasswordRequest, StaffStatusRequest,
    staff_auth_client::StaffAuthClient,
};
use rustctrl_server::{
    config::{ServerConfig, TlsConfig},
    pki::{PkiOptions, initialize},
    service,
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
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
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        stop.cancel();
        anyhow::bail!("server failed to become healthy");
    }
    async fn shutdown(self) -> Result<()> {
        self.stop.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await???;
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
        })
        .await?
        .into_inner();
    Ok(reply.session_token)
}

// Spawn blocking so the single-threaded test runtime keeps polling the Server.
async fn run_server_cli(exe: &str, config: &Path, args: &[&str]) -> Output {
    let exe = exe.to_string();
    let config = config.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(&exe);
        for arg in &args {
            cmd.arg(arg);
        }
        cmd.arg("--config").arg(&config);
        cmd.output().expect("run rustctrl-server CLI")
    })
    .await
    .expect("join rustctrl-server CLI")
}

async fn bootstrap_admin(exe: &str, config: &Path, username: &str, temp: &str) {
    let output = run_server_cli(
        exe,
        config,
        &[
            "bootstrap-admin",
            "--username",
            username,
            "--temporary-password",
            temp,
        ],
    )
    .await;
    assert!(
        output.status.success(),
        "bootstrap-admin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn list_activity(exe: &str, config: &Path) -> String {
    let output = run_server_cli(exe, config, &["list-activity"]).await;
    assert!(
        output.status.success(),
        "list-activity failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test]
async fn staff_change_own_password_verifies_current_and_keeps_sessions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "alice", "AliceTemp123!").await;

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    // Alice establishes a permanent password.
    let boot = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceTemp123!".into(),
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

    // Two independent sessions for the same account.
    let session_kept = login(&mut admin, "alice", "AlicePermanent123!").await?;
    let session_changer = login(&mut admin, "alice", "AlicePermanent123!").await?;

    // Wrong current password is rejected and recorded without leaking secrets.
    let wrong = admin
        .change_own_password(authorized(
            &session_changer,
            ChangeOwnPasswordRequest {
                current_password: "WrongCurrent123!".into(),
                new_password: "AliceRotated123!".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(wrong.code(), Code::InvalidArgument);

    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=change_own_password") && activity.contains("result=rejected"),
        "must record rejected self-change: {activity}"
    );
    assert!(
        !activity.contains("WrongCurrent123!") && !activity.contains("AlicePermanent123!"),
        "activity must not contain passwords: {activity}"
    );

    // Correct current password changes the password; other sessions stay valid.
    let changed = admin
        .change_own_password(authorized(
            &session_changer,
            ChangeOwnPasswordRequest {
                current_password: "AlicePermanent123!".into(),
                new_password: "AliceRotated123!".into(),
            },
        ))
        .await?
        .into_inner();
    assert!(changed.success);

    let status = admin
        .get_staff_status(authorized(&session_kept, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(status.username, "alice");

    // Previous password no longer signs in; the new one does.
    let old_err = admin
        .login(LoginRequest {
            username: "alice".into(),
            password: "AlicePermanent123!".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(old_err.code(), Code::Unauthenticated);
    let renewed = login(&mut admin, "alice", "AliceRotated123!").await?;
    assert!(!renewed.is_empty());

    // An Operator can change their own password but cannot reset any account.
    let alice_session = login(&mut admin, "alice", "AliceRotated123!").await?;
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
    let bob_session = login(&mut admin, "bob", "BobPermanent123!").await?;

    let bob_change = admin
        .change_own_password(authorized(
            &bob_session,
            ChangeOwnPasswordRequest {
                current_password: "BobPermanent123!".into(),
                new_password: "BobRotated123!".into(),
            },
        ))
        .await?
        .into_inner();
    assert!(bob_change.success);

    let bob_reset = admin
        .reset_staff_password(authorized(
            &bob_session,
            ResetStaffPasswordRequest {
                username: "alice".into(),
                temporary_password: "NotAllowed123!".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        bob_reset.code(),
        Code::PermissionDenied,
        "operator must not reset another account: {bob_reset}"
    );

    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=change_own_password") && activity.contains("result=success"),
        "must record successful self-changes: {activity}"
    );
    assert!(
        activity.contains("actor=bob") && activity.contains("action=reset_staff_password"),
        "must attribute the rejected operator reset: {activity}"
    );
    assert!(
        !activity.contains("AliceRotated123!")
            && !activity.contains("BobRotated123!")
            && !activity.contains("NotAllowed123!"),
        "activity must not contain passwords: {activity}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn admin_reset_ends_all_target_sessions_and_forces_replacement() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
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

    // Bob holds two sessions on separate client channels.
    let mut controller_one = connect(&pki_dir, &server.endpoint).await?;
    let mut controller_two = connect(&pki_dir, &server.endpoint).await?;
    let bob_session_one = login(&mut controller_one, "bob", "BobPermanent123!").await?;
    let bob_session_two = login(&mut controller_two, "bob", "BobPermanent123!").await?;
    assert_ne!(bob_session_one, bob_session_two);
    assert!(
        controller_one
            .get_staff_status(authorized(&bob_session_one, StaffStatusRequest {}))
            .await
            .is_ok()
    );
    assert!(
        controller_two
            .get_staff_status(authorized(&bob_session_two, StaffStatusRequest {}))
            .await
            .is_ok()
    );

    // Resetting an unknown account is reported as not found.
    let ghost = admin
        .reset_staff_password(authorized(
            &alice_session,
            ResetStaffPasswordRequest {
                username: "ghost".into(),
                temporary_password: "GhostTemp123!".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(ghost.code(), Code::NotFound);

    // Alice resets Bob to a temporary password.
    let reset = admin
        .reset_staff_password(authorized(
            &alice_session,
            ResetStaffPasswordRequest {
                username: "bob".into(),
                temporary_password: "BobResetTemp123!".into(),
            },
        ))
        .await?
        .into_inner()
        .account
        .expect("reset account");
    assert_eq!(reset.username, "bob");
    assert_eq!(reset.role, "operator");
    assert!(reset.must_change_password);

    // Both of Bob's sessions die on their already-open channels.
    let dead_one = controller_one
        .get_staff_status(authorized(&bob_session_one, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(dead_one.code(), Code::Unauthenticated);
    let dead_two = controller_two
        .get_staff_status(authorized(&bob_session_two, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(dead_two.code(), Code::Unauthenticated);

    // The previous password no longer signs in; the temporary one is forced.
    let old_err = admin
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobPermanent123!".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(old_err.code(), Code::Unauthenticated);

    let bob_temp = admin
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobResetTemp123!".into(),
        })
        .await?
        .into_inner();
    assert!(bob_temp.must_change_password);
    let restricted = admin
        .get_staff_status(authorized(&bob_temp.session_token, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(
        restricted.code(),
        Code::PermissionDenied,
        "temporary session must be restricted to password replacement: {restricted}"
    );
    admin
        .replace_temporary_password(authorized(
            &bob_temp.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "BobRenewed123!".into(),
            },
        ))
        .await?;
    assert!(
        admin
            .get_staff_status(authorized(&bob_temp.session_token, StaffStatusRequest {}))
            .await
            .is_ok()
    );

    // An Admin resetting their own account also ends their own sessions.
    admin
        .reset_staff_password(authorized(
            &alice_session,
            ResetStaffPasswordRequest {
                username: "alice".into(),
                temporary_password: "AliceResetTemp123!".into(),
            },
        ))
        .await?;
    let alice_dead = admin
        .get_staff_status(authorized(&alice_session, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(alice_dead.code(), Code::Unauthenticated);

    // Revocation and the new credentials survive a Server restart.
    drop(controller_one);
    drop(controller_two);
    drop(admin);
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;

    let revoked_after_restart = client
        .get_staff_status(authorized(&bob_session_one, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(revoked_after_restart.code(), Code::Unauthenticated);

    let alice_temp = client
        .login(LoginRequest {
            username: "alice".into(),
            password: "AliceResetTemp123!".into(),
        })
        .await?
        .into_inner();
    assert!(alice_temp.must_change_password);

    let bob_login = client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobRenewed123!".into(),
        })
        .await?
        .into_inner();
    assert!(!bob_login.must_change_password);

    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=reset_staff_password") && activity.contains("result=success"),
        "must record successful resets: {activity}"
    );
    assert!(
        !activity.contains("BobResetTemp123!")
            && !activity.contains("AliceResetTemp123!")
            && !activity.contains("BobPermanent123!"),
        "activity must not contain passwords: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn local_recover_admin_resets_existing_admin_without_bootstrap_bypass() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "root", "RootTemp1234!").await;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let mut admin = connect(&pki_dir, &server.endpoint).await?;
    let boot = admin
        .login(LoginRequest {
            username: "root".into(),
            password: "RootTemp1234!".into(),
        })
        .await?
        .into_inner();
    admin
        .replace_temporary_password(authorized(
            &boot.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "RootPermanent123!".into(),
            },
        ))
        .await?;
    let root_session = login(&mut admin, "root", "RootPermanent123!").await?;
    admin
        .create_staff_account(authorized(
            &root_session,
            CreateStaffAccountRequest {
                username: "op".into(),
                role: "operator".into(),
                temporary_password: "OperatorTemp123!".into(),
            },
        ))
        .await?;
    drop(admin);
    server.shutdown().await?;

    // Recovery only applies to an existing Admin account.
    let missing = run_server_cli(
        exe,
        &config_path,
        &[
            "recover-admin",
            "--username",
            "ghost",
            "--temporary-password",
            "GhostTemp1234!",
        ],
    )
    .await;
    assert!(
        !missing.status.success(),
        "unknown account must be rejected"
    );
    let missing_err = String::from_utf8_lossy(&missing.stderr);
    assert!(
        missing_err.contains("not found"),
        "stderr should explain the account is unknown: {missing_err}"
    );

    let not_admin = run_server_cli(
        exe,
        &config_path,
        &[
            "recover-admin",
            "--username",
            "op",
            "--temporary-password",
            "OperatorReset123!",
        ],
    )
    .await;
    assert!(
        !not_admin.status.success(),
        "operator account must be rejected by admin recovery"
    );
    let not_admin_err = String::from_utf8_lossy(&not_admin.stderr);
    assert!(
        not_admin_err.contains("not an admin"),
        "stderr should explain only admin accounts qualify: {not_admin_err}"
    );

    let recovered = run_server_cli(
        exe,
        &config_path,
        &[
            "recover-admin",
            "--username",
            "root",
            "--temporary-password",
            "RootRecovery123!",
        ],
    )
    .await;
    assert!(
        recovered.status.success(),
        "recover-admin failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );

    // Recovery is not a second bootstrap: it resets the existing account only.
    let rebootstrap = run_server_cli(
        exe,
        &config_path,
        &[
            "bootstrap-admin",
            "--username",
            "intruder",
            "--temporary-password",
            "IntruderTemp123!",
        ],
    )
    .await;
    assert!(
        !rebootstrap.status.success(),
        "bootstrap must stay rejected after recovery"
    );

    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;

    // The pre-recovery session stays revoked across the restart.
    let revoked = client
        .get_staff_status(authorized(&root_session, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(revoked.code(), Code::Unauthenticated);

    // The previous permanent password no longer signs in.
    let old_err = client
        .login(LoginRequest {
            username: "root".into(),
            password: "RootPermanent123!".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(old_err.code(), Code::Unauthenticated);

    // The temporary password signs in and forces a replacement.
    let recovery_login = client
        .login(LoginRequest {
            username: "root".into(),
            password: "RootRecovery123!".into(),
        })
        .await?
        .into_inner();
    assert!(recovery_login.must_change_password);
    let restricted = client
        .get_staff_status(authorized(
            &recovery_login.session_token,
            StaffStatusRequest {},
        ))
        .await
        .unwrap_err();
    assert_eq!(restricted.code(), Code::PermissionDenied);
    client
        .replace_temporary_password(authorized(
            &recovery_login.session_token,
            ReplaceTemporaryPasswordRequest {
                new_password: "RootRenewed123!".into(),
            },
        ))
        .await?;
    assert!(
        client
            .get_staff_status(authorized(
                &recovery_login.session_token,
                StaffStatusRequest {}
            ))
            .await
            .is_ok()
    );

    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=recover_admin") && activity.contains("actor=local"),
        "must record local recovery: {activity}"
    );
    assert!(
        activity.contains("result=success") && activity.contains("root"),
        "recovery record must name the target: {activity}"
    );
    assert!(
        !activity.contains("RootRecovery123!")
            && !activity.contains("RootPermanent123!")
            && !activity.contains("RootRenewed123!"),
        "activity must not contain passwords: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn controller_cli_changes_and_resets_passwords() -> Result<()> {
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

    // Alice establishes a permanent password, then changes it herself.
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
    assert!(
        bootstrap.status.success(),
        "controller bootstrap failed: {}",
        String::from_utf8_lossy(&bootstrap.stderr)
    );

    let changed = run_controller(&[
        "change-password",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--new-password",
        "AliceRotated123!",
    ])
    .await;
    assert!(
        changed.status.success(),
        "controller change-password failed: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let changed_out = String::from_utf8_lossy(&changed.stdout);
    assert!(
        changed_out.contains("Password changed successfully."),
        "must confirm the change: {changed_out}"
    );
    assert!(
        changed_out.contains("Protected status: authenticated=true"),
        "must prove the session survives a self-change: {changed_out}"
    );

    let old_login = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(
        !old_login.status.success(),
        "previous password must stop signing in"
    );

    let new_login = run_controller(&[
        "login",
        "--username",
        "alice",
        "--password",
        "AliceRotated123!",
    ])
    .await;
    assert!(new_login.status.success());

    // Alice creates Bob and resets his password to a temporary one.
    let created = run_controller(&[
        "create-account",
        "--username",
        "alice",
        "--password",
        "AliceRotated123!",
        "--target-username",
        "bob",
        "--target-role",
        "operator",
        "--temporary-password",
        "BobTemp12345!",
    ])
    .await;
    assert!(
        created.status.success(),
        "controller create-account failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let reset = run_controller(&[
        "reset-password",
        "--username",
        "alice",
        "--password",
        "AliceRotated123!",
        "--target-username",
        "bob",
        "--temporary-password",
        "BobResetTemp123!",
    ])
    .await;
    assert!(
        reset.status.success(),
        "controller reset-password failed: {}",
        String::from_utf8_lossy(&reset.stderr)
    );
    let reset_out = String::from_utf8_lossy(&reset.stdout);
    assert!(
        reset_out.contains("username=bob") && reset_out.contains("temporary=true"),
        "must report the reset account: {reset_out}"
    );

    let bob_old =
        run_controller(&["login", "--username", "bob", "--password", "BobTemp12345!"]).await;
    assert!(
        !bob_old.status.success(),
        "bob's earlier password must stop signing in"
    );

    let bob_temp = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobResetTemp123!",
    ])
    .await;
    assert!(bob_temp.status.success());
    let bob_temp_out = String::from_utf8_lossy(&bob_temp.stdout);
    assert!(
        bob_temp_out.contains("must_change_password=true"),
        "reset login must force replacement: {bob_temp_out}"
    );

    // Bob replaces the temporary password and changes his own afterwards.
    let bob_replace = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobResetTemp123!",
        "--replace-password",
        "BobPermanent123!",
    ])
    .await;
    assert!(bob_replace.status.success());

    let bob_change = run_controller(&[
        "change-password",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
        "--new-password",
        "BobRotated123!",
    ])
    .await;
    assert!(
        bob_change.status.success(),
        "operator self-change failed: {}",
        String::from_utf8_lossy(&bob_change.stderr)
    );

    // An Operator cannot reset another account through the CLI.
    let bob_reset = run_controller(&[
        "reset-password",
        "--username",
        "bob",
        "--password",
        "BobRotated123!",
        "--target-username",
        "bob",
        "--temporary-password",
        "NotPermitted123!",
    ])
    .await;
    assert!(
        !bob_reset.status.success(),
        "operator reset attempt must fail"
    );

    server.shutdown().await?;
    Ok(())
}
