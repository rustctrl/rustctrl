use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    CreateStaffAccountRequest, DeactivateStaffAccountRequest, ListStaffAccountsRequest,
    LoginRequest, ReplaceTemporaryPasswordRequest, StaffStatusRequest,
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
            staff_session: Default::default(),
            fleet: Default::default(),
            enrollment: Default::default(),
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
            remember: false,
        })
        .await?
        .into_inner();
    Ok(reply.session_token)
}

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

async fn replace_temporary(
    client: &mut StaffAuthClient<Channel>,
    token: &str,
    new_password: &str,
) -> Result<()> {
    client
        .replace_temporary_password(authorized(
            token,
            ReplaceTemporaryPasswordRequest {
                new_password: new_password.into(),
            },
        ))
        .await?;
    Ok(())
}

#[tokio::test]
async fn deactivation_ends_sessions_blocks_login_and_survives_restart() -> Result<()> {
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
            remember: false,
        })
        .await?
        .into_inner();
    replace_temporary(&mut admin, &boot.session_token, "AlicePermanent123!").await?;
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
    replace_temporary(&mut admin, &bob_boot.session_token, "BobPermanent123!").await?;

    // Bob holds two sessions on separate client channels.
    let mut controller_one = connect(&pki_dir, &server.endpoint).await?;
    let mut controller_two = connect(&pki_dir, &server.endpoint).await?;
    let bob_session_one = login(&mut controller_one, "bob", "BobPermanent123!").await?;
    let bob_session_two = login(&mut controller_two, "bob", "BobPermanent123!").await?;
    assert!(
        controller_one
            .get_staff_status(authorized(&bob_session_one, StaffStatusRequest {}))
            .await
            .is_ok()
    );

    // An Operator cannot deactivate any account.
    let op_attempt = controller_one
        .deactivate_staff_account(authorized(
            &bob_session_one,
            DeactivateStaffAccountRequest {
                username: "alice".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        op_attempt.code(),
        Code::PermissionDenied,
        "operator deactivation must be denied: {op_attempt}"
    );

    // Alice deactivates Bob.
    let deactivated = admin
        .deactivate_staff_account(authorized(
            &alice_session,
            DeactivateStaffAccountRequest {
                username: "bob".into(),
            },
        ))
        .await?
        .into_inner()
        .account
        .expect("deactivated account");
    assert_eq!(deactivated.username, "bob");
    assert!(!deactivated.active);

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

    // Correct credentials no longer sign a deactivated account in.
    let bob_login = admin
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobPermanent123!".into(),
            remember: false,
        })
        .await
        .unwrap_err();
    assert_eq!(bob_login.code(), Code::Unauthenticated);

    // Deactivating an already-deactivated account is rejected.
    let repeat = admin
        .deactivate_staff_account(authorized(
            &alice_session,
            DeactivateStaffAccountRequest {
                username: "bob".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(repeat.code(), Code::FailedPrecondition);

    // Deactivation, revocation, and account identity survive a restart.
    drop(controller_one);
    drop(controller_two);
    drop(admin);
    server.shutdown().await?;
    let restarted = RunningServer::start(&pki_dir, db_path).await?;
    let mut client = connect(&pki_dir, &restarted.endpoint).await?;

    let bob_after_restart = client
        .login(LoginRequest {
            username: "bob".into(),
            password: "BobPermanent123!".into(),
            remember: false,
        })
        .await
        .unwrap_err();
    assert_eq!(bob_after_restart.code(), Code::Unauthenticated);

    let bob_session_after_restart = client
        .get_staff_status(authorized(&bob_session_one, StaffStatusRequest {}))
        .await
        .unwrap_err();
    assert_eq!(bob_session_after_restart.code(), Code::Unauthenticated);

    // Alice keeps her own session and still sees Bob's deactivated record.
    let alice_status = client
        .get_staff_status(authorized(&alice_session, StaffStatusRequest {}))
        .await?
        .into_inner();
    assert_eq!(alice_status.username, "alice");
    let accounts = client
        .list_staff_accounts(authorized(&alice_session, ListStaffAccountsRequest {}))
        .await?
        .into_inner()
        .accounts;
    let bob_entry = accounts
        .iter()
        .find(|acc| acc.username == "bob")
        .expect("deactivated account stays listed");
    assert!(!bob_entry.active);

    let activity = list_activity(exe, &config_path).await;
    assert!(
        activity.contains("action=deactivate_staff_account")
            && activity.contains("result=success")
            && activity.contains("actor=alice"),
        "must record successful deactivation: {activity}"
    );
    assert!(
        activity.contains("result=rejected") && activity.contains("actor=bob"),
        "must record the rejected operator attempt: {activity}"
    );
    assert!(
        !activity.contains("BobPermanent123!") && !activity.contains("AlicePermanent123!"),
        "activity must not contain passwords: {activity}"
    );

    restarted.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mixed_concurrent_demotion_and_deactivation_keep_one_active_admin() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    initialize(&pki_options(&pki_dir))?;
    let config_path = pki_dir.join("server.toml");
    let db_path = temp.path().join("rustctrl.db");
    let exe = env!("CARGO_BIN_EXE_rustctrl-server");

    bootstrap_admin(exe, &config_path, "admin1", "Admin1Temp123!").await;

    let server = RunningServer::start(&pki_dir, db_path).await?;
    let mut admin = connect(&pki_dir, &server.endpoint).await?;

    let boot = admin
        .login(LoginRequest {
            username: "admin1".into(),
            password: "Admin1Temp123!".into(),
            remember: false,
        })
        .await?
        .into_inner();
    replace_temporary(&mut admin, &boot.session_token, "Admin1Permanent123!").await?;
    let session1 = login(&mut admin, "admin1", "Admin1Permanent123!").await?;

    admin
        .create_staff_account(authorized(
            &session1,
            CreateStaffAccountRequest {
                username: "admin2".into(),
                role: "admin".into(),
                temporary_password: "Admin2Temp12345!".into(),
            },
        ))
        .await?;

    // Two active Admins. Concurrently demote admin1 and deactivate admin2.
    let cfg_demote = client_config(&pki_dir, &server.endpoint, "controller");
    let tok_demote = session1.clone();
    let demote = tokio::spawn(async move {
        let mut client = rustctrl_network::connect_staff_auth(&cfg_demote).await?;
        let res = client
            .change_staff_role(authorized(
                &tok_demote,
                rustctrl_protocol::auth::ChangeStaffRoleRequest {
                    username: "admin1".into(),
                    new_role: "operator".into(),
                },
            ))
            .await;
        Ok::<_, anyhow::Error>(res.is_ok())
    });

    let cfg_deactivate = client_config(&pki_dir, &server.endpoint, "controller");
    let tok_deactivate = session1.clone();
    let deactivate = tokio::spawn(async move {
        let mut client = rustctrl_network::connect_staff_auth(&cfg_deactivate).await?;
        let res = client
            .deactivate_staff_account(authorized(
                &tok_deactivate,
                DeactivateStaffAccountRequest {
                    username: "admin2".into(),
                },
            ))
            .await;
        Ok::<_, anyhow::Error>(res.is_ok())
    });

    let demoted = demote.await??;
    let deactivated = deactivate.await??;
    assert!(
        demoted != deactivated,
        "mixed concurrent last-admin changes must not both succeed: demoted={demoted}, deactivated={deactivated}"
    );

    // Exactly one active Admin remains; log in through it and count.
    let accounts = if demoted {
        // admin1 was demoted; admin2 remains the active Admin with its temporary password.
        let boot2 = admin
            .login(LoginRequest {
                username: "admin2".into(),
                password: "Admin2Temp12345!".into(),
                remember: false,
            })
            .await?
            .into_inner();
        replace_temporary(&mut admin, &boot2.session_token, "Admin2Permanent123!").await?;
        let session2 = login(&mut admin, "admin2", "Admin2Permanent123!").await?;
        admin
            .list_staff_accounts(authorized(&session2, ListStaffAccountsRequest {}))
            .await?
            .into_inner()
            .accounts
    } else {
        // admin2 was deactivated; admin1 remains the active Admin.
        admin
            .list_staff_accounts(authorized(&session1, ListStaffAccountsRequest {}))
            .await?
            .into_inner()
            .accounts
    };
    let active_admins = accounts
        .iter()
        .filter(|acc| acc.role == "admin" && acc.active)
        .count();
    assert_eq!(active_admins, 1, "exactly one active admin must remain");

    // Deactivating the remaining active Admin is rejected.
    let remaining = accounts
        .iter()
        .find(|acc| acc.role == "admin" && acc.active)
        .expect("remaining admin");
    let last_admin = if remaining.username == "admin1" {
        admin
            .deactivate_staff_account(authorized(
                &session1,
                DeactivateStaffAccountRequest {
                    username: "admin1".into(),
                },
            ))
            .await
            .unwrap_err()
    } else {
        let boot2 = admin
            .login(LoginRequest {
                username: "admin2".into(),
                password: "Admin2Permanent123!".into(),
                remember: false,
            })
            .await?
            .into_inner();
        let session2 = boot2.session_token.clone();
        admin
            .deactivate_staff_account(authorized(
                &session2,
                DeactivateStaffAccountRequest {
                    username: "admin2".into(),
                },
            ))
            .await
            .unwrap_err()
    };
    assert_eq!(last_admin.code(), Code::FailedPrecondition);
    assert!(
        last_admin.message().contains("last active admin"),
        "error must mention the last active admin: {last_admin}"
    );

    server.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn controller_cli_deactivates_account() -> Result<()> {
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

    // Alice establishes a permanent password and creates Bob.
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

    let created = run_controller(&[
        "create-account",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--target-username",
        "bob",
        "--target-role",
        "operator",
        "--temporary-password",
        "BobTemp12345!",
    ])
    .await;
    assert!(created.status.success());

    let bob_replaced = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobTemp12345!",
        "--replace-password",
        "BobPermanent123!",
    ])
    .await;
    assert!(bob_replaced.status.success());

    // Alice deactivates Bob through the Controller CLI.
    let deactivated = run_controller(&[
        "deactivate-account",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
        "--target-username",
        "bob",
    ])
    .await;
    assert!(
        deactivated.status.success(),
        "controller deactivate-account failed: {}",
        String::from_utf8_lossy(&deactivated.stderr)
    );
    let out = String::from_utf8_lossy(&deactivated.stdout);
    assert!(
        out.contains("username=bob") && out.contains("active=false"),
        "must report the deactivated account: {out}"
    );

    // Bob's credentials no longer sign him in, and the listing keeps his record.
    let bob_login = run_controller(&[
        "login",
        "--username",
        "bob",
        "--password",
        "BobPermanent123!",
    ])
    .await;
    assert!(
        !bob_login.status.success(),
        "deactivated account must not sign in"
    );

    let listed = run_controller(&[
        "list-accounts",
        "--username",
        "alice",
        "--password",
        "AlicePermanent123!",
    ])
    .await;
    assert!(listed.status.success());
    let listed_out = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed_out.contains("username=bob role=operator temporary=false active=false"),
        "listing must keep the deactivated record with its state: {listed_out}"
    );

    server.shutdown().await?;
    Ok(())
}
