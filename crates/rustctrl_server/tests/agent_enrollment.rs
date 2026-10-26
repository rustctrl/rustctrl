use anyhow::Result;
use rustctrl_core::{AgentInstallationArtifact, ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    LoginRequest, PrepareInstallationArtifactRequest, staff_auth_client::StaffAuthClient,
};
use rustctrl_protocol::bootstrap::{
    EnrollAgentReply, EnrollAgentRequest, HealthRequest, HeartbeatRequest,
};
use rustctrl_server::{
    config::{FleetConfig, ServerConfig, TlsConfig},
    password::hash_password,
    pki::{self, PkiOptions},
    service,
    store::DeviceStore,
};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use x509_parser::parse_x509_certificate;

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
            fleet: FleetConfig {
                offline_after_secs: 5,
            },
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
                && client.get_health(HealthRequest {}).await.is_ok()
            {
                return Ok(Self {
                    endpoint,
                    stop,
                    handle,
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        anyhow::bail!("server failed to start within timeout");
    }

    async fn stop(self) -> Result<()> {
        self.stop.cancel();
        self.handle.await?
    }
}

async fn seed_staff(db_path: &Path) -> Result<()> {
    let _store = DeviceStore::open(db_path)?;
    let connection = rusqlite::Connection::open(db_path)?;
    let now = 1700000000000i64;
    let admin_hash = hash_password("AdminPass123!@#")?;
    let op_hash = hash_password("OperatorPass123!@#")?;
    connection.execute(
        "INSERT OR REPLACE INTO staff_accounts (username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, 0, 1, ?4, ?4)",
        rusqlite::params!["admin_alice", "admin", admin_hash, now],
    )?;
    connection.execute(
        "INSERT OR REPLACE INTO staff_accounts (username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, 0, 1, ?4, ?4)",
        rusqlite::params!["op_bob", "operator", op_hash, now],
    )?;
    Ok(())
}

async fn login(
    client: &mut StaffAuthClient<tonic::transport::Channel>,
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

async fn enroll_agent(
    endpoint: &str,
    ca_pem: &str,
    enrollment_cert: &str,
    enrollment_key: &str,
    device_id: DeviceId,
    name: &str,
    secret: &str,
) -> Result<EnrollAgentReply> {
    let mut client = rustctrl_network::connect_from_pem(
        endpoint,
        "localhost",
        ca_pem.as_bytes(),
        enrollment_cert.as_bytes(),
        enrollment_key.as_bytes(),
    )
    .await?;
    let reply = client
        .enroll_agent(EnrollAgentRequest {
            device_id: device_id.to_string(),
            name: name.into(),
            agent_version: "0.1.0".into(),
            installation_secret: secret.into(),
        })
        .await?
        .into_inner();
    Ok(reply)
}

#[tokio::test]
async fn prepare_installation_artifact_enforces_admin_role_and_audit_logging() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let pki_dir = dir.path().join("pki");
    pki::initialize(&pki_options(&pki_dir))?;

    let db_path = dir.path().join("rustctrl.db");
    seed_staff(&db_path).await?;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut staff_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // 1. Operator attempts to prepare installation artifact -> denied.
    let op_token = login(&mut staff_client, "op_bob", "OperatorPass123!@#").await?;
    let mut op_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    op_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {op_token}").parse()?);
    let op_err = staff_client
        .prepare_installation_artifact(op_req)
        .await
        .unwrap_err();
    assert_eq!(op_err.code(), tonic::Code::PermissionDenied);

    // 2. Admin prepares installation artifact -> succeeds.
    let admin_token = login(&mut staff_client, "admin_alice", "AdminPass123!@#").await?;
    let mut admin_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply = staff_client
        .prepare_installation_artifact(admin_req)
        .await?
        .into_inner();

    assert!(!reply.authorization_id.is_empty());
    assert!(!reply.installation_secret.is_empty());
    assert!(!reply.ca_certificate.is_empty());
    assert!(!reply.enrollment_certificate.is_empty());
    assert!(!reply.enrollment_private_key.is_empty());

    // 3. Verify audit log: logs success and rejection, NEVER records the secret!
    let store = DeviceStore::open(&db_path)?;
    let logs = store.list_activity().await?;
    let secret = reply.installation_secret;

    for log in &logs {
        assert!(
            !log.detail.contains(&secret),
            "audit log must NEVER contain the installation secret! Found in log: {:?}",
            log
        );
    }

    assert!(
        logs.iter()
            .any(|l| l.action == "prepare_installation_artifact"
                && l.result == "rejected"
                && l.actor == "op_bob"),
        "rejection of operator must be logged"
    );
    assert!(
        logs.iter()
            .any(|l| l.action == "create_installation_authorization"
                && l.result == "success"
                && l.actor == "admin_alice"),
        "authorization creation must be logged"
    );

    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn agent_enrollment_lifecycle_multiple_devices_and_idempotency() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let pki_dir = dir.path().join("pki");
    let pki_opts = pki_options(&pki_dir);
    let bootstrap_id = pki_opts.device_id;
    pki::initialize(&pki_opts)?;

    let db_path = dir.path().join("rustctrl.db");
    seed_staff(&db_path).await?;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut staff_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // 1. Admin prepares installation artifact
    let admin_token = login(&mut staff_client, "admin_alice", "AdminPass123!@#").await?;
    let mut admin_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply = staff_client
        .prepare_installation_artifact(admin_req)
        .await?
        .into_inner();

    let artifact = AgentInstallationArtifact {
        server_endpoint: server.endpoint.clone(),
        domain_name: "localhost".into(),
        ca_certificate: reply.ca_certificate,
        enrollment_certificate: reply.enrollment_certificate,
        enrollment_private_key: reply.enrollment_private_key,
        authorization_id: reply.authorization_id.clone(),
        installation_secret: reply.installation_secret.clone(),
        created_at_unix_ms: reply.created_at_unix_ms,
    };
    let artifact_path = dir.path().join("installer-artifact.toml");
    artifact.save_to_file(&artifact_path)?;

    // 2. Reject enrollment when client certificate is NOT an enrollment certificate (e.g. controller cert)
    let mut non_enrollment_client = rustctrl_network::connect(&controller_cfg).await?;
    let non_enrollment_err = non_enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: DeviceId::new().to_string(),
            name: "Imposter-PC".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(non_enrollment_err.code(), tonic::Code::PermissionDenied);

    // 3. Enroll Agent 1 with valid enrollment credentials
    let dev1_id = DeviceId::new();
    let enroll1 = enroll_agent(
        &server.endpoint,
        &artifact.ca_certificate,
        &artifact.enrollment_certificate,
        &artifact.enrollment_private_key,
        dev1_id,
        "DESKTOP-ALICE-1",
        &artifact.installation_secret,
    )
    .await?;

    assert_eq!(enroll1.device_id, dev1_id.to_string());

    // Verify Agent 1 certificate binding: SAN must be <device_id>.agent.rustctrl.internal
    let (_, pem) = x509_parser::pem::parse_x509_pem(enroll1.certificate.as_bytes())
        .map_err(|e| anyhow::anyhow!("parse pem: {e}"))?;
    let (_, parsed_cert) =
        parse_x509_certificate(&pem.contents).map_err(|e| anyhow::anyhow!("parse cert: {e}"))?;
    let expected_san = format!("{}.agent.rustctrl.internal", dev1_id);
    let san_ext = parsed_cert.subject_alternative_name().unwrap().unwrap();
    assert!(
        san_ext.value.general_names.iter().any(|gn| match gn {
            x509_parser::extensions::GeneralName::DNSName(name) => *name == expected_san,
            _ => false,
        }),
        "Agent certificate SAN must match <device_id>.agent.rustctrl.internal"
    );

    // 4. Agent 1 sends heartbeat using operational credentials
    let mut agent1_client = rustctrl_network::connect_from_pem(
        &server.endpoint,
        "localhost",
        enroll1.ca_certificate.as_bytes(),
        enroll1.certificate.as_bytes(),
        enroll1.private_key.as_bytes(),
    )
    .await?;
    let hb1 = agent1_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb1.received_at_unix_ms > 0);

    // 5. Resuming enrollment for Agent 1 under the same authorization succeeds (idempotent resumption)
    let mut enrollment_client = rustctrl_network::connect_from_pem(
        &server.endpoint,
        "localhost",
        artifact.ca_certificate.as_bytes(),
        artifact.enrollment_certificate.as_bytes(),
        artifact.enrollment_private_key.as_bytes(),
    )
    .await?;
    let resume1 = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
        })
        .await?
        .into_inner();
    assert_eq!(resume1.device_id, dev1_id.to_string());

    // 5b. Attempting to enroll an existing bootstrap device's ID fails
    let bootstrap_cfg = client_config(&pki_dir, &server.endpoint, "agent");
    let mut bootstrap_client = rustctrl_network::connect(&bootstrap_cfg).await?;
    bootstrap_client
        .send_heartbeat(HeartbeatRequest {
            device_id: bootstrap_id.to_string(),
            name: "BOOTSTRAP-AGENT".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    let steal_bootstrap_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: bootstrap_id.to_string(),
            name: "BOOTSTRAP-STEAL".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(steal_bootstrap_err.code(), tonic::Code::PermissionDenied);

    // 5c. Attempting to enroll Agent 1 under a different authorization fails
    let mut admin_req2 = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req2
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply2 = staff_client
        .prepare_installation_artifact(admin_req2)
        .await?
        .into_inner();

    let diff_auth_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-HIJACK".into(),
            agent_version: "0.1.0".into(),
            installation_secret: reply2.installation_secret,
        })
        .await
        .unwrap_err();
    assert_eq!(diff_auth_err.code(), tonic::Code::PermissionDenied);

    // 6. Enroll Agent 2 from same artifact -> receives distinct DeviceId
    let dev2_id = DeviceId::new();
    let enroll2 = enroll_agent(
        &server.endpoint,
        &artifact.ca_certificate,
        &artifact.enrollment_certificate,
        &artifact.enrollment_private_key,
        dev2_id,
        "DESKTOP-BOB-2",
        &artifact.installation_secret,
    )
    .await?;

    assert_eq!(enroll2.device_id, dev2_id.to_string());
    assert_ne!(dev1_id, dev2_id);

    let mut agent2_client = rustctrl_network::connect_from_pem(
        &server.endpoint,
        "localhost",
        enroll2.ca_certificate.as_bytes(),
        enroll2.certificate.as_bytes(),
        enroll2.private_key.as_bytes(),
    )
    .await?;
    agent2_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev2_id.to_string(),
            name: "DESKTOP-BOB-2".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // 7. Verify Fleet Inventory contains both devices
    let store = DeviceStore::open(&db_path)?;
    let dev1_rec = store.get_device(&dev1_id.to_string()).await?.unwrap();
    assert_eq!(dev1_rec.name, "DESKTOP-ALICE-1");

    let dev2_rec = store.get_device(&dev2_id.to_string()).await?.unwrap();
    assert_eq!(dev2_rec.name, "DESKTOP-BOB-2");

    // 8. Invalid secret rejected
    let invalid_secret_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: DeviceId::new().to_string(),
            name: "Hacker-PC".into(),
            agent_version: "0.1.0".into(),
            installation_secret: "completely-wrong-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(invalid_secret_err.code(), tonic::Code::Unauthenticated);

    // 9. Revoking authorization rejects subsequent enrollment attempts
    let revoked = store
        .revoke_installation_authorization(&reply.authorization_id)
        .await?;
    assert!(revoked);

    let revoked_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: DeviceId::new().to_string(),
            name: "Late-PC".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(revoked_err.code(), tonic::Code::PermissionDenied);

    // 10. Existing enrolled agents continue to operate normally even if auth is revoked
    agent1_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?;

    // 11. Server restart test: Server restarts and enrolled agents continue to heartbeat
    server.stop().await?;

    let server2 = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let mut agent1_restarted_client = rustctrl_network::connect_from_pem(
        &server2.endpoint,
        "localhost",
        enroll1.ca_certificate.as_bytes(),
        enroll1.certificate.as_bytes(),
        enroll1.private_key.as_bytes(),
    )
    .await?;
    let hb_after_restart = agent1_restarted_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb_after_restart.received_at_unix_ms > 0);

    server2.stop().await?;
    Ok(())
}
