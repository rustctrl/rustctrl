use anyhow::Result;
use rustctrl_core::{AgentInstallationArtifact, ClientConfig, DeviceId};
use rustctrl_protocol::auth::{
    BlockDeviceRequest, ListFleetDevicesRequest, ListInstallationAuthorizationsRequest,
    LoginRequest, PrepareInstallationArtifactRequest, RevokeInstallationAuthorizationRequest,
    UpdateFleetDeviceRequest, staff_auth_client::StaffAuthClient,
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
use std::process::Command;
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

#[allow(clippy::too_many_arguments)]
async fn enroll_agent(
    endpoint: &str,
    ca_pem: &str,
    enrollment_cert: &str,
    enrollment_key: &str,
    device_id: DeviceId,
    name: &str,
    secret: &str,
    resumption_secret: &str,
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
            resumption_secret: resumption_secret.into(),
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
async fn revoke_installation_authorization_admin_enforcement_and_audit_logging() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let pki_dir = dir.path().join("pki");
    pki::initialize(&pki_options(&pki_dir))?;

    let db_path = dir.path().join("rustctrl.db");
    seed_staff(&db_path).await?;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut staff_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // 1. Admin prepares an installation artifact (creates authorization A1)
    let admin_token = login(&mut staff_client, "admin_alice", "AdminPass123!@#").await?;
    let mut admin_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply = staff_client
        .prepare_installation_artifact(admin_req)
        .await?
        .into_inner();
    let auth_id = reply.authorization_id;
    let secret = reply.installation_secret;

    // 2. Operator attempts to list installation authorizations -> denied
    let op_token = login(&mut staff_client, "op_bob", "OperatorPass123!@#").await?;
    let mut op_list_req = tonic::Request::new(ListInstallationAuthorizationsRequest {});
    op_list_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {op_token}").parse()?);
    let op_list_err = staff_client
        .list_installation_authorizations(op_list_req)
        .await
        .unwrap_err();
    assert_eq!(op_list_err.code(), tonic::Code::PermissionDenied);

    // 3. Operator attempts to revoke authorization A1 -> denied
    let mut op_revoke_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: auth_id.clone(),
    });
    op_revoke_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {op_token}").parse()?);
    let op_revoke_err = staff_client
        .revoke_installation_authorization(op_revoke_req)
        .await
        .unwrap_err();
    assert_eq!(op_revoke_err.code(), tonic::Code::PermissionDenied);

    // 4. Admin lists installation authorizations -> sees A1 as active
    let mut admin_list_req = tonic::Request::new(ListInstallationAuthorizationsRequest {});
    admin_list_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let list_reply = staff_client
        .list_installation_authorizations(admin_list_req)
        .await?
        .into_inner();
    assert_eq!(list_reply.authorizations.len(), 1);
    let a1 = &list_reply.authorizations[0];
    assert_eq!(a1.authorization_id, auth_id);
    assert_eq!(a1.created_by, "admin_alice");
    assert!(a1.revoked_at_unix_ms.is_none());

    // 5. Admin revokes non-existent authorization -> not found
    let mut not_found_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: "non-existent-auth-id".into(),
    });
    not_found_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let not_found_err = staff_client
        .revoke_installation_authorization(not_found_req)
        .await
        .unwrap_err();
    assert_eq!(not_found_err.code(), tonic::Code::NotFound);

    // 6. Admin revokes authorization A1 -> succeeds
    let mut revoke_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: auth_id.clone(),
    });
    revoke_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let revoke_reply = staff_client
        .revoke_installation_authorization(revoke_req)
        .await?
        .into_inner();
    assert!(revoke_reply.success);
    assert_eq!(revoke_reply.authorization_id, auth_id);
    assert!(revoke_reply.revoked_at_unix_ms > 0);

    // 7. Admin attempts to revoke A1 again -> failed precondition (already revoked)
    let mut repeat_revoke_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: auth_id.clone(),
    });
    repeat_revoke_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let repeat_err = staff_client
        .revoke_installation_authorization(repeat_revoke_req)
        .await
        .unwrap_err();
    assert_eq!(repeat_err.code(), tonic::Code::FailedPrecondition);

    // 8. Admin lists authorizations -> A1 is now revoked
    let mut admin_list_req2 = tonic::Request::new(ListInstallationAuthorizationsRequest {});
    admin_list_req2
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let list_reply2 = staff_client
        .list_installation_authorizations(admin_list_req2)
        .await?
        .into_inner();
    assert_eq!(list_reply2.authorizations.len(), 1);
    assert!(list_reply2.authorizations[0].revoked_at_unix_ms.is_some());

    // 9. Verify audit logs: no secrets logged, rejections logged, success logged
    let store = DeviceStore::open(&db_path)?;
    let logs = store.list_activity().await?;
    for log in &logs {
        assert!(
            !log.detail.contains(&secret),
            "audit log must NEVER contain installation secret! Found: {:?}",
            log
        );
    }
    assert!(
        logs.iter()
            .any(|l| l.action == "revoke_installation_authorization"
                && l.result == "rejected"
                && l.actor == "op_bob"),
        "operator rejection must be logged"
    );
    assert!(
        logs.iter()
            .any(|l| l.action == "revoke_installation_authorization"
                && l.result == "success"
                && l.actor == "admin_alice"),
        "admin revoke success must be logged"
    );

    // 10. Persistence across Server restart
    server.stop().await?;
    let server2 = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg2 = client_config(&pki_dir, &server2.endpoint, "controller");
    let mut staff_client2 = rustctrl_network::connect_staff_auth(&controller_cfg2).await?;
    let admin_token2 = login(&mut staff_client2, "admin_alice", "AdminPass123!@#").await?;

    let mut list_req_restarted = tonic::Request::new(ListInstallationAuthorizationsRequest {});
    list_req_restarted
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token2}").parse()?);
    let list_restarted = staff_client2
        .list_installation_authorizations(list_req_restarted)
        .await?
        .into_inner();
    assert_eq!(list_restarted.authorizations.len(), 1);
    assert!(
        list_restarted.authorizations[0]
            .revoked_at_unix_ms
            .is_some()
    );

    server2.stop().await?;
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
            resumption_secret: "imposter-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(non_enrollment_err.code(), tonic::Code::PermissionDenied);

    // 3. Enroll Agent 1 with valid enrollment credentials
    let dev1_id = DeviceId::new();
    let dev1_resumption_secret = "alice-secret-token-123";
    let enroll1 = enroll_agent(
        &server.endpoint,
        &artifact.ca_certificate,
        &artifact.enrollment_certificate,
        &artifact.enrollment_private_key,
        dev1_id,
        "DESKTOP-ALICE-1",
        &artifact.installation_secret,
        dev1_resumption_secret,
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

    // 5. Resuming enrollment for Agent 1 with matching resumption secret succeeds (idempotent resumption)
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
            resumption_secret: dev1_resumption_secret.into(),
        })
        .await?
        .into_inner();
    assert_eq!(resume1.device_id, dev1_id.to_string());

    // 5a. Attempting to re-enroll Agent 1 with wrong resumption secret fails (imposter cannot hijack)
    let hijack_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-HIJACK".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
            resumption_secret: "hacker-guessed-wrong-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(hijack_err.code(), tonic::Code::PermissionDenied);

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
            resumption_secret: "random-secret".into(),
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
            resumption_secret: dev1_resumption_secret.into(),
        })
        .await
        .unwrap_err();
    assert_eq!(diff_auth_err.code(), tonic::Code::PermissionDenied);

    // 6. Enroll Agent 2 from same artifact -> receives distinct DeviceId
    let dev2_id = DeviceId::new();
    let dev2_resumption_secret = "bob-secret-token-456";
    let enroll2 = enroll_agent(
        &server.endpoint,
        &artifact.ca_certificate,
        &artifact.enrollment_certificate,
        &artifact.enrollment_private_key,
        dev2_id,
        "DESKTOP-BOB-2",
        &artifact.installation_secret,
        dev2_resumption_secret,
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
            resumption_secret: "random-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(invalid_secret_err.code(), tonic::Code::Unauthenticated);

    // 9. Revoking authorization rejects subsequent enrollment attempts for new devices
    let revoked = store
        .revoke_installation_authorization(&reply.authorization_id)
        .await?;
    assert!(matches!(
        revoked,
        rustctrl_server::store::RevokeAuthorizationOutcome::Revoked(_)
    ));

    let revoked_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: DeviceId::new().to_string(),
            name: "Late-PC".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
            resumption_secret: "late-pc-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(revoked_err.code(), tonic::Code::PermissionDenied);

    // 9b. Legitimate Agent 1 with matching resumption secret can still resume after revocation
    let resume_after_revoke = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
            resumption_secret: dev1_resumption_secret.into(),
        })
        .await?
        .into_inner();
    assert_eq!(resume_after_revoke.device_id, dev1_id.to_string());

    // 9c. Imposter with wrong resumption secret fails after revocation
    let imposter_after_revoke_err = enrollment_client
        .enroll_agent(EnrollAgentRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
            installation_secret: artifact.installation_secret.clone(),
            resumption_secret: "wrong-secret".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        imposter_after_revoke_err.code(),
        tonic::Code::PermissionDenied
    );

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

#[tokio::test]
async fn complete_controller_rotation_rejection_replacement_continuity_and_blocked_identity()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let pki_dir = dir.path().join("pki");
    pki::initialize(&pki_options(&pki_dir))?;

    let db_path = dir.path().join("rustctrl.db");
    seed_staff(&db_path).await?;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut staff_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // 1. Admin logs in and prepares package 1 (auth A1)
    let admin_token = login(&mut staff_client, "admin_alice", "AdminPass123!@#").await?;
    let mut admin_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply1 = staff_client
        .prepare_installation_artifact(admin_req)
        .await?
        .into_inner();
    let auth1_id = reply1.authorization_id.clone();
    let auth1_secret = reply1.installation_secret.clone();

    // 2. Enroll Agent 1 and Agent 2 using package 1
    let dev1_id = DeviceId::new();
    let dev1_resumption = "alice-resumption-secret-1";
    let enroll1 = enroll_agent(
        &server.endpoint,
        &reply1.ca_certificate,
        &reply1.enrollment_certificate,
        &reply1.enrollment_private_key,
        dev1_id,
        "DESKTOP-ALICE-1",
        &auth1_secret,
        dev1_resumption,
    )
    .await?;

    let dev2_id = DeviceId::new();
    let dev2_resumption = "bob-resumption-secret-2";
    let enroll2 = enroll_agent(
        &server.endpoint,
        &reply1.ca_certificate,
        &reply1.enrollment_certificate,
        &reply1.enrollment_private_key,
        dev2_id,
        "DESKTOP-BOB-2",
        &auth1_secret,
        dev2_resumption,
    )
    .await?;

    // Operational client for Agent 1 sends heartbeat
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

    // Operational client for Agent 2 sends heartbeat
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

    // 3. Admin blocks Agent 2
    let mut block_req = tonic::Request::new(BlockDeviceRequest {
        device_id: dev2_id.to_string(),
    });
    block_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    staff_client.block_device(block_req).await?;

    // Heartbeat from blocked Agent 2 is refused
    let hb2_err = agent2_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev2_id.to_string(),
            name: "DESKTOP-BOB-2".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(hb2_err.code(), tonic::Code::PermissionDenied);

    // 4. Operator denial cases: Operator cannot revoke or prepare package
    let op_token = login(&mut staff_client, "op_bob", "OperatorPass123!@#").await?;
    let mut op_revoke_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: auth1_id.clone(),
    });
    op_revoke_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {op_token}").parse()?);
    let op_revoke_err = staff_client
        .revoke_installation_authorization(op_revoke_req)
        .await
        .unwrap_err();
    assert_eq!(op_revoke_err.code(), tonic::Code::PermissionDenied);

    let mut op_prepare_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    op_prepare_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {op_token}").parse()?);
    let op_prepare_err = staff_client
        .prepare_installation_artifact(op_prepare_req)
        .await
        .unwrap_err();
    assert_eq!(op_prepare_err.code(), tonic::Code::PermissionDenied);

    // 5. Admin revokes authorization A1
    let mut admin_revoke_req = tonic::Request::new(RevokeInstallationAuthorizationRequest {
        authorization_id: auth1_id.clone(),
    });
    admin_revoke_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let revoke_reply = staff_client
        .revoke_installation_authorization(admin_revoke_req)
        .await?
        .into_inner();
    assert!(revoke_reply.success);
    assert_eq!(revoke_reply.authorization_id, auth1_id);

    // 6. Admin prepares replacement package 2 (auth A2) using existing creation flow
    let mut admin_replace_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_replace_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let reply2 = staff_client
        .prepare_installation_artifact(admin_replace_req)
        .await?
        .into_inner();
    let auth2_id = reply2.authorization_id.clone();
    let auth2_secret = reply2.installation_secret.clone();
    assert_ne!(auth1_id, auth2_id);

    // 7. New Agent 3 attempting to enroll with revoked A1 is refused
    let dev3_id = DeviceId::new();
    let enroll3_err = enroll_agent(
        &server.endpoint,
        &reply1.ca_certificate,
        &reply1.enrollment_certificate,
        &reply1.enrollment_private_key,
        dev3_id,
        "DESKTOP-CHARLIE-3",
        &auth1_secret,
        "charlie-resumption-3",
    )
    .await
    .unwrap_err();
    assert_eq!(
        enroll3_err.downcast_ref::<tonic::Status>().unwrap().code(),
        tonic::Code::PermissionDenied
    );

    // 8. Blocked Device 2 remains blocked across rotation:
    // - Attempting to enroll Device 2 under replacement authority A2 fails
    let enroll_blocked_err = enroll_agent(
        &server.endpoint,
        &reply2.ca_certificate,
        &reply2.enrollment_certificate,
        &reply2.enrollment_private_key,
        dev2_id,
        "DESKTOP-BOB-2",
        &auth2_secret,
        dev2_resumption,
    )
    .await
    .unwrap_err();
    assert_eq!(
        enroll_blocked_err
            .downcast_ref::<tonic::Status>()
            .unwrap()
            .code(),
        tonic::Code::PermissionDenied
    );

    // - Operational heartbeat from blocked Device 2 is still refused
    let hb2_blocked_err = agent2_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev2_id.to_string(),
            name: "DESKTOP-BOB-2".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(hb2_blocked_err.code(), tonic::Code::PermissionDenied);

    // - Fleet inventory still lists Device 2 as blocked
    let mut list_devices_req = tonic::Request::new(ListFleetDevicesRequest {});
    list_devices_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let fleet_reply = staff_client
        .list_fleet_devices(list_devices_req)
        .await?
        .into_inner();
    let dev2_entry = fleet_reply
        .devices
        .iter()
        .find(|d| d.device_id == dev2_id.to_string())
        .expect("blocked device 2 must still be visible in inventory");
    assert!(dev2_entry.blocked);
    assert_eq!(dev2_entry.status, "blocked");

    let dev1_entry = fleet_reply
        .devices
        .iter()
        .find(|d| d.device_id == dev1_id.to_string())
        .expect("enrolled device 1 must remain visible in fleet inventory");
    assert!(!dev1_entry.blocked);
    assert_eq!(dev1_entry.display_name, "DESKTOP-ALICE-1");

    // Unrelated inventory operation (e.g. updating device metadata) must NOT unblock Device 2
    let mut update_req = tonic::Request::new(UpdateFleetDeviceRequest {
        device_id: dev2_id.to_string(),
        display_name: "DESKTOP-BOB-2-RENAMED".into(),
        location: Some("Branch-Office".into()),
    });
    update_req
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let updated_dev2 = staff_client
        .update_fleet_device(update_req)
        .await?
        .into_inner();
    assert!(
        updated_dev2.device.unwrap().blocked,
        "inventory operation must preserve device block"
    );

    let mut list_devices_req2 = tonic::Request::new(ListFleetDevicesRequest {});
    list_devices_req2
        .metadata_mut()
        .insert("authorization", format!("Bearer {admin_token}").parse()?);
    let fleet_reply2 = staff_client
        .list_fleet_devices(list_devices_req2)
        .await?
        .into_inner();
    let dev2_entry2 = fleet_reply2
        .devices
        .iter()
        .find(|d| d.device_id == dev2_id.to_string())
        .expect("device 2 must remain in inventory");
    assert!(dev2_entry2.blocked);
    assert_eq!(dev2_entry2.status, "blocked");
    assert_eq!(dev2_entry2.display_name, "DESKTOP-BOB-2-RENAMED");

    // 9. Existing Agent 1 (enrolled under revoked A1) retains credentials and operational access
    let hb1_continuity = agent1_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb1_continuity.received_at_unix_ms > 0);

    // 10. New distinct Agent 4 enrolls with replacement authority A2 -> succeeds
    let dev4_id = DeviceId::new();
    let enroll4 = enroll_agent(
        &server.endpoint,
        &reply2.ca_certificate,
        &reply2.enrollment_certificate,
        &reply2.enrollment_private_key,
        dev4_id,
        "DESKTOP-DAVE-4",
        &auth2_secret,
        "dave-resumption-4",
    )
    .await?;
    assert_eq!(enroll4.device_id, dev4_id.to_string());
    assert_ne!(dev4_id, dev1_id);
    assert_ne!(dev4_id, dev2_id);

    let mut agent4_client = rustctrl_network::connect_from_pem(
        &server.endpoint,
        "localhost",
        enroll4.ca_certificate.as_bytes(),
        enroll4.certificate.as_bytes(),
        enroll4.private_key.as_bytes(),
    )
    .await?;
    let hb4 = agent4_client
        .send_heartbeat(HeartbeatRequest {
            device_id: dev4_id.to_string(),
            name: "DESKTOP-DAVE-4".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb4.received_at_unix_ms > 0);

    // 11. Server restart verification
    server.stop().await?;
    let server2 = RunningServer::start(&pki_dir, db_path.clone()).await?;

    // Agent 1 still works after restart
    let mut agent1_restarted = rustctrl_network::connect_from_pem(
        &server2.endpoint,
        "localhost",
        enroll1.ca_certificate.as_bytes(),
        enroll1.certificate.as_bytes(),
        enroll1.private_key.as_bytes(),
    )
    .await?;
    let hb1_post_restart = agent1_restarted
        .send_heartbeat(HeartbeatRequest {
            device_id: dev1_id.to_string(),
            name: "DESKTOP-ALICE-1".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb1_post_restart.received_at_unix_ms > 0);

    // Agent 4 still works after restart
    let mut agent4_restarted = rustctrl_network::connect_from_pem(
        &server2.endpoint,
        "localhost",
        enroll4.ca_certificate.as_bytes(),
        enroll4.certificate.as_bytes(),
        enroll4.private_key.as_bytes(),
    )
    .await?;
    let hb4_post_restart = agent4_restarted
        .send_heartbeat(HeartbeatRequest {
            device_id: dev4_id.to_string(),
            name: "DESKTOP-DAVE-4".into(),
            agent_version: "0.1.0".into(),
        })
        .await?
        .into_inner();
    assert!(hb4_post_restart.received_at_unix_ms > 0);

    // Blocked Device 2 remains blocked after restart
    let mut agent2_restarted = rustctrl_network::connect_from_pem(
        &server2.endpoint,
        "localhost",
        enroll2.ca_certificate.as_bytes(),
        enroll2.certificate.as_bytes(),
        enroll2.private_key.as_bytes(),
    )
    .await?;
    let hb2_post_restart_err = agent2_restarted
        .send_heartbeat(HeartbeatRequest {
            device_id: dev2_id.to_string(),
            name: "DESKTOP-BOB-2".into(),
            agent_version: "0.1.0".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(hb2_post_restart_err.code(), tonic::Code::PermissionDenied);

    // Enrolling with revoked A1 after restart still fails
    let dev5_id = DeviceId::new();
    let enroll5_post_restart_err = enroll_agent(
        &server2.endpoint,
        &reply1.ca_certificate,
        &reply1.enrollment_certificate,
        &reply1.enrollment_private_key,
        dev5_id,
        "DESKTOP-EVE-5",
        &auth1_secret,
        "eve-resumption-5",
    )
    .await
    .unwrap_err();
    assert_eq!(
        enroll5_post_restart_err
            .downcast_ref::<tonic::Status>()
            .unwrap()
            .code(),
        tonic::Code::PermissionDenied
    );

    // Enrolling with replacement A2 after restart succeeds
    let dev6_id = DeviceId::new();
    let enroll6 = enroll_agent(
        &server2.endpoint,
        &reply2.ca_certificate,
        &reply2.enrollment_certificate,
        &reply2.enrollment_private_key,
        dev6_id,
        "DESKTOP-FRANK-6",
        &auth2_secret,
        "frank-resumption-6",
    )
    .await?;
    assert_eq!(enroll6.device_id, dev6_id.to_string());

    // 12. Non-secret activity records verification
    let store = DeviceStore::open(&db_path)?;
    let logs = store.list_activity().await?;
    for log in &logs {
        assert!(
            !log.detail.contains(&auth1_secret) && !log.detail.contains(&auth2_secret),
            "Secrets must never appear in activity logs! Found: {:?}",
            log
        );
    }

    server2.stop().await?;
    Ok(())
}

#[tokio::test]
async fn controller_cli_lists_and_revokes_installation_authorizations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let pki_dir = temp.path().join("pki");
    pki::initialize(&pki_options(&pki_dir))?;
    let controller_config_path = pki_dir.join("clients/controller/config.toml");
    let db_path = temp.path().join("rustctrl.db");
    seed_staff(&db_path).await?;

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

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
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

    // 1. Prepare installation artifact A1
    let artifact1_path = temp.path().join("artifact1.toml");
    let prep_output = run_controller(&[
        "prepare-installation-artifact",
        "--username",
        "admin_alice",
        "--password",
        "AdminPass123!@#",
        "--output",
        artifact1_path.to_str().unwrap(),
    ])
    .await;
    assert!(
        prep_output.status.success(),
        "prepare artifact must succeed"
    );

    let artifact1 = AgentInstallationArtifact::load_from_file(&artifact1_path)?;
    let auth1_id = artifact1.authorization_id.clone();

    // 2. List installation authorizations -> sees A1 active
    let list_output = run_controller(&[
        "list-installation-authorizations",
        "--username",
        "admin_alice",
        "--password",
        "AdminPass123!@#",
    ])
    .await;
    assert!(list_output.status.success());
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    assert!(list_stdout.contains(&auth1_id));
    assert!(list_stdout.contains("status=active"));

    // 3. Operator attempting to revoke fails
    let op_revoke_output = run_controller(&[
        "revoke-installation-authorization",
        "--username",
        "op_bob",
        "--password",
        "OperatorPass123!@#",
        "--authorization-id",
        &auth1_id,
    ])
    .await;
    assert!(!op_revoke_output.status.success());

    // 4. Admin revokes A1 and specifies replacement output
    let artifact2_path = temp.path().join("artifact2.toml");
    let revoke_replace_output = run_controller(&[
        "revoke-installation-authorization",
        "--username",
        "admin_alice",
        "--password",
        "AdminPass123!@#",
        "--authorization-id",
        &auth1_id,
        "--replace-output",
        artifact2_path.to_str().unwrap(),
    ])
    .await;
    assert!(
        revoke_replace_output.status.success(),
        "revoke and replace must succeed: {}",
        String::from_utf8_lossy(&revoke_replace_output.stderr)
    );
    let revoke_stdout = String::from_utf8_lossy(&revoke_replace_output.stdout);
    assert!(revoke_stdout.contains(&format!("revoked authorization_id={auth1_id}")));

    let artifact2 = AgentInstallationArtifact::load_from_file(&artifact2_path)?;
    let auth2_id = artifact2.authorization_id.clone();
    assert_ne!(auth1_id, auth2_id);

    // 5. List installation authorizations -> A1 is revoked, A2 is active
    let list_output2 = run_controller(&[
        "list-installation-authorizations",
        "--username",
        "admin_alice",
        "--password",
        "AdminPass123!@#",
    ])
    .await;
    assert!(list_output2.status.success());
    let list_stdout2 = String::from_utf8_lossy(&list_output2.stdout);
    assert!(list_stdout2.contains(&format!("authorization_id={auth1_id}")));
    assert!(list_stdout2.contains("status=revoked"));
    assert!(list_stdout2.contains(&format!("authorization_id={auth2_id}")));
    assert!(list_stdout2.contains("status=active"));

    server.stop().await?;
    Ok(())
}
