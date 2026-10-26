use anyhow::Result;
use rustctrl_agent::{enroll_or_load, run_agent};
use rustctrl_core::{AgentInstallationArtifact, ClientConfig, DeviceId};
use rustctrl_protocol::auth::{LoginRequest, PrepareInstallationArtifactRequest};
use rustctrl_protocol::bootstrap::HealthRequest;
use rustctrl_server::{
    config::{FleetConfig, ServerConfig, TlsConfig},
    password::hash_password,
    pki::{self, PkiOptions},
    service,
    store::DeviceStore,
};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

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

async fn seed_admin(db_path: &Path) -> Result<()> {
    let _store = DeviceStore::open(db_path)?;
    let connection = rusqlite::Connection::open(db_path)?;
    let now = 1700000000000i64;
    let admin_hash = hash_password("AdminPass123!@#")?;
    connection.execute(
        "INSERT OR REPLACE INTO staff_accounts (username, role, password_hash, must_change_password, active, created_at_unix_ms, updated_at_unix_ms) VALUES (?1, ?2, ?3, 0, 1, ?4, ?4)",
        rusqlite::params!["admin_alice", "admin", admin_hash, now],
    )?;
    Ok(())
}

#[tokio::test]
async fn agent_enrolls_from_artifact_and_restarts_cleanly() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let pki_dir = dir.path().join("pki");
    pki::initialize(&pki_options(&pki_dir))?;

    let db_path = dir.path().join("rustctrl.db");
    seed_admin(&db_path).await?;

    let server = RunningServer::start(&pki_dir, db_path.clone()).await?;
    let controller_cfg = client_config(&pki_dir, &server.endpoint, "controller");
    let mut staff_client = rustctrl_network::connect_staff_auth(&controller_cfg).await?;

    // Admin prepares installation artifact
    let admin_login = staff_client
        .login(LoginRequest {
            username: "admin_alice".into(),
            password: "AdminPass123!@#".into(),
            remember: false,
        })
        .await?
        .into_inner();

    let mut admin_req = tonic::Request::new(PrepareInstallationArtifactRequest {});
    admin_req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", admin_login.session_token).parse()?,
    );
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
    let artifact_path = dir.path().join("package-artifact.toml");
    artifact.save_to_file(&artifact_path)?;

    // First agent enrollment
    let agent_dir = dir.path().join("agent");
    let agent_cfg =
        enroll_or_load(&artifact_path, &agent_dir, Some("TEST-AGENT-PC".into()), 5).await?;

    assert_eq!(agent_cfg.name, "TEST-AGENT-PC");
    let dev_id = agent_cfg.device_id;

    // Verify persistent files were written
    assert!(agent_dir.join("config.toml").exists());
    assert!(agent_dir.join("ca.pem").exists());
    assert!(agent_dir.join("cert.pem").exists());
    assert!(agent_dir.join("key.pem").exists());

    // Run agent heartbeat loop once
    let stop = CancellationToken::new();
    run_agent(agent_cfg.clone(), stop.clone(), true).await?;

    // Restart/retry: calling enroll_or_load again reuses the existing configuration
    let restarted_cfg = enroll_or_load(
        &artifact_path,
        &agent_dir,
        Some("NEW-NAME-IGNORED".into()),
        5,
    )
    .await?;

    assert_eq!(restarted_cfg.device_id, dev_id);
    assert_eq!(restarted_cfg.name, "TEST-AGENT-PC");

    // Verify device in server inventory
    let store = DeviceStore::open(&db_path)?;
    let dev = store.get_device(&dev_id.to_string()).await?.unwrap();
    assert_eq!(dev.name, "TEST-AGENT-PC");

    server.stop().await?;
    Ok(())
}
