use anyhow::Result;
use rustctrl_core::{ClientConfig, DeviceId};
use rustctrl_protocol::bootstrap::{
    HealthRequest, HeartbeatRequest, bootstrap_client::BootstrapClient,
};
use rustctrl_server::{
    config::{ServerConfig, TlsConfig},
    pki::{PkiOptions, initialize},
    service,
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tonic::{
    Code,
    transport::{Certificate, ClientTlsConfig, Endpoint},
};

fn pki_options(root: &Path, device_id: DeviceId) -> PkiOptions {
    PkiOptions {
        output: root.to_owned(),
        server_output: None,
        server_names: vec!["localhost".into()],
        server_ips: vec!["127.0.0.1".parse().unwrap()],
        endpoint: "https://localhost:9876".into(),
        domain_name: "localhost".into(),
        device_id,
    }
}
fn client(root: &Path, endpoint: &str, role: &str) -> ClientConfig {
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
        let config = client(root, &endpoint, "controller");
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
fn heartbeat(device_id: DeviceId) -> HeartbeatRequest {
    HeartbeatRequest {
        device_id: device_id.to_string(),
        name: "Bootstrap test".into(),
        agent_version: "test".into(),
    }
}

#[tokio::test]
async fn real_tls_identity_checks_and_persistence_survive_server_restart() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("pki");
    let id = DeviceId::new();
    initialize(&pki_options(&root, id))?;
    let db = temp.path().join("state.db");
    let server = RunningServer::start(&root, db.clone()).await?;
    let mut agent = rustctrl_network::connect(&client(&root, &server.endpoint, "agent")).await?;
    assert!(
        agent
            .send_heartbeat(heartbeat(id))
            .await?
            .into_inner()
            .received_at_unix_ms
            > 0
    );
    agent.send_heartbeat(heartbeat(id)).await?;
    assert_eq!(
        agent
            .get_health(HealthRequest {})
            .await?
            .into_inner()
            .registered_devices,
        1
    );

    let denied = agent
        .send_heartbeat(heartbeat(DeviceId::new()))
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied);
    let mut controller =
        rustctrl_network::connect(&client(&root, &server.endpoint, "controller")).await?;
    assert_eq!(
        controller
            .send_heartbeat(heartbeat(id))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        controller
            .get_health(HealthRequest {})
            .await?
            .into_inner()
            .registered_devices,
        1
    );

    // A trusted server CA alone does not grant access without a client certificate.
    let channel = Endpoint::from_shared(server.endpoint.clone())?
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(std::fs::read(
                    root.join("ca/cert.pem"),
                )?)),
        )?
        .connect()
        .await;
    if let Ok(channel) = channel {
        assert!(
            BootstrapClient::new(channel)
                .get_health(HealthRequest {})
                .await
                .is_err()
        );
    }
    let rogue_root = temp.path().join("rogue-pki");
    initialize(&pki_options(&rogue_root, id))?;
    let mut rogue = client(&rogue_root, &server.endpoint, "agent");
    rogue.ca_certificate = root.join("ca/cert.pem");
    if let Ok(mut rogue) = rustctrl_network::connect(&rogue).await {
        assert!(rogue.get_health(HealthRequest {}).await.is_err());
    }
    let mut wrong_name = client(&root, &server.endpoint, "controller");
    wrong_name.domain_name = "not-this-server.invalid".into();
    assert!(rustctrl_network::connect(&wrong_name).await.is_err());

    drop(agent);
    drop(controller);
    server.shutdown().await?;
    let restarted = RunningServer::start(&root, db).await?;
    let mut agent = rustctrl_network::connect(&client(&root, &restarted.endpoint, "agent")).await?;
    assert_eq!(
        agent
            .get_health(HealthRequest {})
            .await?
            .into_inner()
            .registered_devices,
        1
    );
    agent.send_heartbeat(heartbeat(id)).await?;
    assert_eq!(
        agent
            .get_health(HealthRequest {})
            .await?
            .into_inner()
            .registered_devices,
        1
    );
    drop(agent);
    restarted.shutdown().await?;
    Ok(())
}

#[test]
fn bootstrap_never_overwrites_existing_ca_or_client_keys() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let options = pki_options(&temp.path().join("pki"), DeviceId::new());
    initialize(&options)?;
    let key_path = options.output.join("ca/key.pem");
    let before = std::fs::read(&key_path)?;
    assert!(initialize(&options).is_err());
    assert_eq!(before, std::fs::read(key_path)?);
    assert!(
        rustctrl_core::AgentConfig::load(&options.output.join("clients/agent/config.toml")).is_ok()
    );
    assert!(
        rustctrl_core::ControllerConfig::load(
            &options.output.join("clients/controller/config.toml")
        )
        .is_ok()
    );
    Ok(())
}
