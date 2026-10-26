use anyhow::Result;
use rustctrl_core::{AgentConfig, AgentInstallationArtifact, DeviceId};
use rustctrl_protocol::bootstrap::{EnrollAgentRequest, HeartbeatRequest};
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
pub mod service;

/// Runtime options for running the Agent as a Windows Service or service daemon.
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    pub config: Option<std::path::PathBuf>,
    pub artifact: Option<std::path::PathBuf>,
    pub target_dir: std::path::PathBuf,
    pub name: Option<String>,
    pub heartbeat_seconds: u64,
}

impl ServiceOptions {
    pub async fn load_or_enroll(&self, stop: CancellationToken) -> Result<AgentConfig> {
        let config_path = self
            .config
            .clone()
            .unwrap_or_else(|| self.target_dir.join("config.toml"));
        if config_path.exists() {
            tracing::info!(path = %config_path.display(), "using existing agent configuration");
            return AgentConfig::load(&config_path);
        }

        let artifact_path = self
            .artifact
            .clone()
            .unwrap_or_else(|| self.target_dir.join("artifact.toml"));
        if !artifact_path.exists() {
            anyhow::bail!(
                "neither agent configuration ({}) nor installation artifact ({}) was found",
                config_path.display(),
                artifact_path.display()
            );
        }

        tracing::info!(
            artifact = %artifact_path.display(),
            target_dir = %self.target_dir.display(),
            "starting automatic agent enrollment"
        );

        let mut retry_delay = Duration::from_secs(2);
        loop {
            tokio::select! {
                _ = stop.cancelled() => anyhow::bail!("enrollment cancelled during service shutdown"),
                res = enroll_or_load(&artifact_path, &self.target_dir, self.name.clone(), self.heartbeat_seconds) => {
                    match res {
                        Ok(cfg) => return Ok(cfg),
                        Err(err) => {
                            tracing::warn!(%err, retry_secs = retry_delay.as_secs(), "enrollment attempt failed; retrying");
                        }
                    }
                }
            }

            tokio::select! {
                _ = stop.cancelled() => anyhow::bail!("enrollment cancelled during service shutdown"),
                _ = tokio::time::sleep(retry_delay) => {}
            }
            retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
        }
    }
}

fn write_pending_enrollment(path: &Path, id: DeviceId, secret: &str) -> Result<()> {
    let body = format!("{id}\n{secret}\n");
    std::fs::write(path, body.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub async fn enroll_or_load(
    artifact_path: &Path,
    target_dir: &Path,
    name: Option<String>,
    heartbeat_seconds: u64,
) -> Result<AgentConfig> {
    anyhow::ensure!(
        (1..=3600).contains(&heartbeat_seconds),
        "heartbeat_seconds must be between 1 and 3600"
    );

    let config_path = target_dir.join("config.toml");
    if config_path.exists() {
        tracing::info!(path = %config_path.display(), "using existing agent configuration");
        return AgentConfig::load(&config_path);
    }

    let artifact = AgentInstallationArtifact::load_from_file(artifact_path)?;
    let pending_file = target_dir.join(".pending_enrollment");
    let legacy_pending_id_path = target_dir.join(".pending_device_id");
    let (device_id, resumption_secret) = if pending_file.exists() {
        let content = std::fs::read_to_string(&pending_file)?;
        let mut lines = content.lines();
        let id_str = lines.next().unwrap_or("").trim();
        let id = id_str.parse::<DeviceId>()?;
        let secret = match lines.next().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => s.to_string(),
            None => {
                let s = uuid::Uuid::new_v4().to_string();
                write_pending_enrollment(&pending_file, id, &s)?;
                s
            }
        };
        (id, secret)
    } else if legacy_pending_id_path.exists() {
        let content = std::fs::read_to_string(&legacy_pending_id_path)?;
        let id = content.trim().parse::<DeviceId>()?;
        let secret = uuid::Uuid::new_v4().to_string();
        write_pending_enrollment(&pending_file, id, &secret)?;
        let _ = std::fs::remove_file(&legacy_pending_id_path);
        (id, secret)
    } else {
        std::fs::create_dir_all(target_dir)?;
        let id = DeviceId::new();
        let secret = uuid::Uuid::new_v4().to_string();
        write_pending_enrollment(&pending_file, id, &secret)?;
        (id, secret)
    };

    let computer_name = name
        .filter(|n| !n.trim().is_empty())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "Windows PC".into());

    tracing::info!(
        device_id = %device_id,
        name = %computer_name,
        authorization_id = %artifact.authorization_id,
        "enrolling agent with controller"
    );

    let mut client = rustctrl_network::connect_from_pem(
        &artifact.server_endpoint,
        &artifact.domain_name,
        artifact.ca_certificate.as_bytes(),
        artifact.enrollment_certificate.as_bytes(),
        artifact.enrollment_private_key.as_bytes(),
    )
    .await?;

    let req = EnrollAgentRequest {
        device_id: device_id.to_string(),
        name: computer_name.clone(),
        agent_version: env!("CARGO_PKG_VERSION").into(),
        installation_secret: artifact.installation_secret,
        resumption_secret,
    };

    let reply = client.enroll_agent(req).await?.into_inner();

    std::fs::create_dir_all(target_dir)?;

    let ca_path = target_dir.join("ca.pem");
    let cert_path = target_dir.join("cert.pem");
    let key_path = target_dir.join("key.pem");

    std::fs::write(&ca_path, reply.ca_certificate.as_bytes())?;
    std::fs::write(&cert_path, reply.certificate.as_bytes())?;
    std::fs::write(&key_path, reply.private_key.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    let agent_config = AgentConfig {
        device_id,
        name: computer_name,
        heartbeat_seconds,
        log_file: std::path::PathBuf::from("agent.log"),
        server: rustctrl_core::ClientConfig {
            endpoint: artifact.server_endpoint,
            domain_name: artifact.domain_name,
            ca_certificate: std::path::PathBuf::from("ca.pem"),
            certificate: std::path::PathBuf::from("cert.pem"),
            private_key: std::path::PathBuf::from("key.pem"),
        },
    };
    agent_config.save(&config_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = std::fs::remove_file(&pending_file);
    let _ = std::fs::remove_file(&legacy_pending_id_path);

    tracing::info!(
        device_id = %device_id,
        config_path = %config_path.display(),
        "enrollment successful; saved operational credentials"
    );

    AgentConfig::load(&config_path)
}

pub async fn run_agent(config: AgentConfig, stop: CancellationToken, once: bool) -> Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let attempt: Result<()> = async {
            let mut client = tokio::select! {
                _ = stop.cancelled() => return Ok(()),
                result = rustctrl_network::connect(&config.server) => result?,
            };
            let mut interval = tokio::time::interval(Duration::from_secs(config.heartbeat_seconds));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => return Ok(()),
                    _ = interval.tick() => {}
                }
                let heartbeat = HeartbeatRequest {
                    device_id: config.device_id.to_string(),
                    name: config.name.clone(),
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                };
                let reply = tokio::select! {
                    _ = stop.cancelled() => return Ok(()),
                    result = client.send_heartbeat(heartbeat) => result?.into_inner(),
                };
                tracing::info!(
                    device_id = %config.device_id,
                    received_at = reply.received_at_unix_ms,
                    "heartbeat acknowledged"
                );
                retry_seconds = 1;
                if once {
                    return Ok(());
                }
            }
        }
        .await;
        if stop.is_cancelled() {
            return Ok(());
        }
        if once {
            return attempt;
        }
        if let Err(error) = attempt {
            tracing::warn!(%error, retry_seconds, "agent connection interrupted");
        }
        tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(retry_seconds)) => {}
        }
        retry_seconds = (retry_seconds * 2).min(60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enroll_or_load_reuses_existing_configuration() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();
        let config_path = target_dir.join("config.toml");

        let device_id = DeviceId::new();
        let ca_path = target_dir.join("ca.pem");
        let cert_path = target_dir.join("cert.pem");
        let key_path = target_dir.join("key.pem");
        std::fs::write(&ca_path, "dummy ca")?;
        std::fs::write(&cert_path, "dummy cert")?;
        std::fs::write(&key_path, "dummy key")?;

        let initial_config = format!(
            "device_id = \"{}\"\nname = \"Existing Agent\"\nheartbeat_seconds = 15\nlog_file = \"agent.log\"\n\n[server]\nendpoint = \"https://localhost:9876\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
            device_id
        );
        std::fs::write(&config_path, initial_config)?;

        let artifact_path = target_dir.join("nonexistent-artifact.toml");
        let loaded = enroll_or_load(&artifact_path, target_dir, None, 10).await?;

        assert_eq!(loaded.device_id, device_id);
        assert_eq!(loaded.name, "Existing Agent");
        assert_eq!(loaded.heartbeat_seconds, 15);
        Ok(())
    }

    #[tokio::test]
    async fn enroll_or_load_pending_device_id_persists_before_rpc() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();
        let pending_file = target_dir.join(".pending_enrollment");

        let device_id = DeviceId::new();
        let resumption_secret = "test-resumption-secret-token";
        std::fs::write(
            &pending_file,
            format!("{device_id}\n{resumption_secret}\n").as_bytes(),
        )?;

        let artifact = AgentInstallationArtifact {
            server_endpoint: "https://127.0.0.1:9".into(),
            domain_name: "localhost".into(),
            ca_certificate: "dummy ca".into(),
            enrollment_certificate: "dummy cert".into(),
            enrollment_private_key: "dummy key".into(),
            authorization_id: "auth-123".into(),
            installation_secret: "secret-123".into(),
            created_at_unix_ms: 123456789,
        };
        let artifact_path = target_dir.join("artifact.toml");
        artifact.save_to_file(&artifact_path)?;

        // Connection will fail since endpoint is unreachable, but pending_file should be preserved with the same credentials
        let _ = enroll_or_load(&artifact_path, target_dir, Some("Test PC".into()), 10).await;

        assert!(pending_file.exists());
        let content = std::fs::read_to_string(&pending_file)?;
        let mut lines = content.lines();
        assert_eq!(lines.next().unwrap().trim().parse::<DeviceId>()?, device_id);
        assert_eq!(lines.next().unwrap().trim(), resumption_secret);
        Ok(())
    }

    #[tokio::test]
    async fn enroll_or_load_migrates_legacy_pending_device_id_and_persists_resumption_secret()
    -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();
        let legacy_pending_id_path = target_dir.join(".pending_device_id");
        let pending_file = target_dir.join(".pending_enrollment");

        let device_id = DeviceId::new();
        std::fs::write(&legacy_pending_id_path, device_id.to_string().as_bytes())?;

        let artifact = AgentInstallationArtifact {
            server_endpoint: "https://127.0.0.1:9".into(),
            domain_name: "localhost".into(),
            ca_certificate: "dummy ca".into(),
            enrollment_certificate: "dummy cert".into(),
            enrollment_private_key: "dummy key".into(),
            authorization_id: "auth-123".into(),
            installation_secret: "secret-123".into(),
            created_at_unix_ms: 123456789,
        };
        let artifact_path = target_dir.join("artifact.toml");
        artifact.save_to_file(&artifact_path)?;

        let _ = enroll_or_load(&artifact_path, target_dir, Some("Test PC".into()), 10).await;

        assert!(!legacy_pending_id_path.exists());
        assert!(pending_file.exists());
        let content = std::fs::read_to_string(&pending_file)?;
        let mut lines = content.lines();
        assert_eq!(lines.next().unwrap().trim().parse::<DeviceId>()?, device_id);
        let secret = lines.next().unwrap().trim();
        assert!(!secret.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn enroll_or_load_rejects_invalid_heartbeat_seconds_before_mutating_state() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();
        let artifact_path = target_dir.join("artifact.toml");

        let err_zero = enroll_or_load(&artifact_path, target_dir, None, 0)
            .await
            .unwrap_err();
        assert!(err_zero.to_string().contains("heartbeat_seconds"));

        let err_high = enroll_or_load(&artifact_path, target_dir, None, 3601)
            .await
            .unwrap_err();
        assert!(err_high.to_string().contains("heartbeat_seconds"));

        assert!(!target_dir.join(".pending_enrollment").exists());
        assert!(!target_dir.join("config.toml").exists());
        Ok(())
    }

    #[tokio::test]
    async fn service_options_loads_existing_config_without_artifact() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();
        let config_path = target_dir.join("config.toml");

        let device_id = DeviceId::new();
        std::fs::write(target_dir.join("ca.pem"), "dummy ca")?;
        std::fs::write(target_dir.join("cert.pem"), "dummy cert")?;
        std::fs::write(target_dir.join("key.pem"), "dummy key")?;

        let initial_config = format!(
            "device_id = \"{}\"\nname = \"Existing Service Agent\"\nheartbeat_seconds = 20\nlog_file = \"agent.log\"\n\n[server]\nendpoint = \"https://localhost:9876\"\ndomain_name = \"localhost\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
            device_id
        );
        std::fs::write(&config_path, initial_config)?;

        let opts = ServiceOptions {
            config: None,
            artifact: None,
            target_dir: target_dir.to_path_buf(),
            name: None,
            heartbeat_seconds: 10,
        };

        let stop = CancellationToken::new();
        let loaded = opts.load_or_enroll(stop).await?;

        assert_eq!(loaded.device_id, device_id);
        assert_eq!(loaded.name, "Existing Service Agent");
        assert_eq!(loaded.heartbeat_seconds, 20);
        Ok(())
    }

    #[tokio::test]
    async fn service_options_fails_when_neither_config_nor_artifact_exists() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let target_dir = dir.path();

        let opts = ServiceOptions {
            config: None,
            artifact: None,
            target_dir: target_dir.to_path_buf(),
            name: None,
            heartbeat_seconds: 10,
        };

        let stop = CancellationToken::new();
        let err = opts.load_or_enroll(stop).await.unwrap_err();
        assert!(err.to_string().contains("neither agent configuration"));
        Ok(())
    }
}
