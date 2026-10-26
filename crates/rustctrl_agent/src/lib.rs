use anyhow::Result;
use rustctrl_core::{AgentConfig, AgentInstallationArtifact, DeviceId};
use rustctrl_protocol::bootstrap::{EnrollAgentRequest, HeartbeatRequest};
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
pub mod service;

pub async fn enroll_or_load(
    artifact_path: &Path,
    target_dir: &Path,
    name: Option<String>,
    heartbeat_seconds: u64,
) -> Result<AgentConfig> {
    let config_path = target_dir.join("config.toml");
    if config_path.exists() {
        tracing::info!(path = %config_path.display(), "using existing agent configuration");
        return AgentConfig::load(&config_path);
    }

    let artifact = AgentInstallationArtifact::load_from_file(artifact_path)?;
    let device_id = DeviceId::new();
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

    let config_content = format!(
        "device_id = \"{}\"\nname = \"{}\"\nheartbeat_seconds = {}\nlog_file = \"agent.log\"\n\n[server]\nendpoint = \"{}\"\ndomain_name = \"{}\"\nca_certificate = \"ca.pem\"\ncertificate = \"cert.pem\"\nprivate_key = \"key.pem\"\n",
        device_id, computer_name, heartbeat_seconds, artifact.server_endpoint, artifact.domain_name
    );

    std::fs::write(&config_path, config_content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

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
}
