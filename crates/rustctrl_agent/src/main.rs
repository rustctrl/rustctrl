use anyhow::Result;
use clap::{Parser, Subcommand};
use rustctrl_core::{AgentConfig, init_logging};
use rustctrl_protocol::bootstrap::HeartbeatRequest;
use std::{path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod service;

#[derive(Parser)]
#[command(
    version,
    about = "RustCtrl Windows service and bootstrap diagnostic agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run in the foreground. Also available on Linux for protocol diagnostics.
    Console {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        once: bool,
    },
    /// Enter the Windows Service Control Manager dispatcher.
    Service {
        #[arg(long)]
        config: PathBuf,
    },
}
fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Console { config, once } => {
            init_logging();
            let config = AgentConfig::load(&config)?;
            tokio::runtime::Runtime::new()?.block_on(async move {
                let stop = CancellationToken::new();
                let signal = stop.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    signal.cancel();
                });
                run_agent(config, stop, once).await
            })
        }
        Command::Service { config } => {
            #[cfg(windows)]
            {
                let config = AgentConfig::load(&config)?;
                rustctrl_core::init_file_logging(&config.log_file)?;
                service::dispatch(config)
            }
            #[cfg(not(windows))]
            {
                let _ = config;
                anyhow::bail!(
                    "Windows Service mode requires Windows; use console for protocol diagnostics"
                )
            }
        }
    }
}

pub(crate) async fn run_agent(
    config: AgentConfig,
    stop: CancellationToken,
    once: bool,
) -> Result<()> {
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
                    device_id: config.device_id.to_string(), name: config.name.clone(),
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                };
                let reply = tokio::select! {
                    _ = stop.cancelled() => return Ok(()),
                    result = client.send_heartbeat(heartbeat) => result?.into_inner(),
                };
                tracing::info!(device_id = %config.device_id, received_at = reply.received_at_unix_ms, "heartbeat acknowledged");
                retry_seconds = 1;
                if once { return Ok(()); }
            }
        }.await;
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
