use anyhow::Result;
use clap::{Parser, Subcommand};
#[cfg(windows)]
use rustctrl_agent::ServiceOptions;
use rustctrl_agent::{enroll_or_load, run_agent};
use rustctrl_core::{AgentConfig, init_logging};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

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
        config: Option<PathBuf>,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        target_dir: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 10)]
        heartbeat_seconds: u64,
        #[arg(long)]
        once: bool,
    },
    /// Enter the Windows Service Control Manager dispatcher.
    Service {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        target_dir: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 10)]
        heartbeat_seconds: u64,
    },
    /// Install or update the Agent as a Windows Service.
    Install {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        target_dir: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 10)]
        heartbeat_seconds: u64,
        #[arg(long, default_value = "RustCtrlAgent")]
        service_name: String,
        #[arg(long, default_value = "RustCtrl Agent Service")]
        display_name: String,
        #[arg(long, default_value_t = true)]
        start: bool,
    },
    /// Stop and uninstall the Agent Windows Service.
    Uninstall {
        #[arg(long, default_value = "RustCtrlAgent")]
        service_name: String,
    },
    /// Start the Agent Windows Service.
    Start {
        #[arg(long, default_value = "RustCtrlAgent")]
        service_name: String,
    },
    /// Stop the Agent Windows Service.
    Stop {
        #[arg(long, default_value = "RustCtrlAgent")]
        service_name: String,
    },
    /// Query the Agent Windows Service status.
    Status {
        #[arg(long, default_value = "RustCtrlAgent")]
        service_name: String,
    },
}

#[cfg(windows)]
fn resolve_target_dir(
    target_dir: Option<PathBuf>,
    config: Option<&PathBuf>,
    artifact: Option<&PathBuf>,
) -> PathBuf {
    let raw = target_dir
        .or_else(|| config.and_then(|p| p.parent().map(PathBuf::from)))
        .or_else(|| artifact.and_then(|p| p.parent().map(PathBuf::from)))
        .unwrap_or_else(|| {
            std::env::var_os("ProgramData")
                .map(|p| PathBuf::from(p).join("RustCtrl"))
                .unwrap_or_else(|| PathBuf::from("."))
        });
    std::path::absolute(&raw).unwrap_or(raw)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Console {
            config,
            artifact,
            target_dir,
            name,
            heartbeat_seconds,
            once,
        } => {
            init_logging();
            tokio::runtime::Runtime::new()?.block_on(async move {
                let agent_config = match (config, artifact) {
                    (Some(cfg_path), _) => AgentConfig::load(&cfg_path)?,
                    (None, Some(art_path)) => {
                        enroll_or_load(&art_path, &target_dir, name, heartbeat_seconds).await?
                    }
                    (None, None) => {
                        let default_cfg = target_dir.join("config.toml");
                        if default_cfg.exists() {
                            AgentConfig::load(&default_cfg)?
                        } else {
                            anyhow::bail!("either --config or --artifact must be specified");
                        }
                    }
                };
                let stop = CancellationToken::new();
                let signal = stop.clone();
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    signal.cancel();
                });
                run_agent(agent_config, stop, once).await
            })
        }
        Command::Service {
            config,
            artifact,
            target_dir,
            name,
            heartbeat_seconds,
        } => {
            #[cfg(windows)]
            {
                let resolved_target =
                    resolve_target_dir(target_dir, config.as_ref(), artifact.as_ref());
                let options = ServiceOptions {
                    config,
                    artifact,
                    target_dir: resolved_target,
                    name,
                    heartbeat_seconds,
                };
                rustctrl_agent::service::dispatch(options)
            }
            #[cfg(not(windows))]
            {
                let _ = (config, artifact, target_dir, name, heartbeat_seconds);
                anyhow::bail!(
                    "Windows Service mode requires Windows; use console for protocol diagnostics"
                )
            }
        }
        Command::Install {
            config,
            artifact,
            target_dir,
            name,
            heartbeat_seconds,
            service_name,
            display_name,
            start,
        } => {
            #[cfg(windows)]
            {
                let resolved_target =
                    resolve_target_dir(target_dir, config.as_ref(), artifact.as_ref());
                let options = ServiceOptions {
                    config,
                    artifact,
                    target_dir: resolved_target,
                    name,
                    heartbeat_seconds,
                };
                rustctrl_agent::service::install_service(
                    options,
                    &service_name,
                    &display_name,
                    start,
                )?;
                println!("Service '{service_name}' installed successfully");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = (
                    config,
                    artifact,
                    target_dir,
                    name,
                    heartbeat_seconds,
                    service_name,
                    display_name,
                    start,
                );
                anyhow::bail!(
                    "Windows Service operations require Windows; use console for protocol diagnostics"
                )
            }
        }
        Command::Uninstall { service_name } => {
            #[cfg(windows)]
            {
                rustctrl_agent::service::uninstall_service(&service_name)?;
                println!("Service '{service_name}' uninstalled successfully");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = service_name;
                anyhow::bail!(
                    "Windows Service operations require Windows; use console for protocol diagnostics"
                )
            }
        }
        Command::Start { service_name } => {
            #[cfg(windows)]
            {
                rustctrl_agent::service::start_service(&service_name)?;
                println!("Service '{service_name}' started successfully");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = service_name;
                anyhow::bail!(
                    "Windows Service operations require Windows; use console for protocol diagnostics"
                )
            }
        }
        Command::Stop { service_name } => {
            #[cfg(windows)]
            {
                rustctrl_agent::service::stop_service(&service_name)?;
                println!("Service '{service_name}' stopped successfully");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = service_name;
                anyhow::bail!(
                    "Windows Service operations require Windows; use console for protocol diagnostics"
                )
            }
        }
        Command::Status { service_name } => {
            #[cfg(windows)]
            {
                let status = rustctrl_agent::service::service_status(&service_name)?;
                println!("Service '{service_name}' status: {status}");
                Ok(())
            }
            #[cfg(not(windows))]
            {
                let _ = service_name;
                anyhow::bail!(
                    "Windows Service operations require Windows; use console for protocol diagnostics"
                )
            }
        }
    }
}
