use anyhow::Result;
use clap::{Parser, Subcommand};
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
        config: PathBuf,
    },
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
        Command::Service { config } => {
            #[cfg(windows)]
            {
                let config = AgentConfig::load(&config)?;
                rustctrl_core::init_file_logging(&config.log_file)?;
                rustctrl_agent::service::dispatch(config)
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
