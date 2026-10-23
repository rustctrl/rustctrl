use anyhow::Result;
use clap::{Parser, Subcommand};
use rustctrl_core::{ControllerConfig, init_logging};
use rustctrl_protocol::bootstrap::HealthRequest;
use std::path::PathBuf;

#[cfg(feature = "gui")]
mod gui;

#[derive(Parser)]
#[command(
    version,
    about = "RustCtrl desktop Controller and TLS connection diagnostic"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        default_value = ".local/pki/clients/controller/config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Gui,
    Check,
}

fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    let config = ControllerConfig::load(&cli.config)?;
    match cli.command.unwrap_or(Command::Gui) {
        Command::Check => tokio::runtime::Runtime::new()?.block_on(async {
            let health = rustctrl_network::connect(&config.server)
                .await?
                .get_health(HealthRequest {})
                .await?
                .into_inner();
            println!(
                "healthy version={} registered_devices={}",
                health.version, health.registered_devices
            );
            Ok(())
        }),
        Command::Gui => {
            #[cfg(feature = "gui")]
            {
                gui::open(config)
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = config;
                anyhow::bail!(
                    "GUI support is disabled in this diagnostic build; rebuild with default features"
                )
            }
        }
    }
}
