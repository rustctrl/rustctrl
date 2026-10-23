#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand};
use rustctrl_core::{ClientConfig, DeviceId, init_logging};
use rustctrl_protocol::bootstrap::HealthRequest;
use rustctrl_server::{
    config::ServerConfig,
    pki::{PkiOptions, initialize},
    service,
};
use std::{net::IpAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "RustCtrl Linux bootstrap server and offline PKI tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    InitPki {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        server_output: Option<PathBuf>,
        #[arg(long, default_values_t = [String::from("localhost")])]
        server_name: Vec<String>,
        #[arg(long, default_value = "127.0.0.1")]
        server_ip: Vec<IpAddr>,
        #[arg(long, default_value = "https://localhost:9876")]
        endpoint: String,
        #[arg(long, default_value = "localhost")]
        domain_name: String,
        #[arg(long)]
        device_id: Option<DeviceId>,
    },
    Healthcheck {
        #[arg(long, default_value = "https://localhost:9876")]
        endpoint: String,
        #[arg(long, default_value = "localhost")]
        domain_name: String,
        #[arg(long)]
        tls_dir: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    match Cli::parse().command {
        Command::Serve { config } => service::serve(ServerConfig::load(&config)?, shutdown()).await,
        Command::InitPki {
            output,
            server_output,
            server_name,
            server_ip,
            endpoint,
            domain_name,
            device_id,
        } => initialize(&PkiOptions {
            output,
            server_output,
            server_names: server_name,
            server_ips: server_ip,
            endpoint,
            domain_name,
            device_id: device_id.unwrap_or_default(),
        }),
        Command::Healthcheck {
            endpoint,
            domain_name,
            tls_dir,
        } => {
            let config = ClientConfig {
                endpoint,
                domain_name,
                ca_certificate: tls_dir.join("ca.pem"),
                certificate: tls_dir.join("health/cert.pem"),
                private_key: tls_dir.join("health/key.pem"),
            };
            let health = rustctrl_network::connect(&config)
                .await?
                .get_health(HealthRequest {})
                .await?
                .into_inner();
            println!(
                "healthy version={} registered_devices={}",
                health.version, health.registered_devices
            );
            Ok(())
        }
    }
}
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()).context("register SIGTERM handler") {
            Ok(mut terminate) => {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            }
            Err(error) => {
                tracing::error!(%error);
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("server shutdown requested");
}
