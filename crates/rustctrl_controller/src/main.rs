use anyhow::Result;
use clap::{Parser, Subcommand};
use rustctrl_core::{ControllerConfig, init_logging};
use rustctrl_protocol::auth::{
    LoginRequest, LogoutRequest, ReplaceTemporaryPasswordRequest, StaffStatusRequest,
};
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
    Login {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        replace_password: Option<String>,
        #[arg(long)]
        logout: bool,
    },
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
        Command::Login {
            username,
            password,
            replace_password,
            logout,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let reply = client
                .login(LoginRequest {
                    username: username.clone(),
                    password,
                })
                .await?
                .into_inner();

            println!(
                "Login success: username={} role={} must_change_password={}",
                reply.username, reply.role, reply.must_change_password
            );

            let session_token = reply.session_token;

            if reply.must_change_password {
                if let Some(new_password) = replace_password {
                    let mut req = tonic::Request::new(ReplaceTemporaryPasswordRequest {
                        new_password,
                    });
                    req.metadata_mut().insert(
                        "authorization",
                        format!("Bearer {session_token}").parse()?,
                    );
                    client.replace_temporary_password(req).await?;
                    println!("Temporary password successfully replaced.");
                } else {
                    println!(
                        "Warning: temporary password must be replaced to access protected operations."
                    );
                    return Ok(());
                }
            }

            let mut status_req = tonic::Request::new(StaffStatusRequest {});
            status_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {session_token}").parse()?,
            );
            let status = client.get_staff_status(status_req).await?.into_inner();
            println!(
                "Protected status: authenticated={} registered_devices={} server_version={}",
                status.authenticated, status.registered_devices, status.server_version
            );

            if logout {
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {session_token}").parse()?,
                );
                client.logout(logout_req).await?;
                println!("Logout success.");
            }

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
