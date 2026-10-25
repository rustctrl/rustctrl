use anyhow::Result;
use clap::{Parser, Subcommand};
use rustctrl_core::{ControllerConfig, init_logging};
use rustctrl_protocol::auth::{
    BlockDeviceRequest, ChangeOwnPasswordRequest, ChangeStaffRoleRequest,
    CreateStaffAccountRequest, CreateTargetRequest, DeactivateStaffAccountRequest,
    ListFleetDevicesRequest, ListStaffAccountsRequest, LoginRequest, LogoutRequest,
    RemoveTargetRequest, ReplaceTemporaryPasswordRequest, ResetStaffPasswordRequest,
    StaffStatusRequest, UnblockDeviceRequest, UpdateFleetDeviceRequest, UpdateTargetRequest,
};
use rustctrl_protocol::bootstrap::HealthRequest;
use std::path::PathBuf;

#[cfg(feature = "gui")]
mod gui;
mod session;

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
        remember: bool,
        #[arg(long)]
        logout: bool,
    },
    RestoreSession,
    ListAccounts {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    CreateAccount {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_username: String,
        #[arg(long)]
        target_role: String,
        #[arg(long)]
        temporary_password: String,
    },
    ChangeRole {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_username: String,
        #[arg(long)]
        new_role: String,
    },
    ChangePassword {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        new_password: String,
    },
    ResetPassword {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_username: String,
        #[arg(long)]
        temporary_password: String,
    },
    DeactivateAccount {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_username: String,
    },
    ListDevices {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    EditDevice {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        location: Option<String>,
    },
    BlockDevice {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        device_id: String,
    },
    UnblockDevice {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        device_id: String,
    },
    AddTarget {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        location: Option<String>,
    },
    EditTarget {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        address: String,
        #[arg(long)]
        location: Option<String>,
    },
    RemoveTarget {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        target_id: String,
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
            remember,
            logout,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let reply = client
                .login(LoginRequest {
                    username: username.clone(),
                    password,
                    remember,
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

            // The saved credential reflects the latest explicit choice: stored
            // only for remembered logins, removed otherwise. Never the password.
            let session_path = session::session_file_path(&cli.config);
            if remember {
                session::save(
                    &session_path,
                    &session::SavedStaffSession {
                        endpoint: config.server.endpoint.clone(),
                        domain_name: config.server.domain_name.clone(),
                        username: reply.username,
                        session_token: session_token.clone(),
                    },
                )?;
                println!("Login remembered on this computer.");
            } else if session::load(&session_path).is_ok_and(|saved| saved.is_some()) {
                session::clear(&session_path)?;
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
                // Clear the stored credential only when it belongs to this session.
                let matches_saved = session::load(&session_path)?
                    .is_some_and(|saved| saved.session_token == session_token);
                if matches_saved {
                    session::clear(&session_path)?;
                }
            }

            Ok(())
        }),
        Command::RestoreSession => tokio::runtime::Runtime::new()?.block_on(async {
            let session_path = session::session_file_path(&cli.config);
            let Some(saved) = session::load(&session_path)? else {
                println!("No saved session.");
                return Ok(());
            };
            if !saved.matches_deployment(&config.server) {
                println!("Saved session belongs to a different deployment.");
                return Ok(());
            }
            let mut client =
                match rustctrl_network::connect_staff_auth(&config.server).await {
                    Ok(client) => client,
                    Err(error) => anyhow::bail!(
                        "Server unavailable. Saved session could not be validated: {error}"
                    ),
                };
            let mut status_req = tonic::Request::new(StaffStatusRequest {});
            status_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", saved.session_token).parse()?,
            );
            match client.get_staff_status(status_req).await {
                Ok(status) => {
                    let status = status.into_inner();
                    println!(
                        "Restored session: username={} role={} authenticated={}",
                        status.username, status.role, status.authenticated
                    );
                    Ok(())
                }
                Err(status) if status.code() == tonic::Code::Unauthenticated => {
                    // The saved credential is dead: remove it so reopening
                    // cannot keep retrying revoked access.
                    session::clear(&session_path)?;
                    anyhow::bail!("Saved session expired or was revoked. Sign in again.")
                }
                Err(status) if status.code() == tonic::Code::PermissionDenied => {
                    session::clear(&session_path)?;
                    anyhow::bail!(
                        "Saved session requires replacing a temporary password. Sign in again."
                    )
                }
                Err(status) => anyhow::bail!("Staff session check failed: {status}"),
            }
        }),
        Command::ListAccounts { username, password } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                username,
                password,
                remember: false,
            })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before listing accounts");
                }
                let mut req = tonic::Request::new(ListStaffAccountsRequest {});
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.list_staff_accounts(req).await?.into_inner();
                println!("Staff Accounts ({}):", reply.accounts.len());
                for acc in reply.accounts {
                println!(
                    "  username={} role={} temporary={} active={}",
                    acc.username, acc.role, acc.must_change_password, acc.active
                );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::CreateAccount {
            username,
            password,
            target_username,
            target_role,
            temporary_password,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let login_reply = client
                .login(LoginRequest {
                username,
                password,
                remember: false,
            })
                .await?
                .into_inner();
            if login_reply.must_change_password {
                anyhow::bail!("temporary password must be replaced before creating accounts");
            }
            let mut req = tonic::Request::new(CreateStaffAccountRequest {
                username: target_username,
                role: target_role,
                temporary_password,
            });
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let reply = client.create_staff_account(req).await?.into_inner();
            if let Some(acc) = reply.account {
                println!(
                    "Account created: username={} role={} temporary={}",
                    acc.username, acc.role, acc.must_change_password
                );
            }
            let mut logout_req = tonic::Request::new(LogoutRequest {});
            logout_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let _ = client.logout(logout_req).await;
            Ok(())
        }),
        Command::ChangeRole {
            username,
            password,
            target_username,
            new_role,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let login_reply = client
                .login(LoginRequest {
                username,
                password,
                remember: false,
            })
                .await?
                .into_inner();
            if login_reply.must_change_password {
                anyhow::bail!("temporary password must be replaced before changing roles");
            }
            let mut req = tonic::Request::new(ChangeStaffRoleRequest {
                username: target_username,
                new_role,
            });
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let reply = client.change_staff_role(req).await?.into_inner();
            println!(
                "Role changed: username={} role={}",
                reply.username, reply.role
            );
            let mut logout_req = tonic::Request::new(LogoutRequest {});
            logout_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let _ = client.logout(logout_req).await;
            Ok(())
        }),
        Command::ChangePassword {
            username,
            password,
            new_password,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let login_reply = client
                .login(LoginRequest {
                    username,
                    password: password.clone(),
                    remember: false,
                })
                .await?
                .into_inner();
            if login_reply.must_change_password {
                anyhow::bail!("temporary password must be replaced before changing passwords");
            }
            let mut req = tonic::Request::new(ChangeOwnPasswordRequest {
                current_password: password,
                new_password,
            });
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            client.change_own_password(req).await?;
            println!("Password changed successfully.");

            let mut status_req = tonic::Request::new(StaffStatusRequest {});
            status_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let status = client.get_staff_status(status_req).await?.into_inner();
            println!(
                "Protected status: authenticated={} registered_devices={} server_version={}",
                status.authenticated, status.registered_devices, status.server_version
            );

            let mut logout_req = tonic::Request::new(LogoutRequest {});
            logout_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let _ = client.logout(logout_req).await;
            Ok(())
        }),
        Command::ResetPassword {
            username,
            password,
            target_username,
            temporary_password,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let login_reply = client
                .login(LoginRequest {
                username,
                password,
                remember: false,
            })
                .await?
                .into_inner();
            if login_reply.must_change_password {
                anyhow::bail!("temporary password must be replaced before resetting passwords");
            }
            let mut req = tonic::Request::new(ResetStaffPasswordRequest {
                username: target_username,
                temporary_password,
            });
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let reply = client.reset_staff_password(req).await?.into_inner();
            if let Some(acc) = reply.account {
                println!(
                    "Password reset: username={} role={} temporary={}",
                    acc.username, acc.role, acc.must_change_password
                );
                println!("All staff sessions of this account were revoked.");
            }
            let mut logout_req = tonic::Request::new(LogoutRequest {});
            logout_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let _ = client.logout(logout_req).await;
            Ok(())
        }),
        Command::DeactivateAccount {
            username,
            password,
            target_username,
        } => tokio::runtime::Runtime::new()?.block_on(async {
            let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
            let login_reply = client
                .login(LoginRequest {
                username,
                password,
                remember: false,
            })
                .await?
                .into_inner();
            if login_reply.must_change_password {
                anyhow::bail!("temporary password must be replaced before deactivating accounts");
            }
            let mut req = tonic::Request::new(DeactivateStaffAccountRequest {
                username: target_username,
            });
            req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let reply = client.deactivate_staff_account(req).await?.into_inner();
            if let Some(acc) = reply.account {
                println!(
                    "Account deactivated: username={} role={} active={}",
                    acc.username, acc.role, acc.active
                );
            }
            let mut logout_req = tonic::Request::new(LogoutRequest {});
            logout_req.metadata_mut().insert(
                "authorization",
                format!("Bearer {}", login_reply.session_token).parse()?,
            );
            let _ = client.logout(logout_req).await;
            Ok(())
        }),
        Command::ListDevices { username, password } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before listing devices");
                }
                let mut req = tonic::Request::new(ListFleetDevicesRequest {});
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.list_fleet_devices(req).await?.into_inner();
                println!("Fleet Devices ({}):", reply.devices.len());
                for device in reply.devices {
                    let last_addr_str = if !device.last_address.is_empty() {
                        &device.last_address
                    } else {
                        "-"
                    };
                    let config_addr_str = device.configured_address.as_deref().unwrap_or("-");
                    let status_str = if !device.status.is_empty() {
                        &device.status
                    } else if device.online {
                        "online"
                    } else {
                        "offline"
                    };
                    let last_seen_str = if device.last_seen_unix_ms == 0 {
                        "-".to_string()
                    } else {
                        device.last_seen_unix_ms.to_string()
                    };
                    println!(
                        "  device={} name={} type={} location={} last_address={} configured_address={} status={} last_seen_unix_ms={}",
                        device.device_id,
                        device.display_name,
                        device.device_type,
                        device.location.as_deref().unwrap_or("-"),
                        last_addr_str,
                        config_addr_str,
                        status_str,
                        last_seen_str,
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::EditDevice {
            username,
            password,
            device_id,
            display_name,
            location,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before editing device");
                }
                let mut req = tonic::Request::new(UpdateFleetDeviceRequest {
                    device_id,
                    display_name,
                    location,
                });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.update_fleet_device(req).await?.into_inner();
                if let Some(device) = reply.device {
                    println!(
                        "Updated device {}: name={} location={} address={} status={}",
                        device.device_id,
                        device.display_name,
                        device.location.as_deref().unwrap_or("-"),
                        if device.last_address.is_empty() {
                            "-"
                        } else {
                            &device.last_address
                        },
                        if device.online { "online" } else { "offline" }
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::BlockDevice {
            username,
            password,
            device_id,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before blocking device");
                }
                let mut req = tonic::Request::new(BlockDeviceRequest { device_id });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.block_device(req).await?.into_inner();
                if let Some(device) = reply.device {
                    println!(
                        "Blocked device {}: name={} status={}",
                        device.device_id, device.display_name, device.status
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::UnblockDevice {
            username,
            password,
            device_id,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before unblocking device");
                }
                let mut req = tonic::Request::new(UnblockDeviceRequest { device_id });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.unblock_device(req).await?.into_inner();
                if let Some(device) = reply.device {
                    println!(
                        "Unblocked device {}: name={} status={}",
                        device.device_id, device.display_name, device.status
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::AddTarget {
            username,
            password,
            display_name,
            address,
            location,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before adding target");
                }
                let mut req = tonic::Request::new(CreateTargetRequest {
                    display_name,
                    address,
                    location,
                    target_type: Some("android_tv".into()),
                });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.create_target(req).await?.into_inner();
                if let Some(target) = reply.target {
                    println!(
                        "Added target {}: name={} type={} address={} status={}",
                        target.device_id,
                        target.display_name,
                        target.device_type,
                        target.configured_address.as_deref().unwrap_or("-"),
                        target.status
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::EditTarget {
            username,
            password,
            target_id,
            display_name,
            address,
            location,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before editing target");
                }
                let mut req = tonic::Request::new(UpdateTargetRequest {
                    target_id,
                    display_name,
                    address,
                    location,
                });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.update_target(req).await?.into_inner();
                if let Some(target) = reply.target {
                    println!(
                        "Updated target {}: name={} type={} address={} location={} status={}",
                        target.device_id,
                        target.display_name,
                        target.device_type,
                        target.configured_address.as_deref().unwrap_or("-"),
                        target.location.as_deref().unwrap_or("-"),
                        target.status
                    );
                }
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::RemoveTarget {
            username,
            password,
            target_id,
        } => {
            tokio::runtime::Runtime::new()?.block_on(async {
                let mut client = rustctrl_network::connect_staff_auth(&config.server).await?;
                let login_reply = client
                    .login(LoginRequest {
                        username,
                        password,
                        remember: false,
                    })
                    .await?
                    .into_inner();
                if login_reply.must_change_password {
                    anyhow::bail!("temporary password must be replaced before removing target");
                }
                let mut req = tonic::Request::new(RemoveTargetRequest { target_id });
                req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let reply = client.remove_target(req).await?.into_inner();
                println!("Removed target {}: success={}", reply.target_id, reply.success);
                let mut logout_req = tonic::Request::new(LogoutRequest {});
                logout_req.metadata_mut().insert(
                    "authorization",
                    format!("Bearer {}", login_reply.session_token).parse()?,
                );
                let _ = client.logout(logout_req).await;
                Ok(())
            })
        }
        Command::Gui => {
            #[cfg(feature = "gui")]
            {
                gui::open(config, cli.config)
            }
            #[cfg(not(feature = "gui"))]
            {
                let _ = (config, cli.config);
                anyhow::bail!(
                    "GUI support is disabled in this diagnostic build; rebuild with default features"
                )
            }
        }
    }
}
