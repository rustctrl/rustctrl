use anyhow::{Context, Result};
use std::{ffi::OsString, sync::OnceLock, time::Duration};
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const NAME: &str = "RustCtrlAgent";
static OPTIONS: OnceLock<crate::ServiceOptions> = OnceLock::new();
define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(options: crate::ServiceOptions) -> Result<()> {
    OPTIONS
        .set(options)
        .map_err(|_| anyhow::anyhow!("service configuration already set"))?;
    service_dispatcher::start(NAME, ffi_service_main)
        .context("start Windows service dispatcher")?;
    Ok(())
}

fn status(state: ServiceState, exit_code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: if state == ServiceState::StopPending {
            Duration::from_secs(10)
        } else {
            Duration::ZERO
        },
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let stop = CancellationToken::new();
    let handler_stop = stop.clone();
    let handle = match service_control_handler::register(NAME, move |control| match control {
        ServiceControl::Stop => {
            handler_stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!(%error, "register service handler");
            return;
        }
    };

    let result: Result<()> = (|| {
        let opts = OPTIONS.get().context("missing service options")?.clone();
        let existing_cfg_path = opts
            .config
            .as_ref()
            .filter(|p| p.exists())
            .cloned()
            .or_else(|| {
                let p = opts.target_dir.join("config.toml");
                if p.exists() { Some(p) } else { None }
            });

        let log_file =
            match existing_cfg_path.and_then(|p| rustctrl_core::AgentConfig::load(&p).ok()) {
                Some(cfg) => cfg.log_file,
                None => opts.target_dir.join("agent.log"),
            };
        let _ = rustctrl_core::init_file_logging(&log_file);

        let runtime = tokio::runtime::Runtime::new()?;
        handle.set_service_status(status(ServiceState::Running, 0))?;
        runtime.block_on(async move {
            let config = opts.load_or_enroll(stop.clone()).await?;
            crate::run_agent(config, stop, false).await
        })
    })();

    let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
    let code = if let Err(error) = result {
        tracing::error!(%error, "service stopped with an error");
        1
    } else {
        0
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, code));
}

pub fn install_service(
    mut options: crate::ServiceOptions,
    service_name: &str,
    display_name: &str,
    start: bool,
) -> Result<()> {
    // Resolve target_dir to an absolute path so the Windows service (running under a different working dir)
    // always locates its files accurately.
    let abs_target_dir =
        std::path::absolute(&options.target_dir).unwrap_or_else(|_| options.target_dir.clone());
    options.target_dir = abs_target_dir;

    std::fs::create_dir_all(&options.target_dir)?;

    // Restrict access on Windows: SYSTEM (*S-1-5-18) and BUILTIN\Administrators (*S-1-5-32-544)
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("icacls")
            .arg(&options.target_dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .output();
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let mut was_running = false;
    // Stop existing service if running before overwriting its binary
    if let Ok(existing) = manager.open_service(
        service_name,
        windows_service::service::ServiceAccess::STOP
            | windows_service::service::ServiceAccess::QUERY_STATUS,
    ) && let Ok(svc_status) = existing.query_status()
        && svc_status.current_state != ServiceState::Stopped
    {
        was_running = true;
        tracing::info!(
            service_name,
            "stopping existing service before binary update"
        );
        let _ = existing.stop();
        for _ in 0..40 {
            std::thread::sleep(Duration::from_millis(500));
            if let Ok(st) = existing.query_status()
                && st.current_state == ServiceState::Stopped
            {
                break;
            }
        }
    }

    let current_exe = std::env::current_exe()?;
    let target_exe = options.target_dir.join("rustctrl-agent.exe");
    if current_exe != target_exe {
        let mut copied = false;
        for _ in 0..25 {
            if std::fs::copy(&current_exe, &target_exe).is_ok() {
                copied = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        if !copied {
            std::fs::copy(&current_exe, &target_exe)?;
        }
    }

    let target_config = options.target_dir.join("config.toml");
    let target_artifact = options.target_dir.join("artifact.toml");

    // Copy explicit config and referenced certificates if provided
    if let Some(cfg) = &options.config {
        let abs_cfg = std::path::absolute(cfg).unwrap_or_else(|_| cfg.clone());
        if abs_cfg.exists() && abs_cfg != target_config {
            std::fs::copy(&abs_cfg, &target_config)?;
            if let Some(parent) = abs_cfg.parent() {
                for cert_name in ["ca.pem", "cert.pem", "key.pem"] {
                    let src_cert = parent.join(cert_name);
                    let dst_cert = options.target_dir.join(cert_name);
                    if src_cert.exists() && src_cert != dst_cert {
                        let _ = std::fs::copy(src_cert, dst_cert);
                    }
                }
            }
        }
    }

    if !target_config.exists()
        && let Some(art) = &options.artifact
    {
        let abs_art = std::path::absolute(art).unwrap_or_else(|_| art.clone());
        if abs_art.exists() && abs_art != target_artifact {
            std::fs::copy(&abs_art, &target_artifact)?;
        }
    }

    let mut launch_arguments: Vec<OsString> = vec![
        "service".into(),
        "--target-dir".into(),
        options.target_dir.clone().into(),
    ];
    if target_config.exists() {
        launch_arguments.push("--config".into());
        launch_arguments.push(target_config.into());
    } else {
        launch_arguments.push("--artifact".into());
        launch_arguments.push(target_artifact.into());
    }
    if let Some(name) = &options.name {
        launch_arguments.push("--name".into());
        launch_arguments.push(name.clone().into());
    }
    if options.heartbeat_seconds > 0 {
        launch_arguments.push("--heartbeat-seconds".into());
        launch_arguments.push(options.heartbeat_seconds.to_string().into());
    }

    let info = ServiceInfo {
        name: service_name.into(),
        display_name: display_name.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target_exe,
        launch_arguments,
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    let service = match manager.open_service(
        service_name,
        windows_service::service::ServiceAccess::CHANGE_CONFIG
            | windows_service::service::ServiceAccess::START
            | windows_service::service::ServiceAccess::QUERY_STATUS,
    ) {
        Ok(existing) => {
            tracing::info!(
                service_name,
                "updating existing Windows service configuration"
            );
            existing.change_config(&info)?;
            existing
        }
        Err(_) => {
            tracing::info!(service_name, "creating new Windows service");
            manager.create_service(
                &info,
                windows_service::service::ServiceAccess::START
                    | windows_service::service::ServiceAccess::QUERY_STATUS,
            )?
        }
    };

    let _ = service
        .set_description("RustCtrl Windows Agent service for fleet management and monitoring");

    if start || was_running {
        tracing::info!(service_name, "starting Windows service");
        let _ = service.start(&[] as &[&str]);
    }

    Ok(())
}

pub fn uninstall_service(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(
        service_name,
        windows_service::service::ServiceAccess::STOP
            | windows_service::service::ServiceAccess::DELETE
            | windows_service::service::ServiceAccess::QUERY_STATUS,
    )?;

    let _ = service.stop();
    service.delete()?;

    tracing::info!(
        service_name,
        "service unregistered; local identity and config preserved"
    );
    Ok(())
}

pub fn start_service(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(service_name, windows_service::service::ServiceAccess::START)?;
    service.start(&[] as &[&str])?;
    Ok(())
}

pub fn stop_service(service_name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(service_name, windows_service::service::ServiceAccess::STOP)?;
    service.stop()?;
    Ok(())
}

pub fn service_status(service_name: &str) -> Result<String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        service_name,
        windows_service::service::ServiceAccess::QUERY_STATUS,
    )?;
    let status = service.query_status()?;
    let state_str = match status.current_state {
        ServiceState::Running => "Running",
        ServiceState::Stopped => "Stopped",
        ServiceState::StartPending => "StartPending",
        ServiceState::StopPending => "StopPending",
        ServiceState::Paused => "Paused",
        ServiceState::PausePending => "PausePending",
        ServiceState::ContinuePending => "ContinuePending",
    };
    Ok(state_str.to_string())
}
