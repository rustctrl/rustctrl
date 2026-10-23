use anyhow::{Context, Result};
use rustctrl_core::AgentConfig;
use std::{ffi::OsString, sync::OnceLock, time::Duration};
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

const NAME: &str = "RustCtrlAgent";
static CONFIG: OnceLock<AgentConfig> = OnceLock::new();
define_windows_service!(ffi_service_main, service_main);

pub fn dispatch(config: AgentConfig) -> Result<()> {
    CONFIG
        .set(config)
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
        let config = CONFIG
            .get()
            .context("missing service configuration")?
            .clone();
        let runtime = tokio::runtime::Runtime::new()?;
        handle.set_service_status(status(ServiceState::Running, 0))?;
        runtime.block_on(crate::run_agent(config, stop, false))
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
