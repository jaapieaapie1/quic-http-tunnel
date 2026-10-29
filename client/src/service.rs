//! Runs the client under the Windows Service Control Manager.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Notify;
use tracing::error;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::Args;

/// Ignored by the SCM for an own-process service; any name works.
const SERVICE_NAME: &str = "tunnel-client";
const LOG_FILE: &str = "tunnel-client.log";

/// Handed from `start` to `service_main`, which the SCM calls on its own thread.
static ARGS: Mutex<Option<Args>> = Mutex::new(None);

define_windows_service!(ffi_service_main, service_main);

/// Connects to the SCM and blocks until the service stops.
pub fn start(args: Args) -> Result<()> {
    // The SCM starts services in System32; resolve relative paths next to the exe.
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("executable has no parent directory")?;
    std::env::set_current_dir(dir)?;

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
        .with_context(|| format!("opening {LOG_FILE}"))?;
    tracing_subscriber::fmt()
        .with_env_filter(crate::log_filter())
        .with_ansi(false)
        .with_writer(Mutex::new(log))
        .init();

    *ARGS.lock().unwrap() = Some(args);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connecting to the service control manager, was this started as a service?")
}

/// Start arguments from the SCM are ignored; configure through the service's
/// command line (binPath) or environment instead.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("service failed: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let args = ARGS
        .lock()
        .unwrap()
        .take()
        .context("service started twice")?;
    let stop = Arc::new(Notify::new());
    let handler_stop = stop.clone();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            handler_stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let set_state = |state, exit_code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };

    set_state(ServiceState::Running, ServiceExitCode::Win32(0))?;
    let result = tokio::runtime::Runtime::new()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| {
            runtime.block_on(crate::run(args, async move { stop.notified().await }))
        });
    if let Err(e) = &result {
        error!("tunnel failed: {e:#}");
    }
    let exit_code = match result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    set_state(ServiceState::Stopped, exit_code)?;
    Ok(())
}
