//! Windows service registration, dispatch, and control (0.6.0 S3).
//!
//! The SCM calls are the second FFI surface of the platform crate, scoped
//! behind `#![allow(unsafe_code)]` exactly like the DPAPI wrapper: the
//! functions below are the safe seam, and everything above them is
//! unsafe-free.
//!
//! Lifecycle: `service run` registers itself with the SCM through
//! [`dispatch_service`]; the SCM invokes the static [`service_main`] on its
//! own thread, which registers the control handler, reports RUNNING, and
//! parks until the async runtime finishes or the SCM requests a stop. The
//! control handler only records the stop request and transitions the status;
//! the actual drain runs on the tokio runtime through [`ServiceControl`].

#![allow(unsafe_code)]

use std::{
    ffi::c_void,
    io,
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
    },
};

use tokio::sync::{oneshot, watch};
use windows_sys::Win32::{
    Foundation::{
        ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_PARAMETER, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE, GetLastError,
        NO_ERROR,
    },
    System::Services::{
        ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
        OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SC_HANDLE,
        SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
        SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW,
    },
};
use windows_sys::core::PWSTR;

use super::{SERVICE_DISPLAY_NAME, SERVICE_NAME, ServiceArguments};

/// The wait hint (milliseconds) reported while the service starts and stops.
///
/// The hint is informational only — the SCM never terminates the process
/// when it expires, it only tunes the SCM's own progress reporting — so the
/// bound on a stop comes from the runtime itself: the app's drains are
/// bounded (§7.8), including the 10-second grace for in-flight HTTP
/// requests once the stop signal resolves (the app runtime's
/// `GRACEFUL_DRAIN_TIMEOUT`), which keeps the STOPPED status well inside
/// this 30-second hint window.
const STATUS_WAIT_HINT_MS: u32 = 30_000;

/// The single dispatch slot: the SCM invokes a static `service_main`, so the
/// process-wide control state is parked here for the duration of one
/// dispatch. One service per process makes a single slot sound.
static DISPATCH_SLOT: Mutex<Option<DispatchSlot>> = Mutex::new(None);

struct DispatchSlot {
    control: Arc<ServiceControl>,
    ready: Option<oneshot::Sender<io::Result<()>>>,
}

/// Shared control state between the SCM threads and the async runtime.
pub struct ServiceControl {
    inner: Arc<ServiceControlInner>,
}

struct ServiceControlInner {
    stop_requested: AtomicBool,
    stop_watch: watch::Sender<bool>,
    // An `AtomicPtr` keeps the raw SCM status handle `Send + Sync` so the
    // control state can live in a process-wide static.
    status_handle: AtomicPtr<c_void>,
    current_state: AtomicU32,
    release: Mutex<bool>,
    release_condvar: Condvar,
}

impl ServiceControl {
    /// Creates the control state for one service run.
    #[must_use]
    pub fn new() -> Self {
        let (stop_watch, _) = watch::channel(false);
        Self {
            inner: Arc::new(ServiceControlInner {
                stop_requested: AtomicBool::new(false),
                stop_watch,
                status_handle: AtomicPtr::new(std::ptr::null_mut()),
                current_state: AtomicU32::new(SERVICE_START_PENDING),
                release: Mutex::new(false),
                release_condvar: Condvar::new(),
            }),
        }
    }

    /// Resolves when the SCM requests the service to stop.
    ///
    /// The stop can be requested before the runtime arms this future, so the
    /// current flag is checked first and the watch re-checked after waking.
    pub async fn wait_stop(&self) {
        let mut watch = self.inner.stop_watch.subscribe();
        loop {
            if self.inner.stop_requested.load(Ordering::SeqCst) {
                return;
            }
            if watch.changed().await.is_err() {
                // The sender is owned by this structure and never dropped.
                return;
            }
        }
    }

    /// Reports whether the SCM already requested a stop.
    #[must_use]
    pub fn is_stop_requested(&self) -> bool {
        self.inner.stop_requested.load(Ordering::SeqCst)
    }

    /// Releases the SCM dispatch thread after the runtime has drained.
    pub fn finish(&self) {
        self.inner.release();
    }
}

impl Default for ServiceControl {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceControlInner {
    fn register_status_handle(&self, handle: SERVICE_STATUS_HANDLE) {
        self.status_handle.store(handle, Ordering::SeqCst);
    }

    fn set_status(&self, state: u32) {
        self.current_state.store(state, Ordering::SeqCst);
        let handle = self.status_handle.load(Ordering::SeqCst);
        set_service_status(handle, state, 0, STATUS_WAIT_HINT_MS);
    }

    fn release(&self) {
        *self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.release_condvar.notify_all();
    }

    fn wait_release(&self) {
        let mut released = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .release_condvar
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Registers the service with the SCM and blocks until the service stops.
///
/// The SCM invokes the static [`service_main`] on its own thread; that
/// thread registers the control handler, reports the RUNNING status through
/// `control_ready`, and parks. This function returns only after
/// `service_main` returns — that is, after [`ServiceControl::finish`] or an
/// SCM stop request.
///
/// # Errors
///
/// Returns an I/O error when the SCM refuses the registration (for example
/// when the process was not started by the SCM).
pub fn dispatch_service(
    control: Arc<ServiceControl>,
    control_ready: oneshot::Sender<io::Result<()>>,
) -> io::Result<()> {
    let service_name = encode_wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    {
        let mut slot = DISPATCH_SLOT
            .lock()
            .map_err(|_| io::Error::other("the service dispatch slot is poisoned"))?;
        *slot = Some(DispatchSlot {
            control,
            ready: Some(control_ready),
        });
    }
    let dispatched = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if dispatched == 0 {
        let code = unsafe { GetLastError() };
        // The SCM never invoked service_main, so the slot is still ours.
        let mut slot = DISPATCH_SLOT
            .lock()
            .map_err(|_| io::Error::other("the service dispatch slot is poisoned"))?;
        slot.take();
        return Err(os_error(code));
    }
    Ok(())
}

/// The SCM-invoked service entry point (static: the SCM requires a fn
/// pointer). Runs on an SCM thread, not on the tokio runtime.
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let slot = DISPATCH_SLOT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some(DispatchSlot { control, ready }) = slot else {
        return;
    };

    let name = encode_wide(SERVICE_NAME);
    // The Arc lives for the whole registration: service_main holds one
    // clone and the handler context borrows the inner state through the raw
    // pointer, which stays valid until the handler is unregistered.
    let context = Arc::as_ptr(&control.inner).cast::<c_void>();
    let status_handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), context) };
    if status_handle.is_null() {
        let code = unsafe { GetLastError() };
        if let Some(ready) = ready {
            let _ = ready.send(Err(os_error(code)));
        }
        return;
    }
    control.inner.register_status_handle(status_handle);
    control.inner.set_status(SERVICE_START_PENDING);
    control.inner.set_status(SERVICE_RUNNING);
    if let Some(ready) = ready {
        let _ = ready.send(Ok(()));
    }
    // Park until the runtime's drain completes: only `finish()` (called by
    // the runtime after its §7.8 drain) releases the condvar, so STOPPED is
    // reported strictly after the drain. An SCM stop request alone wakes the
    // runtime, not this thread.
    control.inner.wait_release();
    control.inner.set_status(SERVICE_STOPPED);
}

/// The SCM control handler: records stop requests and answers interrogates.
unsafe extern "system" fn control_handler(
    control_code: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    // The context pointer borrows the control state registered by
    // `service_main`; the Arc it came from stays alive for the whole
    // registration, so the borrow is valid for the handler's lifetime.
    let Some(control) = (unsafe { (context as *const ServiceControlInner).as_ref() }) else {
        return ERROR_INVALID_PARAMETER;
    };
    match control_code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            control.request_stop();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            let state = control.current_state.load(Ordering::SeqCst);
            let handle = control.status_handle.load(Ordering::SeqCst);
            set_service_status(handle, state, 0, STATUS_WAIT_HINT_MS);
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

impl ServiceControlInner {
    /// Records an SCM stop request: the runtime's stop future resolves and
    /// the status moves to `STOP_PENDING`, but the SCM thread is deliberately
    /// NOT released here — `service_main` parks until [`Self::finish`], which
    /// the runtime calls only after its §7.8 drain completes, so the
    /// `STOPPED` status is never reported before the drain.
    ///
    /// The 30-second wait hint is not the bound on the stop: the SCM treats
    /// it as a hint for its progress reporting and never terminates the
    /// process when it expires. The stop is bounded by the runtime's own
    /// drains — in particular the app runtime's 10-second grace for
    /// in-flight HTTP requests once the stop signal resolves
    /// (`GRACEFUL_DRAIN_TIMEOUT`), which force-completes the server drain
    /// — so a stop lands well inside the hint window.
    fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        let _ = self.stop_watch.send(true);
        self.set_status(SERVICE_STOP_PENDING);
    }
}

fn set_service_status(handle: SERVICE_STATUS_HANDLE, state: u32, checkpoint: u32, wait_hint: u32) {
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    unsafe { SetServiceStatus(handle, std::ptr::from_ref(&status)) };
}

fn encode_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Converts a Win32 error code to an `io::Error` without wrapping casts.
fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(-1))
}

fn scm_error() -> io::Error {
    os_error(unsafe { GetLastError() })
}

/// Registers (or re-registers) the service with the SCM and starts it.
///
/// The binary path is the current executable plus the `service run` argv.
/// An existing service is updated in place so re-installation is idempotent;
/// an already-running service is left running (the start is a no-op then).
///
/// # Errors
///
/// Returns [`super::ServiceInstallError::Scm`] when the SCM refuses the
/// registration, [`super::ServiceInstallError::ScmUpdate`] when the SCM
/// refuses updating an existing service, or
/// [`super::ServiceInstallError::ScmStart`] when the service cannot start.
pub(super) fn install_service(
    arguments: &ServiceArguments,
    executable: &Path,
) -> Result<(), super::ServiceInstallError> {
    use super::ServiceInstallError;

    let binary_path = arguments
        .to_windows_command_line(executable)
        .map_err(ServiceInstallError::CommandLine)?;
    let service_name = encode_wide(SERVICE_NAME);
    let display_name = encode_wide(SERVICE_DISPLAY_NAME);
    let binary = encode_wide(&binary_path);
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if manager.is_null() {
            return Err(ServiceInstallError::Scm(scm_error()));
        }
        let service = CreateServiceW(
            manager,
            service_name.as_ptr(),
            display_name.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        );
        if !service.is_null() {
            let start_result = start_service(service);
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return start_result;
        }
        let code = GetLastError();
        if code != ERROR_SERVICE_EXISTS {
            CloseServiceHandle(manager);
            return Err(ServiceInstallError::Scm(os_error(code)));
        }
        // Re-installation updates the registered command line in place.
        let existing = OpenServiceW(manager, service_name.as_ptr(), SERVICE_ALL_ACCESS);
        if existing.is_null() {
            let open_error = scm_error();
            CloseServiceHandle(manager);
            return Err(ServiceInstallError::Scm(open_error));
        }
        let updated = ChangeServiceConfigW(
            existing,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            display_name.as_ptr(),
        );
        if updated == 0 {
            let update_error = scm_error();
            CloseServiceHandle(existing);
            CloseServiceHandle(manager);
            return Err(ServiceInstallError::ScmUpdate(update_error));
        }
        let start_result = start_service(existing);
        CloseServiceHandle(existing);
        CloseServiceHandle(manager);
        start_result
    }
}

/// Starts one service handle, tolerating an already-running service.
fn start_service(service: SC_HANDLE) -> Result<(), super::ServiceInstallError> {
    use super::ServiceInstallError;

    let started = unsafe { StartServiceW(service, 0, std::ptr::null()) };
    if started == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(ServiceInstallError::ScmStart(os_error(code)));
        }
    }
    Ok(())
}

/// Removes the registered service, stopping it first if it is running.
///
/// # Errors
///
/// Returns [`super::ServiceUninstallError::NotInstalled`] when no service is
/// registered, [`super::ServiceUninstallError::ScmStop`] when the service
/// cannot be stopped, or [`super::ServiceUninstallError::Scm`] when the SCM
/// refuses the removal.
pub(super) fn uninstall_service() -> Result<(), super::ServiceUninstallError> {
    use super::ServiceUninstallError;

    let service_name = encode_wide(SERVICE_NAME);
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ALL_ACCESS);
        if manager.is_null() {
            return Err(ServiceUninstallError::Scm(scm_error()));
        }
        let service = OpenServiceW(manager, service_name.as_ptr(), SERVICE_ALL_ACCESS);
        if service.is_null() {
            let code = GetLastError();
            CloseServiceHandle(manager);
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Err(ServiceUninstallError::NotInstalled { name: SERVICE_NAME });
            }
            return Err(ServiceUninstallError::Scm(os_error(code)));
        }
        if let Err(error) = stop_service(service) {
            CloseServiceHandle(service);
            CloseServiceHandle(manager);
            return Err(error);
        }
        let deleted = DeleteService(service);
        let delete_error = scm_error();
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if deleted == 0 {
            return Err(ServiceUninstallError::Scm(delete_error));
        }
    }
    Ok(())
}

/// Reports whether the product service is registered with the SCM.
///
/// The query opens the SCM read-only (`SC_MANAGER_CONNECT`) and the service
/// with `SERVICE_QUERY_STATUS` only, so the doctor check never requires
/// administrative privileges.
pub(super) fn query_service_status() -> Result<super::ServiceStatus, super::ServiceStatusError> {
    use super::{ServiceStatus, ServiceStatusError};

    let service_name = encode_wide(SERVICE_NAME);
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(ServiceStatusError::Scm(scm_error()));
        }
        let service = OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS);
        if service.is_null() {
            let code = GetLastError();
            CloseServiceHandle(manager);
            if code == ERROR_SERVICE_DOES_NOT_EXIST {
                return Ok(ServiceStatus::NotInstalled);
            }
            return Err(ServiceStatusError::Scm(os_error(code)));
        }
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        Ok(ServiceStatus::Installed)
    }
}

/// Stops one running service and waits for its STOPPED state, tolerating a
/// service that is already stopped.
fn stop_service(service: SC_HANDLE) -> Result<(), super::ServiceUninstallError> {
    use super::ServiceUninstallError;

    // The bound mirrors the service's own stop wait hint (30 seconds).
    const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    let mut status = SERVICE_STATUS::default();
    let controlled = unsafe {
        ControlService(
            service,
            SERVICE_CONTROL_STOP,
            std::ptr::from_mut(&mut status),
        )
    };
    if controlled == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_SERVICE_NOT_ACTIVE {
            return Err(ServiceUninstallError::ScmStop(os_error(code)));
        }
        return Ok(());
    }
    let deadline = std::time::Instant::now() + STOP_TIMEOUT;
    while status.dwCurrentState != SERVICE_STOPPED && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(250));
        let queried = unsafe { QueryServiceStatus(service, std::ptr::from_mut(&mut status)) };
        if queried == 0 {
            return Err(ServiceUninstallError::ScmStop(scm_error()));
        }
    }
    if status.dwCurrentState != SERVICE_STOPPED {
        return Err(ServiceUninstallError::ScmStop(io::Error::other(
            "the service did not stop within 30 seconds",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_encoding_terminates_and_round_trips() {
        let wide = encode_wide(SERVICE_NAME);
        assert_eq!(wide.last(), Some(&0));
        let decoded = wide
            .split(|unit| *unit == 0)
            .next()
            .map(String::from_utf16)
            .ok_or(io::Error::other("empty wide string"))
            .and_then(|result| result.map_err(io::Error::other));

        assert_eq!(decoded.ok(), Some(SERVICE_NAME.to_owned()));
    }
}
