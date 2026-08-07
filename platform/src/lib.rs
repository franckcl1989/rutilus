// `deny` (not `forbid`) so the Windows DPAPI and SCM FFI modules can scope an
// `#![allow(unsafe_code)]` to their wrappers; everything else in this crate
// stays unsafe-free and the workspace lint denies unsafe code everywhere.
#![deny(unsafe_code)]

mod instance_marker;
mod master_key_file;
mod runtime_lock;
mod runtime_paths;
mod service;
mod system_master_key_file;
mod system_secret_store;

pub use instance_marker::{InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState};
pub use master_key_file::{MasterKeyFile, MasterKeyFileError};
pub use runtime_lock::{RuntimeLock, RuntimeLockError};
pub use runtime_paths::{DataLocation, DataPathError, RuntimePaths};
pub use service::{
    ServiceArguments, ServiceArgumentsError, ServiceInstallError, ServiceUninstallError, install,
    uninstall,
};
pub use system_master_key_file::{SystemMasterKeyFile, SystemMasterKeyFileError};
pub use system_secret_store::{SystemSecretStore, SystemSecretStoreError, UnlockSource};

#[cfg(windows)]
pub use service::{ServiceControl, dispatch_service};
