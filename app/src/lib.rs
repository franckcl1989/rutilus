#![forbid(unsafe_code)]

mod backup;
mod doctor;
mod event_listener;
mod initialization_runtime;
mod licenses;
mod onboarding_runtime;
mod scheduler;
mod site_runtime;
mod standalone_runtime;
mod telemetry_sampler;

pub use backup::{
    BackupError, BackupKeyUnlock, BackupOutcome, RestoreOutcome, create_backup, restore_backup,
};
pub use doctor::{CheckLevel, DoctorCheck, DoctorReport, run_doctor};
pub use licenses::{THIRD_PARTY_LICENSES, ThirdPartyLicense, licenses_text};

pub use initialization_runtime::{
    InitializationError, InitializationOutcome, StandaloneUnlock, StandaloneUnlockError,
    initialize_standalone,
};
pub use onboarding_runtime::{
    ActiveCredentialResolver, ActiveCredentialResolverError, EndpointCsvImporter, SystemClock,
    TrustedEndpointEnrollment, endpoint_csv_importer, endpoint_trust_establishment,
    trusted_endpoint_enrollment,
};
pub use site_runtime::{
    ListenAddress, ListenAddressError, SiteBinding, SiteConfigError, SiteInstallError,
    SiteRunError, SiteRunOptions, SiteTls, SiteTlsError, has_system_master_key,
    rewrap_to_system_unlock, run_site,
};
pub use standalone_runtime::{
    StandaloneBinding, StandaloneExecutionError, StandaloneInstance, StandaloneInstanceCloseError,
    StandaloneInstanceError, StandaloneRunError, StandaloneRunOptions, console_stop_signal,
    run_initialized_standalone, run_standalone,
};
