#![forbid(unsafe_code)]

mod backup;
mod center_acceptor;
mod center_ca;
mod center_client;
mod center_runtime;
mod center_transport;
mod center_ws;
mod doctor;
mod event_listener;
mod initialization_runtime;
mod licenses;
mod onboarding_runtime;
mod scheduler;
mod site_runtime;
mod standalone_runtime;
mod telemetry_sampler;
mod tls_material;
mod x509;

pub use backup::{
    BackupError, BackupKeyUnlock, BackupOutcome, RestoreOutcome, create_backup, restore_backup,
};
pub use center_acceptor::{
    AcceptedCenterConnection, CenterAcceptError, CenterAcceptor, CenterAcceptorError,
    CenterAcceptorOptions, CenterAdmissionResolver, CenterConnection, CenterConnectionError,
    ClientIdentity,
};
pub use center_ca::{CenterCa, CenterCaError, SiteClientCertificate};
pub use center_client::{CenterClientConfig, CenterClientError, CenterClientOptions, CenterLink};
pub use center_runtime::{
    CenterCaIssuer, CenterRunError, CenterRunOptions, CenterServicesError, run_center,
};
pub use center_ws::CenterFrameHandler;
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
    SiteRunError, SiteRunOptions, SiteTls, SiteTlsError, UnbindError, UnbindOutcome,
    has_system_master_key, rewrap_to_system_unlock, run_site, unbind_from_center,
};
pub use standalone_runtime::{
    StandaloneBinding, StandaloneExecutionError, StandaloneInstance, StandaloneInstanceCloseError,
    StandaloneInstanceError, StandaloneRunError, StandaloneRunOptions, console_stop_signal,
    run_initialized_standalone, run_standalone,
};
pub use tls_material::TlsMaterialError;
pub use x509::DerReadError;
