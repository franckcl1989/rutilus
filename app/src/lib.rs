#![forbid(unsafe_code)]

mod onboarding_runtime;

pub use onboarding_runtime::{
    ActiveCredentialResolver, ActiveCredentialResolverError, SystemClock,
    trusted_endpoint_onboarding,
};
