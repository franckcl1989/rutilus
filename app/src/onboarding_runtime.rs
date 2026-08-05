use rutilus_application::{
    BoundaryFuture, Clock, CredentialResolver, EndpointEnrollment, EndpointTrustEstablishment,
    ResolvedCredential,
};
use rutilus_domain::{AuditActor, CredentialId, DeploymentPosture};
use rutilus_infra_redfish::RedfishGateway;
use rutilus_persistence::{CredentialRepositoryError, SqliteStore};
use rutilus_security::{CredentialProtectionError, MasterKey, decrypt_credential};
use thiserror::Error;
use time::OffsetDateTime;

/// Resolves exactly one selected active credential from encrypted persistence.
pub struct ActiveCredentialResolver<'a> {
    store: &'a SqliteStore,
    master_key: &'a MasterKey,
}

impl<'a> ActiveCredentialResolver<'a> {
    #[must_use]
    pub const fn new(store: &'a SqliteStore, master_key: &'a MasterKey) -> Self {
        Self { store, master_key }
    }
}

impl CredentialResolver for ActiveCredentialResolver<'_> {
    type Error = ActiveCredentialResolverError;

    fn resolve(
        &self,
        credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        Box::pin(async move {
            let Some(stored) = self
                .store
                .find_active_credential(credential_id)
                .await
                .map_err(ActiveCredentialResolverError::Repository)?
            else {
                return Ok(None);
            };
            let username = stored.metadata().username().clone();
            let password = decrypt_credential(self.master_key, stored.protected_secret())
                .map_err(ActiveCredentialResolverError::Protection)?;
            Ok(Some(ResolvedCredential::new(username, password)))
        })
    }
}

/// The production wall clock for local application use cases.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// Concrete post-trust enrollment composition used by Edge runtimes.
pub type TrustedEndpointEnrollment<'a> = EndpointEnrollment<
    &'a SqliteStore,
    ActiveCredentialResolver<'a>,
    &'a RedfishGateway,
    SystemClock,
>;

/// Wires the credential-free TLS probe into the first stage of endpoint
/// onboarding.
#[must_use]
pub fn endpoint_trust_establishment(
    gateway: &RedfishGateway,
) -> EndpointTrustEstablishment<&RedfishGateway, SystemClock> {
    EndpointTrustEstablishment::new(gateway, SystemClock)
}

/// Wires endpoint discovery and the mandatory first complete refresh into one
/// post-trust enrollment use case.
#[must_use]
pub fn trusted_endpoint_enrollment<'a>(
    store: &'a SqliteStore,
    master_key: &'a MasterKey,
    gateway: &'a RedfishGateway,
    actor: AuditActor,
    origin: DeploymentPosture,
) -> TrustedEndpointEnrollment<'a> {
    EndpointEnrollment::new(
        store,
        ActiveCredentialResolver::new(store, master_key),
        gateway,
        SystemClock,
        actor,
        origin,
    )
}

/// A secret-safe failure while loading and decrypting an active credential.
#[derive(Debug, Error)]
pub enum ActiveCredentialResolverError {
    #[error("failed to load the selected active credential: {0}")]
    Repository(#[source] CredentialRepositoryError),
    #[error("failed to authenticate the selected encrypted credential: {0}")]
    Protection(#[source] CredentialProtectionError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_application::{Clock, CredentialResolver, EndpointTrustEstablishment};
    use rutilus_domain::{CredentialId, CredentialName, CredentialUsername, CredentialVersionId};
    use rutilus_persistence::NewCredential;
    use rutilus_security::encrypt_credential;
    use secrecy::{ExposeSecret, SecretString};

    use super::*;

    #[test]
    fn exposes_the_concrete_tls_trust_composition() {
        fn assert_factory(
            _factory: for<'a> fn(
                &'a RedfishGateway,
            )
                -> EndpointTrustEstablishment<&'a RedfishGateway, SystemClock>,
        ) {
        }

        assert_factory(endpoint_trust_establishment);
    }

    #[test]
    fn exposes_the_complete_endpoint_enrollment_composition() {
        fn assert_factory(
            _factory: for<'a> fn(
                &'a SqliteStore,
                &'a MasterKey,
                &'a RedfishGateway,
                AuditActor,
                DeploymentPosture,
            ) -> TrustedEndpointEnrollment<'a>,
        ) {
        }

        assert_factory(trusted_endpoint_enrollment);
    }

    #[tokio::test]
    async fn resolves_only_the_selected_active_credential() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x61; 32]));
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = String::from("active secret").into();
        let protected = encrypt_credential(&master_key, credential_id, version_id, &plaintext)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("BMC administrator")?,
                CredentialUsername::parse("administrator")?,
                protected,
            ))
            .await?;

        {
            let resolver = ActiveCredentialResolver::new(&store, &master_key);
            let active = resolver
                .resolve(credential_id)
                .await?
                .ok_or("active credential is missing")?;
            assert_eq!(active.username().as_str(), "administrator");
            assert_eq!(active.password().expose_secret(), "active secret");
            assert!(resolver.resolve(CredentialId::generate()).await?.is_none());
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_ciphertext_under_a_different_master_key() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let encryption_key = MasterKey::from_boxed_bytes(Box::new([0x62; 32]));
        let wrong_key = MasterKey::from_boxed_bytes(Box::new([0x63; 32]));
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let plaintext: SecretString = String::from("must remain secret").into();
        let protected = encrypt_credential(&encryption_key, credential_id, version_id, &plaintext)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("Encrypted BMC")?,
                CredentialUsername::parse("operator")?,
                protected,
            ))
            .await?;

        {
            let resolver = ActiveCredentialResolver::new(&store, &wrong_key);
            let error = match resolver.resolve(credential_id).await {
                Err(
                    error @ ActiveCredentialResolverError::Protection(
                        CredentialProtectionError::AuthenticationFailed,
                    ),
                ) => error,
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "credential unexpectedly decrypted with a different key",
                    )
                    .into());
                }
            };
            let message = error.to_string();
            assert!(!message.contains("must remain secret"));
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[test]
    fn system_clock_reports_current_utc_time() {
        let before = OffsetDateTime::now_utc();
        let observed = SystemClock.now();
        let after = OffsetDateTime::now_utc();

        assert!(observed >= before);
        assert!(observed <= after);
    }
}
