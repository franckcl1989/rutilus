use rutilus_domain::{
    CertificateFingerprint, CredentialId, Endpoint, EndpointAddress, EndpointAddressError,
    EndpointDisplayName, EndpointDisplayNameError, EndpointId, EndpointTimelineError,
    PinnedCertificate, PinnedCertificateError, TlsTrust,
};
use rutilus_entity::{credential, endpoint, endpoint_address, endpoint_credential, endpoint_trust};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set, SqlErr,
    TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

const CERTIFICATE_FINGERPRINT_LENGTH: usize = 32;

impl SqliteStore {
    /// Atomically persists a validated endpoint, active address, TLS trust, and
    /// credential binding.
    ///
    /// This method performs no network access and never transmits credentials.
    /// The caller must establish [`TlsTrust`] before constructing the endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointRepositoryError`] when the bound credential is absent
    /// or inactive, identity or address uniqueness is violated, write
    /// coordination fails, or the transaction cannot commit.
    pub async fn create_endpoint(
        &self,
        domain: Endpoint,
    ) -> Result<Endpoint, EndpointRepositoryError> {
        let endpoint_id = domain.id();
        let credential_id = domain.credential_id();
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(EndpointRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(EndpointRepositoryError::Database)?;

        let bound_credential = credential::Entity::find_by_id(credential_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(EndpointRepositoryError::Database)?
            .ok_or(EndpointRepositoryError::CredentialNotFound { credential_id })?;
        if bound_credential.active_version_id.is_none() {
            return Err(EndpointRepositoryError::CredentialInactive { credential_id });
        }

        endpoint::ActiveModel {
            id: Set(endpoint_id.into_uuid()),
            display_name: Set(domain.display_name().to_string()),
            created_at: Set(domain.created_at()),
            updated_at: Set(domain.updated_at()),
        }
        .insert(&transaction)
        .await
        .map_err(map_endpoint_insert_error)?;

        endpoint_address::ActiveModel {
            id: Set(uuid::Uuid::now_v7()),
            endpoint_id: Set(endpoint_id.into_uuid()),
            address: Set(domain.address().to_string()),
            is_active: Set(true),
            created_at: Set(domain.created_at()),
            retired_at: Set(None),
        }
        .insert(&transaction)
        .await
        .map_err(map_endpoint_insert_error)?;

        let (trust_mode, certificate_sha256, certificate_der, trusted_at) = match domain.trust() {
            TlsTrust::SystemCa { verified_at } => (
                endpoint_trust::TrustMode::SystemCa,
                None,
                None,
                *verified_at,
            ),
            TlsTrust::PinnedCertificate {
                certificate,
                trusted_at,
            } => (
                endpoint_trust::TrustMode::PinnedCertificate,
                Some(certificate.fingerprint().into_bytes().to_vec()),
                Some(certificate.certificate_der().to_vec()),
                *trusted_at,
            ),
        };
        endpoint_trust::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            trust_mode: Set(trust_mode),
            certificate_sha256: Set(certificate_sha256),
            certificate_der: Set(certificate_der),
            trusted_at: Set(trusted_at),
        }
        .insert(&transaction)
        .await
        .map_err(map_endpoint_insert_error)?;

        endpoint_credential::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            credential_id: Set(credential_id.into_uuid()),
            assigned_at: Set(domain.updated_at()),
        }
        .insert(&transaction)
        .await
        .map_err(map_endpoint_insert_error)?;

        transaction
            .commit()
            .await
            .map_err(EndpointRepositoryError::Database)?;
        Ok(domain)
    }

    /// Finds a complete, secret-free endpoint aggregate by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointRepositoryError`] when a query fails or any persisted
    /// component violates the domain, TLS trust, or timeline invariants.
    pub async fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Option<Endpoint>, EndpointRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(EndpointRepositoryError::Database)?;
        let Some(endpoint_model) = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(EndpointRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(EndpointRepositoryError::Database)?;
            return Ok(None);
        };

        let domain = map_stored_endpoint(&transaction, endpoint_id, endpoint_model).await?;
        transaction
            .commit()
            .await
            .map_err(EndpointRepositoryError::Database)?;
        Ok(Some(domain))
    }
}

async fn map_stored_endpoint<C>(
    database: &C,
    endpoint_id: EndpointId,
    endpoint_model: endpoint::Model,
) -> Result<Endpoint, EndpointRepositoryError>
where
    C: ConnectionTrait,
{
    let addresses = endpoint_address::Entity::find()
        .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
        .filter(endpoint_address::Column::IsActive.eq(true))
        .all(database)
        .await
        .map_err(EndpointRepositoryError::Database)?;
    let address_model = match addresses.as_slice() {
        [] => {
            return Err(corrupt(
                endpoint_id,
                StoredEndpointError::ActiveAddressMissing,
            ));
        }
        [address] => address,
        _ => {
            return Err(corrupt(
                endpoint_id,
                StoredEndpointError::MultipleActiveAddresses,
            ));
        }
    };
    if address_model.retired_at.is_some() {
        return Err(corrupt(
            endpoint_id,
            StoredEndpointError::ActiveAddressRetired,
        ));
    }
    validate_component_time(
        address_model.created_at,
        endpoint_model.created_at,
        endpoint_model.updated_at,
        StoredEndpointError::AddressOutsideTimeline,
        endpoint_id,
    )?;

    let trust_model = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
        .one(database)
        .await
        .map_err(EndpointRepositoryError::Database)?
        .ok_or_else(|| corrupt(endpoint_id, StoredEndpointError::TrustMissing))?;
    let trust = map_trust(trust_model).map_err(|source| corrupt(endpoint_id, source))?;

    let binding = endpoint_credential::Entity::find_by_id(endpoint_id.into_uuid())
        .one(database)
        .await
        .map_err(EndpointRepositoryError::Database)?
        .ok_or_else(|| corrupt(endpoint_id, StoredEndpointError::CredentialBindingMissing))?;
    validate_component_time(
        binding.assigned_at,
        endpoint_model.created_at,
        endpoint_model.updated_at,
        StoredEndpointError::CredentialBindingOutsideTimeline,
        endpoint_id,
    )?;
    let credential_id = CredentialId::from_uuid(binding.credential_id);
    let bound_credential = credential::Entity::find_by_id(binding.credential_id)
        .one(database)
        .await
        .map_err(EndpointRepositoryError::Database)?
        .ok_or_else(|| {
            corrupt(
                endpoint_id,
                StoredEndpointError::BoundCredentialMissing { credential_id },
            )
        })?;
    if bound_credential.active_version_id.is_none() {
        return Err(corrupt(
            endpoint_id,
            StoredEndpointError::BoundCredentialInactive { credential_id },
        ));
    }

    let display_name = EndpointDisplayName::parse(&endpoint_model.display_name)
        .map_err(StoredEndpointError::InvalidDisplayName)
        .map_err(|source| corrupt(endpoint_id, source))?;
    let address = EndpointAddress::parse(&address_model.address)
        .map_err(StoredEndpointError::InvalidAddress)
        .map_err(|source| corrupt(endpoint_id, source))?;
    Endpoint::try_new(
        endpoint_id,
        display_name,
        address,
        trust,
        credential_id,
        endpoint_model.created_at,
        endpoint_model.updated_at,
    )
    .map_err(StoredEndpointError::InvalidTimeline)
    .map_err(|source| corrupt(endpoint_id, source))
}

fn map_trust(model: endpoint_trust::Model) -> Result<TlsTrust, StoredEndpointError> {
    match model.trust_mode {
        endpoint_trust::TrustMode::SystemCa => {
            if model.certificate_sha256.is_some() || model.certificate_der.is_some() {
                return Err(StoredEndpointError::UnexpectedSystemCaCertificate);
            }
            Ok(TlsTrust::SystemCa {
                verified_at: model.trusted_at,
            })
        }
        endpoint_trust::TrustMode::PinnedCertificate => {
            let fingerprint = model
                .certificate_sha256
                .ok_or(StoredEndpointError::PinnedFingerprintMissing)?;
            let actual = fingerprint.len();
            let fingerprint = fingerprint.try_into().map_err(|_| {
                StoredEndpointError::InvalidFingerprintLength {
                    actual,
                    expected: CERTIFICATE_FINGERPRINT_LENGTH,
                }
            })?;
            let certificate_der = model
                .certificate_der
                .ok_or(StoredEndpointError::PinnedCertificateMissing)?;
            let certificate = PinnedCertificate::from_parts(
                CertificateFingerprint::from_bytes(fingerprint),
                certificate_der,
            )
            .map_err(StoredEndpointError::InvalidPinnedCertificate)?;
            Ok(TlsTrust::PinnedCertificate {
                certificate,
                trusted_at: model.trusted_at,
            })
        }
    }
}

fn validate_component_time(
    component_time: time::OffsetDateTime,
    created_at: time::OffsetDateTime,
    updated_at: time::OffsetDateTime,
    error: StoredEndpointError,
    endpoint_id: EndpointId,
) -> Result<(), EndpointRepositoryError> {
    if component_time < created_at || component_time > updated_at {
        return Err(corrupt(endpoint_id, error));
    }
    Ok(())
}

fn corrupt(endpoint_id: EndpointId, source: StoredEndpointError) -> EndpointRepositoryError {
    EndpointRepositoryError::Corrupt {
        endpoint_id,
        source,
    }
}

fn map_endpoint_insert_error(error: DbErr) -> EndpointRepositoryError {
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        EndpointRepositoryError::AlreadyExists
    } else {
        EndpointRepositoryError::Database(error)
    }
}

/// A controlled failure while creating or reading managed endpoints.
#[derive(Debug, Error)]
pub enum EndpointRepositoryError {
    #[error("endpoint write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("endpoint identity or address already exists")]
    AlreadyExists,
    #[error("credential {credential_id} was not found")]
    CredentialNotFound { credential_id: CredentialId },
    #[error("credential {credential_id} has no active encrypted version")]
    CredentialInactive { credential_id: CredentialId },
    #[error("stored endpoint {endpoint_id} is invalid: {source}")]
    Corrupt {
        endpoint_id: EndpointId,
        #[source]
        source: StoredEndpointError,
    },
    #[error("endpoint database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted endpoint data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredEndpointError {
    #[error("endpoint display name is invalid: {0}")]
    InvalidDisplayName(#[source] EndpointDisplayNameError),
    #[error("endpoint address is invalid: {0}")]
    InvalidAddress(#[source] EndpointAddressError),
    #[error("endpoint has no active address")]
    ActiveAddressMissing,
    #[error("endpoint has multiple active addresses")]
    MultipleActiveAddresses,
    #[error("endpoint active address is marked retired")]
    ActiveAddressRetired,
    #[error("endpoint active address timestamp is outside the endpoint timeline")]
    AddressOutsideTimeline,
    #[error("endpoint has no TLS trust decision")]
    TrustMissing,
    #[error("system CA trust unexpectedly stores pinned certificate data")]
    UnexpectedSystemCaCertificate,
    #[error("pinned certificate fingerprint is missing")]
    PinnedFingerprintMissing,
    #[error("pinned certificate DER is missing")]
    PinnedCertificateMissing,
    #[error("pinned certificate fingerprint has {actual} bytes; expected {expected}")]
    InvalidFingerprintLength { actual: usize, expected: usize },
    #[error("pinned certificate data is invalid: {0}")]
    InvalidPinnedCertificate(#[source] PinnedCertificateError),
    #[error("endpoint has no credential binding")]
    CredentialBindingMissing,
    #[error("endpoint credential binding timestamp is outside the endpoint timeline")]
    CredentialBindingOutsideTimeline,
    #[error("bound credential {credential_id} is missing")]
    BoundCredentialMissing { credential_id: CredentialId },
    #[error("bound credential {credential_id} has no active encrypted version")]
    BoundCredentialInactive { credential_id: CredentialId },
    #[error("endpoint timeline is invalid: {0}")]
    InvalidTimeline(#[source] EndpointTimelineError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        CredentialName, CredentialUsername, CredentialVersionId, EndpointDisplayName,
    };
    use rutilus_security::{MasterKey, encrypt_credential};
    use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, PaginatorTrait};
    use secrecy::SecretString;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::NewCredential;

    #[tokio::test]
    async fn creates_and_loads_system_ca_and_pinned_endpoints() -> Result<(), Box<dyn Error>> {
        let (directory, store, credential_id) = store_with_credential("endpoint trust").await?;
        let system_ca = test_endpoint(
            credential_id,
            "Rack A BMC",
            "https://192.0.2.10/redfish",
            TrustFixture::SystemCa,
        )?;
        let pinned = test_endpoint(
            credential_id,
            "Rack B BMC",
            "https://192.0.2.11",
            TrustFixture::Pinned,
        )?;

        assert_eq!(store.create_endpoint(system_ca.clone()).await?, system_ca);
        assert_eq!(store.create_endpoint(pinned.clone()).await?, pinned);
        assert_eq!(store.find_endpoint(system_ca.id()).await?, Some(system_ca));
        assert_eq!(store.find_endpoint(pinned.id()).await?, Some(pinned));
        assert!(store.find_endpoint(EndpointId::generate()).await?.is_none());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn missing_or_inactive_credentials_cannot_be_bound() -> Result<(), Box<dyn Error>> {
        let (directory, store, credential_id) = store_with_credential("credential state").await?;
        let missing_id = CredentialId::generate();
        let missing_endpoint = test_endpoint(
            missing_id,
            "Missing credential",
            "https://192.0.2.20",
            TrustFixture::SystemCa,
        )?;
        assert!(matches!(
            store.create_endpoint(missing_endpoint).await,
            Err(EndpointRepositoryError::CredentialNotFound { credential_id })
                if credential_id == missing_id
        ));

        let credential_model = credential::Entity::find_by_id(credential_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("credential is missing")?;
        let mut credential_model = credential_model.into_active_model();
        credential_model.active_version_id = Set(None);
        credential_model.update(&store.database).await?;
        let inactive_endpoint = test_endpoint(
            credential_id,
            "Inactive credential",
            "https://192.0.2.21",
            TrustFixture::SystemCa,
        )?;
        assert!(matches!(
            store.create_endpoint(inactive_endpoint).await,
            Err(EndpointRepositoryError::CredentialInactive { credential_id: id })
                if id == credential_id
        ));
        assert_eq!(endpoint::Entity::find().count(&store.database).await?, 0);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_address_rolls_back_the_entire_aggregate() -> Result<(), Box<dyn Error>> {
        let (directory, store, credential_id) = store_with_credential("duplicate endpoint").await?;
        let first = test_endpoint(
            credential_id,
            "First endpoint",
            "https://192.0.2.30",
            TrustFixture::SystemCa,
        )?;
        store.create_endpoint(first).await?;
        let duplicate = test_endpoint(
            credential_id,
            "Duplicate endpoint",
            "https://192.0.2.30",
            TrustFixture::Pinned,
        )?;
        let duplicate_id = duplicate.id();
        assert!(matches!(
            store.create_endpoint(duplicate).await,
            Err(EndpointRepositoryError::AlreadyExists)
        ));
        assert!(
            endpoint::Entity::find_by_id(duplicate_id.into_uuid())
                .one(&store.database)
                .await?
                .is_none()
        );
        assert!(
            endpoint_trust::Entity::find_by_id(duplicate_id.into_uuid())
                .one(&store.database)
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_corrupt_pinned_certificate_without_accepting_it() -> Result<(), Box<dyn Error>>
    {
        let (directory, store, credential_id) = store_with_credential("corrupt endpoint").await?;
        let endpoint = test_endpoint(
            credential_id,
            "Pinned endpoint",
            "https://192.0.2.40",
            TrustFixture::Pinned,
        )?;
        let endpoint_id = endpoint.id();
        store.create_endpoint(endpoint).await?;

        let trust_model = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("endpoint trust is missing")?;
        let mut trust_model = trust_model.into_active_model();
        trust_model.certificate_sha256 = Set(Some(vec![0_u8; CERTIFICATE_FINGERPRINT_LENGTH]));
        trust_model.update(&store.database).await?;

        assert!(matches!(
            store.find_endpoint(endpoint_id).await,
            Err(EndpointRepositoryError::Corrupt {
                source: StoredEndpointError::InvalidPinnedCertificate(
                    PinnedCertificateError::FingerprintMismatch
                ),
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum TrustFixture {
        SystemCa,
        Pinned,
    }

    fn test_endpoint(
        credential_id: CredentialId,
        display_name: &str,
        address: &str,
        trust_fixture: TrustFixture,
    ) -> Result<Endpoint, Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let updated_at = created_at + Duration::SECOND;
        let trust = match trust_fixture {
            TrustFixture::SystemCa => TlsTrust::SystemCa {
                verified_at: updated_at,
            },
            TrustFixture::Pinned => TlsTrust::PinnedCertificate {
                certificate: PinnedCertificate::from_der(b"test leaf certificate".to_vec())?,
                trusted_at: updated_at,
            },
        };
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse(display_name)?,
            EndpointAddress::parse(address)?,
            trust,
            credential_id,
            created_at,
            updated_at,
        )?)
    }

    async fn store_with_credential(
        name: &str,
    ) -> Result<(tempfile::TempDir, SqliteStore, CredentialId), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let key = MasterKey::from_boxed_bytes(Box::new([0x51; 32]));
        let secret: SecretString = String::from("test secret").into();
        let protected_secret = encrypt_credential(&key, credential_id, version_id, &secret)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse(name)?,
                CredentialUsername::parse("administrator")?,
                protected_secret,
            ))
            .await?;
        Ok((directory, store, credential_id))
    }
}
