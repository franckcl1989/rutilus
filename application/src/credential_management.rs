use std::{collections::BTreeSet, error::Error, fmt};

use rutilus_domain::{
    Credential, CredentialId, CredentialName, CredentialUsername, CredentialVersionId,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{BoundaryFuture, Clock};

/// Maximum UTF-8 byte length accepted for one BMC password at the application
/// boundary.
pub const CREDENTIAL_SECRET_MAX_BYTES: usize = 4 * 1024;

/// Validated metadata and an in-memory-only plaintext for one reusable BMC
/// credential.
pub struct NewCredentialRequest {
    name: CredentialName,
    username: CredentialUsername,
    password: SecretString,
}

impl NewCredentialRequest {
    /// Validates the only credential field that is intentionally not a domain
    /// value object.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialSecretError`] for an empty password or one larger
    /// than [`CREDENTIAL_SECRET_MAX_BYTES`].
    pub fn try_new(
        name: CredentialName,
        username: CredentialUsername,
        password: SecretString,
    ) -> Result<Self, CredentialSecretError> {
        let actual = password.expose_secret().len();
        if actual == 0 {
            return Err(CredentialSecretError::Empty);
        }
        if actual > CREDENTIAL_SECRET_MAX_BYTES {
            return Err(CredentialSecretError::TooLarge {
                actual,
                maximum: CREDENTIAL_SECRET_MAX_BYTES,
            });
        }
        Ok(Self {
            name,
            username,
            password,
        })
    }

    fn into_parts(self) -> (CredentialName, CredentialUsername, SecretString) {
        (self.name, self.username, self.password)
    }
}

impl fmt::Debug for NewCredentialRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewCredentialRequest")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Why an in-memory BMC password cannot enter credential creation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialSecretError {
    #[error("credential password cannot be empty")]
    Empty,
    #[error("credential password has {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
}

/// Protects a plaintext credential before any persistence boundary can see it.
pub trait CredentialSecretProtector: Send + Sync {
    type Protected: Send + 'static;
    type Error: Error + Send + Sync + 'static;

    /// Binds protected secret material to the preallocated credential and
    /// version identities.
    ///
    /// # Errors
    ///
    /// Returns the implementation's typed failure when randomness, key access,
    /// or authenticated encryption cannot safely complete.
    fn protect(
        &self,
        credential_id: CredentialId,
        version_id: CredentialVersionId,
        password: SecretString,
    ) -> Result<Self::Protected, Self::Error>;
}

impl<Protector> CredentialSecretProtector for &Protector
where
    Protector: CredentialSecretProtector + ?Sized,
{
    type Protected = Protector::Protected;
    type Error = Protector::Error;

    fn protect(
        &self,
        credential_id: CredentialId,
        version_id: CredentialVersionId,
        password: SecretString,
    ) -> Result<Self::Protected, Self::Error> {
        Protector::protect(*self, credential_id, version_id, password)
    }
}

/// Application-owned write model containing only protected secret material.
pub struct ProtectedCredentialCreation<Protected> {
    credential_id: CredentialId,
    version_id: CredentialVersionId,
    name: CredentialName,
    username: CredentialUsername,
    protected_secret: Protected,
    created_at: OffsetDateTime,
}

impl<Protected> ProtectedCredentialCreation<Protected> {
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    #[must_use]
    pub const fn version_id(&self) -> CredentialVersionId {
        self.version_id
    }

    #[must_use]
    pub const fn name(&self) -> &CredentialName {
        &self.name
    }

    #[must_use]
    pub const fn username(&self) -> &CredentialUsername {
        &self.username
    }

    #[must_use]
    pub const fn protected_secret(&self) -> &Protected {
        &self.protected_secret
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialId,
        CredentialVersionId,
        CredentialName,
        CredentialUsername,
        Protected,
        OffsetDateTime,
    ) {
        (
            self.credential_id,
            self.version_id,
            self.name,
            self.username,
            self.protected_secret,
            self.created_at,
        )
    }
}

/// Persists one credential only after its plaintext has been protected.
pub trait CredentialCreationRepository<Protected>: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn create_credential(
        &self,
        creation: ProtectedCredentialCreation<Protected>,
    ) -> BoundaryFuture<'_, Result<Credential, Self::Error>>;
}

impl<Repository, Protected> CredentialCreationRepository<Protected> for &Repository
where
    Repository: CredentialCreationRepository<Protected> + ?Sized,
    Protected: Send + 'static,
{
    type Error = Repository::Error;

    fn create_credential(
        &self,
        creation: ProtectedCredentialCreation<Protected>,
    ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
        Repository::create_credential(*self, creation)
    }
}

/// Encrypts and persists one reusable credential without allowing plaintext to
/// cross the repository boundary.
pub struct CredentialCreation<Protector, Repository, Time> {
    protector: Protector,
    repository: Repository,
    clock: Time,
}

impl<Protector, Repository, Time> CredentialCreation<Protector, Repository, Time>
where
    Protector: CredentialSecretProtector,
    Repository: CredentialCreationRepository<Protector::Protected>,
    Time: Clock,
{
    #[must_use]
    pub const fn new(protector: Protector, repository: Repository, clock: Time) -> Self {
        Self {
            protector,
            repository,
            clock,
        }
    }

    /// Protects plaintext first, then persists one identity-bound version and
    /// verifies the repository's returned domain state.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialCreationError`] for protection, persistence, or a
    /// repository response that does not describe the requested creation.
    pub async fn execute(
        &self,
        request: NewCredentialRequest,
    ) -> Result<Credential, CredentialCreationError<Protector::Error, Repository::Error>> {
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let (name, username, password) = request.into_parts();
        let expected_name = name.clone();
        let expected_username = username.clone();
        let protected_secret = self
            .protector
            .protect(credential_id, version_id, password)
            .map_err(CredentialCreationError::Protection)?;
        let created_at = self.clock.now();
        let persisted = self
            .repository
            .create_credential(ProtectedCredentialCreation {
                credential_id,
                version_id,
                name,
                username,
                protected_secret,
                created_at,
            })
            .await
            .map_err(CredentialCreationError::Repository)?;
        if persisted.id() != credential_id
            || persisted.active_version_id() != version_id
            || persisted.name() != &expected_name
            || persisted.username() != &expected_username
            || persisted.created_at() != created_at
            || persisted.updated_at() != created_at
        {
            return Err(CredentialCreationError::IncoherentPersistence { credential_id });
        }
        Ok(persisted)
    }
}

/// A controlled credential-creation failure that never contains plaintext.
#[derive(Debug, Error)]
pub enum CredentialCreationError<ProtectionError, RepositoryError>
where
    ProtectionError: Error + 'static,
    RepositoryError: Error + 'static,
{
    #[error("failed to protect the new credential: {0}")]
    Protection(#[source] ProtectionError),
    #[error("failed to persist the protected credential: {0}")]
    Repository(#[source] RepositoryError),
    #[error("credential repository returned incoherent state for {credential_id}")]
    IncoherentPersistence { credential_id: CredentialId },
}

/// Loads secret-free reusable credential metadata.
pub trait CredentialInventoryRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>>;
}

impl<Repository> CredentialInventoryRepository for &Repository
where
    Repository: CredentialInventoryRepository + ?Sized,
{
    type Error = Repository::Error;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        Repository::list_credentials(*self)
    }
}

/// Lists credential metadata in deterministic product order.
pub struct CredentialInventoryQuery<Repository> {
    repository: Repository,
}

impl<Repository> CredentialInventoryQuery<Repository>
where
    Repository: CredentialInventoryRepository,
{
    #[must_use]
    pub const fn new(repository: Repository) -> Self {
        Self { repository }
    }

    /// Rejects duplicate credential and active-version identities, then sorts
    /// by display name, username, and stable identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialInventoryQueryError`] when persistence fails or
    /// returns ambiguous identity state.
    pub async fn execute(
        &self,
    ) -> Result<Vec<Credential>, CredentialInventoryQueryError<Repository::Error>> {
        let mut credentials = self
            .repository
            .list_credentials()
            .await
            .map_err(CredentialInventoryQueryError::Repository)?;
        let mut credential_ids = BTreeSet::new();
        let mut version_ids = BTreeSet::new();
        for credential in &credentials {
            if !credential_ids.insert(credential.id()) {
                return Err(CredentialInventoryQueryError::DuplicateCredential {
                    credential_id: credential.id(),
                });
            }
            if !version_ids.insert(credential.active_version_id()) {
                return Err(CredentialInventoryQueryError::DuplicateActiveVersion {
                    version_id: credential.active_version_id(),
                });
            }
        }
        credentials.sort_by(|left, right| {
            left.name()
                .cmp(right.name())
                .then_with(|| left.username().cmp(right.username()))
                .then_with(|| left.id().cmp(&right.id()))
        });
        Ok(credentials)
    }
}

/// A controlled failure while listing secret-free credential metadata.
#[derive(Debug, Error)]
pub enum CredentialInventoryQueryError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("failed to load credential inventory: {0}")]
    Repository(#[source] RepositoryError),
    #[error("credential inventory repeats credential {credential_id}")]
    DuplicateCredential { credential_id: CredentialId },
    #[error("credential inventory repeats active version {version_id}")]
    DuplicateActiveVersion { version_id: CredentialVersionId },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use secrecy::ExposeSecret;

    use super::*;

    const CREATED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    #[test]
    fn validates_and_redacts_plaintext_requests() -> Result<(), Box<dyn Error>> {
        let request = request("Rack administrators", "administrator", "must stay secret")?;
        let rendered = format!("{request:?}");

        assert!(rendered.contains("Rack administrators"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("must stay secret"));
        assert!(matches!(
            NewCredentialRequest::try_new(
                CredentialName::parse("Empty")?,
                CredentialUsername::parse("admin")?,
                String::new().into()
            ),
            Err(CredentialSecretError::Empty)
        ));
        assert!(matches!(
            NewCredentialRequest::try_new(
                CredentialName::parse("Too large")?,
                CredentialUsername::parse("admin")?,
                "x".repeat(CREDENTIAL_SECRET_MAX_BYTES + 1).into()
            ),
            Err(CredentialSecretError::TooLarge {
                actual,
                maximum: CREDENTIAL_SECRET_MAX_BYTES
            }) if actual == CREDENTIAL_SECRET_MAX_BYTES + 1
        ));
        Ok(())
    }

    #[tokio::test]
    async fn protects_before_persisting_and_verifies_returned_state() -> Result<(), Box<dyn Error>>
    {
        let creation = CredentialCreation::new(
            MockProtector::Accept,
            MockCreationRepository::Coherent,
            FixedClock,
        );
        let credential = creation
            .execute(request(
                "Rack administrators",
                "administrator",
                "must stay secret",
            )?)
            .await?;

        assert_eq!(credential.name().as_str(), "Rack administrators");
        assert_eq!(credential.username().as_str(), "administrator");
        assert_eq!(credential.created_at(), CREATED_AT);
        assert_eq!(credential.updated_at(), CREATED_AT);
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_protection_persistence_and_incoherent_state()
    -> Result<(), Box<dyn Error>> {
        let protection = CredentialCreation::new(
            MockProtector::Reject,
            MockCreationRepository::Coherent,
            FixedClock,
        )
        .execute(request("Protected", "admin", "must stay secret")?)
        .await;
        assert!(matches!(
            protection,
            Err(CredentialCreationError::Protection(MockError))
        ));

        let persistence = CredentialCreation::new(
            MockProtector::Accept,
            MockCreationRepository::Reject,
            FixedClock,
        )
        .execute(request("Persisted", "admin", "must stay secret")?)
        .await;
        assert!(matches!(
            persistence,
            Err(CredentialCreationError::Repository(MockError))
        ));

        let incoherent = CredentialCreation::new(
            MockProtector::Accept,
            MockCreationRepository::Incoherent,
            FixedClock,
        )
        .execute(request("Incoherent", "admin", "must stay secret")?)
        .await;
        assert!(matches!(
            incoherent,
            Err(CredentialCreationError::IncoherentPersistence { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sorts_inventory_and_rejects_ambiguous_identities() -> Result<(), Box<dyn Error>> {
        let alpha = credential("Alpha", "operator")?;
        let beta = credential("Beta", "administrator")?;
        let ordered =
            CredentialInventoryQuery::new(MockInventory::Items(vec![beta.clone(), alpha.clone()]))
                .execute()
                .await?;
        assert_eq!(ordered, vec![alpha.clone(), beta]);

        let duplicate_id =
            CredentialInventoryQuery::new(MockInventory::Items(vec![alpha.clone(), alpha.clone()]))
                .execute()
                .await;
        assert!(matches!(
            duplicate_id,
            Err(CredentialInventoryQueryError::DuplicateCredential { .. })
        ));

        let shared_version = Credential::try_new(
            CredentialId::generate(),
            CredentialName::parse("Another")?,
            CredentialUsername::parse("another")?,
            alpha.active_version_id(),
            CREATED_AT,
            CREATED_AT,
        )?;
        let duplicate_version =
            CredentialInventoryQuery::new(MockInventory::Items(vec![alpha, shared_version]))
                .execute()
                .await;
        assert!(matches!(
            duplicate_version,
            Err(CredentialInventoryQueryError::DuplicateActiveVersion { .. })
        ));
        assert!(matches!(
            CredentialInventoryQuery::new(MockInventory::Reject)
                .execute()
                .await,
            Err(CredentialInventoryQueryError::Repository(MockError))
        ));
        Ok(())
    }

    fn request(
        name: &str,
        username: &str,
        password: &str,
    ) -> Result<NewCredentialRequest, Box<dyn Error>> {
        Ok(NewCredentialRequest::try_new(
            CredentialName::parse(name)?,
            CredentialUsername::parse(username)?,
            password.to_owned().into(),
        )?)
    }

    fn credential(name: &str, username: &str) -> Result<Credential, Box<dyn Error>> {
        Ok(Credential::try_new(
            CredentialId::generate(),
            CredentialName::parse(name)?,
            CredentialUsername::parse(username)?,
            CredentialVersionId::generate(),
            CREATED_AT,
            CREATED_AT,
        )?)
    }

    #[derive(Clone, Copy)]
    enum MockProtector {
        Accept,
        Reject,
    }

    #[derive(Clone, Copy)]
    struct MockProtected {
        credential_id: CredentialId,
        version_id: CredentialVersionId,
    }

    impl CredentialSecretProtector for MockProtector {
        type Protected = MockProtected;
        type Error = MockError;

        fn protect(
            &self,
            credential_id: CredentialId,
            version_id: CredentialVersionId,
            password: SecretString,
        ) -> Result<Self::Protected, Self::Error> {
            if matches!(self, Self::Reject) || password.expose_secret() != "must stay secret" {
                return Err(MockError);
            }
            Ok(MockProtected {
                credential_id,
                version_id,
            })
        }
    }

    #[derive(Clone, Copy)]
    enum MockCreationRepository {
        Coherent,
        Incoherent,
        Reject,
    }

    impl CredentialCreationRepository<MockProtected> for MockCreationRepository {
        type Error = MockError;

        fn create_credential(
            &self,
            creation: ProtectedCredentialCreation<MockProtected>,
        ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
            Box::pin(async move {
                if matches!(self, Self::Reject) {
                    return Err(MockError);
                }
                let (credential_id, version_id, name, username, protected, created_at) =
                    creation.into_parts();
                if protected.credential_id != credential_id || protected.version_id != version_id {
                    return Err(MockError);
                }
                let returned_id = if matches!(self, Self::Incoherent) {
                    CredentialId::generate()
                } else {
                    credential_id
                };
                Credential::try_new(
                    returned_id,
                    name,
                    username,
                    version_id,
                    created_at,
                    created_at,
                )
                .map_err(|_| MockError)
            })
        }
    }

    enum MockInventory {
        Items(Vec<Credential>),
        Reject,
    }

    impl CredentialInventoryRepository for MockInventory {
        type Error = MockError;

        fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
            Box::pin(async move {
                match self {
                    Self::Items(credentials) => Ok(credentials.clone()),
                    Self::Reject => Err(MockError),
                }
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            CREATED_AT
        }
    }

    #[derive(Debug, Error)]
    #[error("mock credential boundary failed")]
    struct MockError;
}
