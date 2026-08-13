use rutilus_domain::{
    IdempotencyDecision, InboxEntry, InboxEntryId, InboxEntryState, InboxEntryStateParseError,
    InboxEvent, InstanceId, OperationId, decide_inbox_duplicate,
};
use rutilus_entity::center_inbox;
use rutilus_security::{
    COMMAND_CIPHER_ENVELOPE_PREFIX, CommandProtectionError, MasterKey, decrypt_command,
    encrypt_command,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one received envelope under the §17.5 idempotency rule.
    ///
    /// The operation id is the idempotency key: the row is re-read inside
    /// the transaction (never trusted from a stale read), and a stored row
    /// with the same operation id is decided by the domain pure function —
    /// an in-progress duplicate is parked without a second insertion, and a
    /// resolved duplicate returns the recorded outcome — so the same
    /// operation id can never have two business effects, even across
    /// re-deliveries.
    ///
    /// The envelope's §9.4 payload is protected at rest before the write:
    /// the column stores the `XChaCha20-Poly1305` ciphertext envelope of
    /// the serde JSON (see `rutilus_security::encrypt_command`), bound to
    /// the operation id — the same binding the `operations.command` column
    /// uses — so a received offer's `AccountPassword` never lands in the
    /// clear in the durable inbox. Reading it back goes through the same
    /// protection (see [`Self::find_inbox_entry_by_operation`]).
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::Corrupt`] when the stored
    /// duplicate row violates domain invariants, and
    /// [`CenterInboxRepositoryError`] variants for coordination, a missing
    /// command key, protection, or database failures.
    pub async fn create_inbox_entry(
        &self,
        entry: &InboxEntry,
    ) -> Result<CreateInboxOutcome, CenterInboxRepositoryError> {
        self.inbox_command_key()?;
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterInboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let existing = center_inbox::Entity::find()
            .filter(center_inbox::Column::OperationId.eq(entry.operation_id().to_string()))
            .one(&transaction)
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let outcome = if let Some(model) = existing {
            let stored = map_stored_inbox_entry(self, InboxEntryId::from_uuid(model.id), &model)?;
            match decide_inbox_duplicate(Some(stored.state())) {
                IdempotencyDecision::Proceed => CreateInboxOutcome::Created,
                IdempotencyDecision::InProgress => CreateInboxOutcome::DuplicateInProgress,
                IdempotencyDecision::AlreadyResolved(state) => {
                    CreateInboxOutcome::DuplicateResolved(state)
                }
            }
        } else {
            let payload_json =
                self.protect_inbox_payload(entry.operation_id(), entry.payload_json())?;
            insert_inbox_entry(&transaction, entry, &payload_json).await?;
            CreateInboxOutcome::Created
        };
        transaction
            .commit()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        Ok(outcome)
    }

    /// Reads one received envelope by its operation id — the §17.5
    /// idempotency lookup. The stored payload is decrypted back to its §9.4
    /// plaintext envelope, so the caller parses exactly what the center
    /// sent.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants or its payload ciphertext cannot be
    /// authenticated, and [`CenterInboxRepositoryError::CommandKeyMissing`]
    /// when a ciphertext row is read through a keyless store.
    pub async fn find_inbox_entry_by_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<InboxEntry>, CenterInboxRepositoryError> {
        let Some(model) = center_inbox::Entity::find()
            .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
            .one(&self.database)
            .await
            .map_err(CenterInboxRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_inbox_entry(self, InboxEntryId::from_uuid(model.id), &model).map(Some)
    }

    /// Applies one inbox state-machine event (§17, D4).
    ///
    /// The from-state and to-state come from the domain event, and the
    /// conditional update makes the write idempotent: an entry that already
    /// carries the target state is reported as
    /// [`InboxAdvanceOutcome::AlreadyInState`] instead of failing (the
    /// center may deliver progress envelopes more than once), and an entry
    /// in any other state is refused as a conflict.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::NotFound`] for an unknown
    /// operation id and
    /// [`CenterInboxRepositoryError::StateConflict`] when the stored state
    /// makes the event illegal.
    pub async fn advance_inbox_entry(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> Result<InboxAdvanceOutcome, CenterInboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterInboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let update = center_inbox::Entity::update_many()
            .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
            .filter(center_inbox::Column::State.eq(event.from_state().as_str()))
            .set(center_inbox::ActiveModel {
                state: Set(event.to_state().as_str().to_owned()),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let outcome = if update.rows_affected == 1 {
            InboxAdvanceOutcome::Advanced(event.to_state())
        } else {
            let model = center_inbox::Entity::find()
                .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
                .one(&transaction)
                .await
                .map_err(CenterInboxRepositoryError::Database)?
                .ok_or(CenterInboxRepositoryError::NotFound { operation_id })?;
            let stored = map_stored_inbox_entry(self, InboxEntryId::from_uuid(model.id), &model)?;
            if stored.state() == event.to_state() {
                InboxAdvanceOutcome::AlreadyInState
            } else {
                return Err(CenterInboxRepositoryError::StateConflict {
                    operation_id,
                    event,
                    current: stored.state(),
                });
            }
        };
        transaction
            .commit()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        Ok(outcome)
    }

    /// Returns the command encryption key, refusing inbox work on a keyless
    /// store.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::CommandKeyMissing`] when the
    /// store was opened without a command key.
    fn inbox_command_key(&self) -> Result<&MasterKey, CenterInboxRepositoryError> {
        self.command_key
            .as_deref()
            .ok_or(CenterInboxRepositoryError::CommandKeyMissing)
    }

    /// Protects one received envelope payload for its row: the §9.4 serde
    /// JSON form is encrypted under the instance master key as an
    /// `XChaCha20-Poly1305` envelope bound to the operation id — the same
    /// binding the `operations.command` column uses, so the binding needs
    /// nothing beyond the row the reader is already hydrating (see
    /// `rutilus_security::encrypt_command`).
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::CommandKeyMissing`] on a
    /// keyless store, and
    /// [`CenterInboxRepositoryError::PayloadProtection`] when the
    /// authenticated encryption cannot complete.
    fn protect_inbox_payload(
        &self,
        operation_id: OperationId,
        plaintext: &str,
    ) -> Result<String, CenterInboxRepositoryError> {
        let master_key = self.inbox_command_key()?;
        let plaintext: SecretString = plaintext.to_owned().into();
        encrypt_command(
            master_key,
            operation_id.into_uuid().into_bytes(),
            &plaintext,
        )
        .map_err(CenterInboxRepositoryError::PayloadProtection)
    }

    /// Recovers one stored received envelope payload.
    ///
    /// An envelope row (the `RUTC1:` marker) is decrypted under the instance
    /// master key with the operation id, and a legacy row written before
    /// at-rest encryption is read as plaintext JSON — the caller then parses
    /// the recovered payload exactly like the pre-encryption payload (§9.4).
    ///
    /// # Errors
    ///
    /// Returns [`StoredInboxPayloadError::KeyMissing`] when an envelope row
    /// is read through a keyless store, and
    /// [`StoredInboxPayloadError::Protection`] when the envelope cannot be
    /// decoded or authenticated (a tampered envelope or a different master
    /// key).
    fn recover_inbox_payload(
        &self,
        operation_id: OperationId,
        stored: &str,
    ) -> Result<String, StoredInboxPayloadError> {
        if stored.starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX) {
            let master_key = self
                .command_key
                .as_deref()
                .ok_or(StoredInboxPayloadError::KeyMissing)?;
            let plaintext =
                decrypt_command(master_key, operation_id.into_uuid().into_bytes(), stored)
                    .map_err(StoredInboxPayloadError::Protection)?;
            Ok(plaintext.expose_secret().to_owned())
        } else {
            Ok(stored.to_owned())
        }
    }
}

/// Why a stored inbox payload cannot be recovered.
enum StoredInboxPayloadError {
    /// The store has no command key to release a ciphertext payload.
    KeyMissing,
    /// The ciphertext envelope cannot be decoded or authenticated.
    Protection(CommandProtectionError),
}

async fn insert_inbox_entry<C>(
    database: &C,
    entry: &InboxEntry,
    payload_json: &str,
) -> Result<(), CenterInboxRepositoryError>
where
    C: ConnectionTrait,
{
    center_inbox::ActiveModel {
        id: Set(entry.id().into_uuid()),
        operation_id: Set(entry.operation_id().to_string()),
        instance_id: Set(entry.instance_id().into_uuid()),
        payload_json: Set(payload_json.to_owned()),
        state: Set(entry.state().as_str().to_owned()),
        expires_at: Set(entry.expires_at()),
        received_at: Set(entry.received_at()),
    }
    .insert(database)
    .await
    .map_err(CenterInboxRepositoryError::Database)?;
    Ok(())
}

fn map_stored_inbox_entry(
    store: &SqliteStore,
    entry_id: InboxEntryId,
    model: &center_inbox::Model,
) -> Result<InboxEntry, CenterInboxRepositoryError> {
    let operation_id = model
        .operation_id
        .parse::<OperationId>()
        .map_err(StoredCenterInboxError::InvalidOperationId)
        .map_err(|source| CenterInboxRepositoryError::Corrupt { entry_id, source })?;
    let payload_json = store
        .recover_inbox_payload(operation_id, &model.payload_json)
        .map_err(|error| match error {
            StoredInboxPayloadError::KeyMissing => CenterInboxRepositoryError::CommandKeyMissing,
            StoredInboxPayloadError::Protection(source) => CenterInboxRepositoryError::Corrupt {
                entry_id,
                source: StoredCenterInboxError::InvalidPayloadCiphertext(source),
            },
        })?;
    let state = model
        .state
        .parse::<InboxEntryState>()
        .map_err(StoredCenterInboxError::InvalidState)
        .map_err(|source| CenterInboxRepositoryError::Corrupt { entry_id, source })?;
    Ok(InboxEntry::from_parts(
        entry_id,
        operation_id,
        InstanceId::from_uuid(model.instance_id),
        payload_json,
        state,
        model.expires_at,
        model.received_at,
    ))
}

/// The outcome of an idempotent inbox insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateInboxOutcome {
    /// The envelope was stored as a new entry, carrying the phase of the
    /// inserted row: `Received` for a fresh offer, or the reply's phase
    /// when a receipt insert is born at the phase the reply dictates.
    Created,
    /// A stored entry with the same operation id is still being processed.
    DuplicateInProgress,
    /// A stored entry with the same operation id already finished; the
    /// duplicate is answered with the recorded outcome instead of being
    /// executed again.
    DuplicateResolved(InboxEntryState),
}

/// The outcome of an inbox state-machine write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxAdvanceOutcome {
    /// The transition was applied; the entry now carries the given state.
    Advanced(InboxEntryState),
    /// The entry already carried the target state; nothing changed.
    AlreadyInState,
}

/// A controlled failure while persisting or advancing received envelopes.
#[derive(Debug, Error)]
pub enum CenterInboxRepositoryError {
    #[error("inbox write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("the store has no command key to protect the inbox payload")]
    CommandKeyMissing,
    #[error("the inbox payload could not be protected: {0}")]
    PayloadProtection(#[source] CommandProtectionError),
    #[error("inbox entry for operation {operation_id} was not found")]
    NotFound { operation_id: OperationId },
    #[error(
        "event {event} cannot apply to inbox entry of operation {operation_id} in state {current}"
    )]
    StateConflict {
        operation_id: OperationId,
        event: InboxEvent,
        current: InboxEntryState,
    },
    #[error("stored inbox entry {entry_id} is invalid: {source}")]
    Corrupt {
        entry_id: InboxEntryId,
        #[source]
        source: StoredCenterInboxError,
    },
    #[error("inbox database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted inbox data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCenterInboxError {
    #[error("stored operation id is invalid: {0}")]
    InvalidOperationId(#[source] uuid::Error),
    #[error("stored inbox state is invalid: {0}")]
    InvalidState(#[source] InboxEntryStateParseError),
    #[error("stored inbox payload ciphertext is invalid: {0}")]
    InvalidPayloadCiphertext(#[source] CommandProtectionError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use rutilus_center_protocol::{Envelope, EnvelopeMessage, OperationOffer};
    use rutilus_domain::{
        AccountCommand, AccountPassword, AccountUserName, CreateAccount, EndpointId, InboxEntryId,
        InboxEvent, InstanceId, InstanceKind, OperationId, RedfishCommand, RoleId, SiteInstance,
    };
    use rutilus_entity::center_inbox;
    use rutilus_security::MasterKey;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    fn site_instance(now: OffsetDateTime) -> SiteInstance {
        SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            now,
        )
    }

    fn inbox_entry(
        site: &SiteInstance,
        operation_id: OperationId,
        base: OffsetDateTime,
        state: InboxEntryState,
        payload_json: String,
    ) -> InboxEntry {
        InboxEntry::from_parts(
            InboxEntryId::generate(),
            operation_id,
            site.id(),
            payload_json,
            state,
            base + Duration::hours(1),
            base,
        )
    }

    #[tokio::test]
    async fn operation_id_is_the_idempotency_key() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();

        // A fresh operation id proceeds and is stored as received.
        let first = inbox_entry(
            &site,
            operation_id,
            base,
            InboxEntryState::Received,
            String::from(r#"{"operation_id":"1"}"#),
        );
        assert_eq!(
            store.create_inbox_entry(&first).await?,
            CreateInboxOutcome::Created
        );

        // The same operation id is parked while still being processed.
        let duplicate = inbox_entry(
            &site,
            operation_id,
            base,
            InboxEntryState::Received,
            String::from(r#"{"operation_id":"1"}"#),
        );
        assert_eq!(
            store.create_inbox_entry(&duplicate).await?,
            CreateInboxOutcome::DuplicateInProgress
        );

        // Once the recorded lifecycle finishes, the duplicate is answered
        // with the recorded outcome instead of a second execution.
        store
            .advance_inbox_entry(operation_id, InboxEvent::Accepted)
            .await?;
        store
            .advance_inbox_entry(operation_id, InboxEvent::Completed)
            .await?;
        assert_eq!(
            store.create_inbox_entry(&duplicate).await?,
            CreateInboxOutcome::DuplicateResolved(InboxEntryState::Completed)
        );

        // The idempotency lookup returns the stored entry.
        let stored = store
            .find_inbox_entry_by_operation(operation_id)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert_eq!(stored.state(), InboxEntryState::Completed);
        assert_eq!(stored.operation_id(), operation_id);
        assert_eq!(
            store
                .find_inbox_entry_by_operation(OperationId::generate())
                .await?,
            None
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn advance_walks_the_state_machine_idempotently() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        store
            .create_inbox_entry(&inbox_entry(
                &site,
                operation_id,
                base,
                InboxEntryState::Received,
                String::from(r#"{"operation_id":"1"}"#),
            ))
            .await?;

        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::Advanced(InboxEntryState::Accepted)
        );
        // A repeated acceptance is a no-op, not an error: the center may
        // re-deliver progress.
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::AlreadyInState
        );
        // A rejection while accepted is an illegal transition.
        assert!(matches!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Rejected)
                .await,
            Err(CenterInboxRepositoryError::StateConflict { .. })
        ));
        // An unknown operation id is refused.
        assert!(matches!(
            store
                .advance_inbox_entry(OperationId::generate(), InboxEvent::Accepted)
                .await,
            Err(CenterInboxRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// Opens a command-encrypted store: the queue payloads rest as ciphertext
    /// envelopes exactly like the production runtime's store.
    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open_with_command_key(
            directory.path().join("rutilus.db"),
            Arc::new(MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))),
        )
        .await?;
        Ok((directory, store))
    }

    /// The fixed test command key, shared by every keyed store in this
    /// module so a store written and re-read across two opens uses the same
    /// key, exactly like the operation repository's test key.
    fn test_key() -> Arc<MasterKey> {
        Arc::new(MasterKey::from_boxed_bytes(Box::new([0x5a; 32])))
    }

    /// A second key, for the wrong-key tests.
    fn other_test_key() -> Arc<MasterKey> {
        Arc::new(MasterKey::from_boxed_bytes(Box::new([0x6a; 32])))
    }

    /// One `OperationOffer` whose command carries a §10 secret — the payload
    /// the at-rest protection exists for.
    fn offer_with_password(
        site: &SiteInstance,
        password: &str,
    ) -> Result<OperationOffer, Box<dyn Error>> {
        let command = RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
            AccountUserName::parse("jane")?,
            AccountPassword::parse(password.to_owned())?,
            RoleId::parse("Operator")?,
        )));
        Ok(OperationOffer {
            operation_id: OperationId::generate().to_string(),
            endpoint_id: EndpointId::generate().to_string(),
            site_id: site.id().to_string(),
            command_json: serde_json::to_vec(&command)?,
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix: 0,
            actor_context: String::from("actor"),
        })
    }

    /// One received envelope carrying the password-bearing offer.
    fn received_envelope(
        site: &SiteInstance,
        password: &str,
    ) -> Result<(OperationId, Envelope), Box<dyn Error>> {
        let offer = offer_with_password(site, password)?;
        let operation_id = offer.operation_id.parse::<OperationId>()?;
        let envelope = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer)),
        };
        Ok((operation_id, envelope))
    }

    #[tokio::test]
    async fn payloads_rest_as_ciphertext_and_read_back_plaintext() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let password = "correct-horse-battery-staple";
        let (operation_id, envelope) = received_envelope(&site, password)?;
        let entry = inbox_entry(
            &site,
            operation_id,
            base,
            InboxEntryState::Received,
            serde_json::to_string(&envelope)?,
        );
        assert_eq!(
            store.create_inbox_entry(&entry).await?,
            CreateInboxOutcome::Created
        );

        // The durable row holds the ciphertext envelope: the `RUTC1:` marker
        // and not one plaintext byte of the offer, in particular not the
        // account password.
        let model = center_inbox::Entity::find_by_id(entry.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert!(
            model
                .payload_json
                .starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX),
            "the inbox payload column must hold the ciphertext envelope"
        );
        assert!(
            !model.payload_json.contains(password),
            "the inbox payload column must never hold the password plaintext"
        );

        // The idempotency lookup decrypts the payload: the caller parses
        // exactly the envelope that was received.
        let stored = store
            .find_inbox_entry_by_operation(operation_id)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert_eq!(stored.state(), InboxEntryState::Received);
        let stored_envelope: Envelope = serde_json::from_str(stored.payload_json())?;
        assert_eq!(stored_envelope, envelope);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn legacy_plaintext_rows_remain_readable() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        // A row written before at-rest encryption: raw plaintext envelope
        // JSON, inserted straight into the table.
        let entry = inbox_entry(
            &site,
            operation_id,
            base,
            InboxEntryState::Received,
            String::from(r#"{"operation_id":"1"}"#),
        );
        center_inbox::ActiveModel {
            id: Set(entry.id().into_uuid()),
            operation_id: Set(entry.operation_id().to_string()),
            instance_id: Set(entry.instance_id().into_uuid()),
            payload_json: Set(entry.payload_json().to_owned()),
            state: Set(entry.state().as_str().to_owned()),
            expires_at: Set(entry.expires_at()),
            received_at: Set(entry.received_at()),
        }
        .insert(&store.database)
        .await?;

        let stored = store
            .find_inbox_entry_by_operation(operation_id)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert_eq!(stored.payload_json(), entry.payload_json());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_envelopes_written_with_a_different_master_key_as_corrupt()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let operation_id = {
            let store = SqliteStore::open_with_command_key(&database_path, test_key()).await?;
            let base = OffsetDateTime::now_utc();
            let site = site_instance(base);
            store.create_instance(&site).await?;
            let (operation_id, envelope) = received_envelope(&site, "wrong-key-secret")?;
            store
                .create_inbox_entry(&inbox_entry(
                    &site,
                    operation_id,
                    base,
                    InboxEntryState::Received,
                    serde_json::to_string(&envelope)?,
                ))
                .await?;
            store.close().await?;
            operation_id
        };

        // A store opened with a different key cannot authenticate the
        // envelope, so the row is refused as corrupt — never released
        // half-understood.
        let store = SqliteStore::open_with_command_key(&database_path, other_test_key()).await?;
        assert!(matches!(
            store.find_inbox_entry_by_operation(operation_id).await,
            Err(CenterInboxRepositoryError::Corrupt {
                source: StoredCenterInboxError::InvalidPayloadCiphertext(_),
                ..
            })
        ));
        // The state-machine write does not touch the payload, so it still
        // advances: the corruption surfaces exactly where the payload is
        // read, never in the state columns.
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::Advanced(InboxEntryState::Accepted)
        );
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn keyless_stores_refuse_envelope_writes_and_ciphertext_reads()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let (site, operation_id, envelope, base) = {
            let store = SqliteStore::open_with_command_key(&database_path, test_key()).await?;
            let base = OffsetDateTime::now_utc();
            let site = site_instance(base);
            store.create_instance(&site).await?;
            let (operation_id, envelope) = received_envelope(&site, "keyless-secret")?;
            store
                .create_inbox_entry(&inbox_entry(
                    &site,
                    operation_id,
                    base,
                    InboxEntryState::Received,
                    serde_json::to_string(&envelope)?,
                ))
                .await?;
            store.close().await?;
            (site, operation_id, envelope, base)
        };

        // The keyless store (backup, onboarding, and test paths) fails
        // closed: no envelope write, and no ciphertext plaintext released.
        let store = SqliteStore::open(&database_path).await?;
        assert!(matches!(
            store
                .create_inbox_entry(&inbox_entry(
                    &site,
                    OperationId::generate(),
                    base,
                    InboxEntryState::Received,
                    serde_json::to_string(&envelope)?,
                ))
                .await,
            Err(CenterInboxRepositoryError::CommandKeyMissing)
        ));
        assert!(matches!(
            store.find_inbox_entry_by_operation(operation_id).await,
            Err(CenterInboxRepositoryError::CommandKeyMissing)
        ));

        // A legacy plaintext row needs no key and reads exactly as before.
        let legacy_operation = OperationId::generate();
        let legacy = inbox_entry(
            &site,
            legacy_operation,
            base,
            InboxEntryState::Received,
            String::from(r#"{"operation_id":"legacy"}"#),
        );
        center_inbox::ActiveModel {
            id: Set(legacy.id().into_uuid()),
            operation_id: Set(legacy.operation_id().to_string()),
            instance_id: Set(legacy.instance_id().into_uuid()),
            payload_json: Set(legacy.payload_json().to_owned()),
            state: Set(legacy.state().as_str().to_owned()),
            expires_at: Set(legacy.expires_at()),
            received_at: Set(legacy.received_at()),
        }
        .insert(&store.database)
        .await?;
        let stored = store
            .find_inbox_entry_by_operation(legacy_operation)
            .await?
            .ok_or("legacy inbox entry is missing")?;
        assert_eq!(stored.payload_json(), legacy.payload_json());

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
