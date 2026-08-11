use rutilus_center_protocol::{Envelope, EnvelopeMessage};
use rutilus_domain::{
    InstanceId, OutboxEntry, OutboxEntryError, OutboxEntryId, OutboxEntryState,
    OutboxEntryStateParseError,
};
use rutilus_entity::center_outbox;
use rutilus_security::{
    COMMAND_CIPHER_ENVELOPE_PREFIX, CommandProtectionError, MasterKey, decrypt_command,
    encrypt_command,
};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait,
};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Allocates the next per-instance sequence and persists one envelope
    /// as one atomic write (design §17, D4; §15.4).
    ///
    /// The envelope's payload column holds the §9.4 typed payload — the serde
    /// JSON serialization of the center-protocol `Envelope`, built here from
    /// `message` with the allocated sequence and `acked_sequence: 0`, so the
    /// stored payload always agrees with the row's sequence column and can
    /// only ever be JSON produced by a successfully serialized wire type —
    /// protected at rest before the write: the column stores the
    /// `XChaCha20-Poly1305` ciphertext envelope of that JSON (see
    /// `rutilus_security::encrypt_command`), bound to the entry's own id, so
    /// an offer's `AccountPassword` never lands in the clear in the durable
    /// queue. Reading it back goes through the same protection (see
    /// [`Self::list_pending_outbox`]). The allocation and the insert run
    /// under one write-gate acquisition, so two concurrent enqueues can
    /// never observe the same maximum.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::SequenceOverflow`] when the
    /// next sequence exceeds the signed `SQLite` range, and
    /// [`CenterOutboxRepositoryError`] variants for coordination, a missing
    /// command key, serialization, protection, or database failures.
    pub async fn enqueue_outbox_entry(
        &self,
        instance_id: InstanceId,
        message: &EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> Result<OutboxEntry, CenterOutboxRepositoryError> {
        self.outbox_command_key()?;
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let maximum = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .select_only()
            .column_as(Expr::col(center_outbox::Column::Sequence).max(), "max")
            .into_tuple::<(Option<i64>,)>()
            .one(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
            .and_then(|(maximum,)| maximum)
            .unwrap_or(0);
        let sequence = maximum
            .checked_add(1)
            .ok_or(CenterOutboxRepositoryError::SequenceOverflow { sequence: maximum })?;
        // The wire sequence is an unsigned field; the allocation is bounded
        // by the signed SQLite range above, so the conversion is exact.
        let wire_sequence = u64::try_from(sequence)
            .map_err(|_| CenterOutboxRepositoryError::SequenceOverflow { sequence })?;
        let envelope = Envelope {
            sequence: wire_sequence,
            acked_sequence: 0,
            message: Some(message.clone()),
        };
        let entry_id = OutboxEntryId::generate();
        let payload_json =
            serde_json::to_string(&envelope).map_err(CenterOutboxRepositoryError::Payload)?;
        let protected = self.protect_outbox_payload(entry_id, &payload_json)?;
        // The returned entry carries the §9.4 plaintext payload — the caller
        // queued a message, never a ciphertext — while the stored row holds
        // the protected envelope.
        let entry = OutboxEntry::new(entry_id, instance_id, sequence, payload_json, created_at);
        insert_outbox_entry(&transaction, &entry, &protected).await?;
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(entry)
    }

    /// Queues one outbound envelope for delivery (design §17, D4).
    ///
    /// The entry's plaintext §9.4 payload is protected at rest before the
    /// write exactly like [`Self::enqueue_outbox_entry`]'s (bound to the
    /// entry's own id), so the durable queue never holds the envelope JSON
    /// in the clear. The per-instance sequence is pinned by the unique
    /// `(instance_id, sequence)` index, so a duplicate sequence fails the
    /// insert atomically instead of a check-then-insert race.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError`] when write coordination
    /// fails, the store has no command key, protection fails, or the insert
    /// fails.
    pub async fn create_outbox_entry(
        &self,
        entry: &OutboxEntry,
    ) -> Result<(), CenterOutboxRepositoryError> {
        self.outbox_command_key()?;
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let payload_json = self.protect_outbox_payload(entry.id(), entry.payload_json())?;
        insert_outbox_entry(&self.database, entry, &payload_json).await
    }

    /// Computes the next per-instance envelope sequence: the stored maximum
    /// plus one, or 1 for a site that has never queued anything.
    ///
    /// The computation runs on the write gate, so the returned sequence
    /// cannot collide with a concurrently queued envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError`] when write coordination fails
    /// or the query fails.
    pub async fn next_outbox_sequence(
        &self,
        instance_id: InstanceId,
    ) -> Result<i64, CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let maximum = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .select_only()
            .column_as(Expr::col(center_outbox::Column::Sequence).max(), "max")
            .into_tuple::<(Option<i64>,)>()
            .one(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
            .and_then(|(maximum,)| maximum)
            .unwrap_or(0);
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(maximum + 1)
    }

    /// Reads one outbound envelope by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_outbox_entry(
        &self,
        entry_id: OutboxEntryId,
    ) -> Result<Option<OutboxEntry>, CenterOutboxRepositoryError> {
        let Some(model) = center_outbox::Entity::find_by_id(entry_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_outbox_entry(self, entry_id, &model).map(Some)
    }

    /// Lists the oldest pending envelopes of one instance in sequence order.
    ///
    /// This is the delivery scan of the site sender: the transport slice
    /// takes the head of this list, sends it, and acknowledges it on the
    /// center's `Ack`. Every stored envelope is decrypted back to its §9.4
    /// plaintext payload, so the sender always parses what the envelope
    /// carried on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants or its payload ciphertext cannot be
    /// authenticated, and [`CenterOutboxRepositoryError::CommandKeyMissing`]
    /// when a ciphertext row is read through a keyless store.
    pub async fn list_pending_outbox(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> Result<Vec<OutboxEntry>, CenterOutboxRepositoryError> {
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(center_outbox::Column::State.eq("pending"))
            .order_by_asc(center_outbox::Column::Sequence)
            .order_by_asc(center_outbox::Column::Id)
            .limit(Some(limit))
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        models
            .iter()
            .map(|model| {
                let entry_id = OutboxEntryId::from_uuid(model.id);
                map_stored_outbox_entry(self, entry_id, model)
            })
            .collect()
    }

    /// Lists every outbox entry of one instance, oldest first — the §15.6
    /// offer scan of the center's operation tracking view.
    ///
    /// The center's durable outbox holds exactly the §15.6 operation offers,
    /// acknowledged or not, so the scan rebuilds the offer facts — the
    /// target, the actor context, and the offer expiry — that the tracking
    /// operation record does not persist. Every stored envelope is decrypted
    /// back to its §9.4 plaintext payload like the delivery scan.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants or its payload ciphertext cannot be
    /// authenticated, and [`CenterOutboxRepositoryError::CommandKeyMissing`]
    /// when a ciphertext row is read through a keyless store.
    pub async fn list_outbox_entries(
        &self,
        instance_id: InstanceId,
    ) -> Result<Vec<OutboxEntry>, CenterOutboxRepositoryError> {
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .order_by_asc(center_outbox::Column::Sequence)
            .order_by_asc(center_outbox::Column::Id)
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        models
            .iter()
            .map(|model| {
                let entry_id = OutboxEntryId::from_uuid(model.id);
                map_stored_outbox_entry(self, entry_id, model)
            })
            .collect()
    }

    /// Acknowledges one outbound envelope (design §17, D4).
    ///
    /// The conditional update makes the write idempotent: only a `pending`
    /// row is updated, and a row that is already acknowledged is reported
    /// as [`AckOutcome::AlreadyAcknowledged`] instead of failing — the
    /// center may deliver its `Ack` more than once.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::NotFound`] for an unknown
    /// entry.
    pub async fn ack_outbox_entry(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> Result<AckOutcome, CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let update = center_outbox::Entity::update_many()
            .filter(center_outbox::Column::Id.eq(entry_id.into_uuid()))
            .filter(center_outbox::Column::State.eq("pending"))
            .set(center_outbox::ActiveModel {
                state: Set(String::from("acked")),
                acked_at: Set(Some(acked_at)),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let outcome = if update.rows_affected == 1 {
            AckOutcome::Acknowledged
        } else {
            let model = center_outbox::Entity::find_by_id(entry_id.into_uuid())
                .one(&transaction)
                .await
                .map_err(CenterOutboxRepositoryError::Database)?
                .ok_or(CenterOutboxRepositoryError::NotFound { entry_id })?;
            // The re-read also validates the stored row: a corrupt acked
            // row is refused as Corrupt instead of half-understood.
            map_stored_outbox_entry(self, entry_id, &model)?;
            AckOutcome::AlreadyAcknowledged
        };
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(outcome)
    }

    /// Returns the command encryption key, refusing outbox work on a keyless
    /// store.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::CommandKeyMissing`] when the
    /// store was opened without a command key.
    fn outbox_command_key(&self) -> Result<&MasterKey, CenterOutboxRepositoryError> {
        self.command_key
            .as_deref()
            .ok_or(CenterOutboxRepositoryError::CommandKeyMissing)
    }

    /// Protects one outbound envelope payload for its row: the §9.4 serde
    /// JSON form is encrypted under the instance master key as an
    /// `XChaCha20-Poly1305` envelope bound to the entry id — the 16-byte
    /// identity of the persisted row whose payload it protects, exactly like
    /// the operation command columns (see `rutilus_security::encrypt_command`).
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::CommandKeyMissing`] on a
    /// keyless store, and
    /// [`CenterOutboxRepositoryError::PayloadProtection`] when the
    /// authenticated encryption cannot complete.
    fn protect_outbox_payload(
        &self,
        entry_id: OutboxEntryId,
        plaintext: &str,
    ) -> Result<String, CenterOutboxRepositoryError> {
        let master_key = self.outbox_command_key()?;
        let plaintext: SecretString = plaintext.to_owned().into();
        encrypt_command(master_key, entry_id.into_uuid().into_bytes(), &plaintext)
            .map_err(CenterOutboxRepositoryError::PayloadProtection)
    }

    /// Recovers one stored outbound envelope payload.
    ///
    /// An envelope row (the `RUTC1:` marker) is decrypted under the instance
    /// master key with the entry id, and a legacy row written before at-rest
    /// encryption is read as plaintext JSON — the caller then parses the
    /// recovered payload exactly like the pre-encryption payload (§9.4).
    ///
    /// # Errors
    ///
    /// Returns [`StoredOutboxPayloadError::KeyMissing`] when an envelope row
    /// is read through a keyless store, and
    /// [`StoredOutboxPayloadError::Protection`] when the envelope cannot be
    /// decoded or authenticated (a tampered envelope or a different master
    /// key).
    fn recover_outbox_payload(
        &self,
        entry_id: OutboxEntryId,
        stored: &str,
    ) -> Result<String, StoredOutboxPayloadError> {
        if stored.starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX) {
            let master_key = self
                .command_key
                .as_deref()
                .ok_or(StoredOutboxPayloadError::KeyMissing)?;
            let plaintext = decrypt_command(master_key, entry_id.into_uuid().into_bytes(), stored)
                .map_err(StoredOutboxPayloadError::Protection)?;
            Ok(plaintext.expose_secret().to_owned())
        } else {
            Ok(stored.to_owned())
        }
    }
}

/// Why a stored outbox payload cannot be recovered.
enum StoredOutboxPayloadError {
    /// The store has no command key to release a ciphertext payload.
    KeyMissing,
    /// The ciphertext envelope cannot be decoded or authenticated.
    Protection(CommandProtectionError),
}

async fn insert_outbox_entry<C>(
    database: &C,
    entry: &OutboxEntry,
    payload_json: &str,
) -> Result<(), CenterOutboxRepositoryError>
where
    C: ConnectionTrait,
{
    center_outbox::ActiveModel {
        id: Set(entry.id().into_uuid()),
        sequence: Set(entry.sequence()),
        instance_id: Set(entry.instance_id().into_uuid()),
        payload_json: Set(payload_json.to_owned()),
        state: Set(entry.state().as_str().to_owned()),
        retry_count: Set(entry.retry_count()),
        created_at: Set(entry.created_at()),
        acked_at: Set(entry.acked_at()),
    }
    .insert(database)
    .await
    .map_err(CenterOutboxRepositoryError::Database)?;
    Ok(())
}

fn map_stored_outbox_entry(
    store: &SqliteStore,
    entry_id: OutboxEntryId,
    model: &center_outbox::Model,
) -> Result<OutboxEntry, CenterOutboxRepositoryError> {
    let payload_json = store
        .recover_outbox_payload(entry_id, &model.payload_json)
        .map_err(|error| match error {
            StoredOutboxPayloadError::KeyMissing => CenterOutboxRepositoryError::CommandKeyMissing,
            StoredOutboxPayloadError::Protection(source) => CenterOutboxRepositoryError::Corrupt {
                entry_id,
                source: StoredCenterOutboxError::InvalidPayloadCiphertext(source),
            },
        })?;
    OutboxEntry::try_from_parts(
        entry_id,
        InstanceId::from_uuid(model.instance_id),
        model.sequence,
        payload_json,
        model
            .state
            .parse::<OutboxEntryState>()
            .map_err(StoredCenterOutboxError::InvalidState)
            .map_err(|source| CenterOutboxRepositoryError::Corrupt { entry_id, source })?,
        model.retry_count,
        model.created_at,
        model.acked_at,
    )
    .map_err(|source| CenterOutboxRepositoryError::Corrupt {
        entry_id,
        source: StoredCenterOutboxError::Invalid(source),
    })
}

/// The outcome of an outbox acknowledgement write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    /// The pending entry was acknowledged.
    Acknowledged,
    /// The entry was already acknowledged; nothing changed.
    AlreadyAcknowledged,
}

/// A controlled failure while persisting or acknowledging outbound
/// envelopes.
#[derive(Debug, Error)]
pub enum CenterOutboxRepositoryError {
    #[error("outbox write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("the outbox sequence cannot advance past {sequence}")]
    SequenceOverflow { sequence: i64 },
    #[error("the store has no command key to protect the outbox payload")]
    CommandKeyMissing,
    #[error("the envelope could not be serialized into the outbox payload: {0}")]
    Payload(#[source] serde_json::Error),
    #[error("the outbox payload could not be protected: {0}")]
    PayloadProtection(#[source] CommandProtectionError),
    #[error("outbox entry {entry_id} was not found")]
    NotFound { entry_id: OutboxEntryId },
    #[error("stored outbox entry {entry_id} is invalid: {source}")]
    Corrupt {
        entry_id: OutboxEntryId,
        #[source]
        source: StoredCenterOutboxError,
    },
    #[error("outbox database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted outbox data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCenterOutboxError {
    #[error("stored outbox state is invalid: {0}")]
    InvalidState(#[source] OutboxEntryStateParseError),
    #[error("stored outbox payload ciphertext is invalid: {0}")]
    InvalidPayloadCiphertext(#[source] CommandProtectionError),
    #[error("stored outbox entry is invalid: {0}")]
    Invalid(#[source] OutboxEntryError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use rutilus_center_protocol::{Envelope, EnvelopeMessage, OperationOffer};
    use rutilus_domain::{
        AccountCommand, AccountPassword, AccountUserName, CreateAccount, EndpointId, InstanceId,
        InstanceKind, OperationId, OutboxEntry, OutboxEntryId, OutboxEntryState, RedfishCommand,
        RoleId, SiteInstance,
    };
    use rutilus_entity::center_outbox;
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

    fn outbox_entry(site: &SiteInstance, sequence: i64, created_at: OffsetDateTime) -> OutboxEntry {
        OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            sequence,
            format!(r#"{{"sequence":{sequence}}}"#),
            created_at,
        )
    }

    #[tokio::test]
    async fn pending_listing_is_sequence_ordered_and_bounded() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;

        store
            .create_outbox_entry(&outbox_entry(&site, 1, base))
            .await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 3, base))
            .await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 2, base))
            .await?;

        // The pending scan replays in sequence order, bounded by the limit.
        let page = store.list_pending_outbox(site.id(), 2).await?;
        assert_eq!(
            page.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![1, 2],
            "the page must hold the two oldest sequences in order"
        );
        let all = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(
            all.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the full scan must replay every pending envelope in sequence order"
        );

        // Another instance's pending envelopes never leak into this scan.
        let other = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Two"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&other).await?;
        store
            .create_outbox_entry(&outbox_entry(&other, 1, base))
            .await?;
        let all = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(all.len(), 3);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn ack_is_idempotent_and_sequence_allocation_is_monotonic() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;

        // The first sequence of an empty site is 1, and it continues after
        // the stored maximum.
        assert_eq!(store.next_outbox_sequence(site.id()).await?, 1);
        let entry = outbox_entry(&site, 1, base);
        store.create_outbox_entry(&entry).await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 5, base))
            .await?;
        assert_eq!(store.next_outbox_sequence(site.id()).await?, 6);

        // Acknowledging moves the entry out of the pending scan and is
        // idempotent: a repeated ack of the same entry is a no-op.
        assert_eq!(
            store
                .ack_outbox_entry(entry.id(), base + Duration::SECOND)
                .await?,
            AckOutcome::Acknowledged
        );
        let pending = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(
            pending
                .iter()
                .map(OutboxEntry::sequence)
                .collect::<Vec<_>>(),
            vec![5],
            "the acked entry must leave the delivery scan"
        );
        assert_eq!(
            store
                .ack_outbox_entry(entry.id(), base + Duration::SECOND)
                .await?,
            AckOutcome::AlreadyAcknowledged
        );
        assert!(matches!(
            store
                .ack_outbox_entry(OutboxEntryId::generate(), base)
                .await,
            Err(CenterOutboxRepositoryError::NotFound { .. })
        ));

        // An acked entry rehydrates with its acknowledgement time.
        let stored = store
            .find_outbox_entry(entry.id())
            .await?
            .ok_or("stored outbox entry is missing")?;
        assert_eq!(stored.state(), OutboxEntryState::Acked);
        assert_eq!(stored.acked_at(), Some(base + Duration::SECOND));

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
    ) -> Result<EnvelopeMessage, Box<dyn Error>> {
        let command = RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
            AccountUserName::parse("jane")?,
            AccountPassword::parse(password.to_owned())?,
            RoleId::parse("Operator")?,
        )));
        Ok(EnvelopeMessage::OperationOffer(OperationOffer {
            operation_id: OperationId::generate().to_string(),
            endpoint_id: EndpointId::generate().to_string(),
            site_id: site.id().to_string(),
            command_json: serde_json::to_vec(&command)?,
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix: 0,
            actor_context: String::from("actor"),
        }))
    }

    #[tokio::test]
    async fn payloads_rest_as_ciphertext_and_read_back_plaintext() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let password = "correct-horse-battery-staple";
        let message = offer_with_password(&site, password)?;

        let queued = store
            .enqueue_outbox_entry(site.id(), &message, base)
            .await?;

        // The durable row holds the ciphertext envelope: the `RUTC1:` marker
        // and not one plaintext byte of the offer, in particular not the
        // account password.
        let model = center_outbox::Entity::find_by_id(queued.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("stored outbox entry is missing")?;
        assert!(
            model
                .payload_json
                .starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX),
            "the outbox payload column must hold the ciphertext envelope"
        );
        assert!(
            !model.payload_json.contains(password),
            "the outbox payload column must never hold the password plaintext"
        );
        assert!(
            !model.payload_json.contains(r#"{"sequence":"#),
            "the outbox payload column must not hold the envelope JSON in the clear"
        );

        // The delivery scan decrypts the payload: the sender parses exactly
        // the envelope that was queued.
        let pending = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id(), queued.id());
        let envelope: Envelope = serde_json::from_str(pending[0].payload_json())?;
        assert_eq!(envelope.sequence, 1);
        assert_eq!(envelope.message, Some(message.clone()));

        // The entry returned by the enqueue agrees with the queued message.
        let envelope: Envelope = serde_json::from_str(queued.payload_json())?;
        assert_eq!(envelope.message, Some(message));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn create_outbox_entry_rests_encrypted_too() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let password = "hunter2-example";
        let message = offer_with_password(&site, password)?;
        let envelope = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(message.clone()),
        };
        let entry = OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            1,
            serde_json::to_string(&envelope)?,
            base,
        );
        store.create_outbox_entry(&entry).await?;

        let model = center_outbox::Entity::find_by_id(entry.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("stored outbox entry is missing")?;
        assert!(
            model
                .payload_json
                .starts_with(COMMAND_CIPHER_ENVELOPE_PREFIX)
        );
        assert!(!model.payload_json.contains(password));

        let stored = store
            .find_outbox_entry(entry.id())
            .await?
            .ok_or("stored outbox entry is missing")?;
        let envelope: Envelope = serde_json::from_str(stored.payload_json())?;
        assert_eq!(envelope.message, Some(message));

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
        // A row written before at-rest encryption: raw plaintext envelope
        // JSON, inserted straight into the table.
        let entry = outbox_entry(&site, 1, base);
        center_outbox::ActiveModel {
            id: Set(entry.id().into_uuid()),
            sequence: Set(entry.sequence()),
            instance_id: Set(entry.instance_id().into_uuid()),
            payload_json: Set(entry.payload_json().to_owned()),
            state: Set(entry.state().as_str().to_owned()),
            retry_count: Set(entry.retry_count()),
            created_at: Set(entry.created_at()),
            acked_at: Set(entry.acked_at()),
        }
        .insert(&store.database)
        .await?;

        let stored = store
            .find_outbox_entry(entry.id())
            .await?
            .ok_or("stored outbox entry is missing")?;
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
        let entry = {
            let store = SqliteStore::open_with_command_key(&database_path, test_key()).await?;
            let base = OffsetDateTime::now_utc();
            let site = site_instance(base);
            store.create_instance(&site).await?;
            let message = offer_with_password(&site, "another-secret")?;
            let entry = store
                .enqueue_outbox_entry(site.id(), &message, base)
                .await?;
            store.close().await?;
            entry
        };

        // A store opened with a different key cannot authenticate the
        // envelope, so the row is refused as corrupt — never released
        // half-understood.
        let store = SqliteStore::open_with_command_key(&database_path, other_test_key()).await?;
        assert!(matches!(
            store.find_outbox_entry(entry.id()).await,
            Err(CenterOutboxRepositoryError::Corrupt {
                entry_id,
                source: StoredCenterOutboxError::InvalidPayloadCiphertext(_),
            }) if entry_id == entry.id()
        ));
        assert!(matches!(
            store.list_pending_outbox(entry.instance_id(), 10).await,
            Err(CenterOutboxRepositoryError::Corrupt {
                entry_id,
                source: StoredCenterOutboxError::InvalidPayloadCiphertext(_),
            }) if entry_id == entry.id()
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn keyless_stores_refuse_envelope_writes_and_ciphertext_reads()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let (site, base, message, entry_id) = {
            let store = SqliteStore::open_with_command_key(&database_path, test_key()).await?;
            let base = OffsetDateTime::now_utc();
            let site = site_instance(base);
            store.create_instance(&site).await?;
            let message = offer_with_password(&site, "keyless-secret")?;
            let entry = store
                .enqueue_outbox_entry(site.id(), &message, base)
                .await?;
            store.close().await?;
            (site, base, message, entry.id())
        };

        // The keyless store (backup, onboarding, and test paths) fails
        // closed: no envelope write, and no ciphertext plaintext released.
        let store = SqliteStore::open(&database_path).await?;
        assert!(matches!(
            store.enqueue_outbox_entry(site.id(), &message, base).await,
            Err(CenterOutboxRepositoryError::CommandKeyMissing)
        ));
        assert!(matches!(
            store
                .create_outbox_entry(&OutboxEntry::new(
                    OutboxEntryId::generate(),
                    site.id(),
                    2,
                    String::from(r#"{"sequence":2}"#),
                    base,
                ))
                .await,
            Err(CenterOutboxRepositoryError::CommandKeyMissing)
        ));
        assert!(matches!(
            store.find_outbox_entry(entry_id).await,
            Err(CenterOutboxRepositoryError::CommandKeyMissing)
        ));
        assert!(matches!(
            store.list_pending_outbox(site.id(), 10).await,
            Err(CenterOutboxRepositoryError::CommandKeyMissing)
        ));

        // A legacy plaintext row needs no key and reads exactly as before.
        let legacy = OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            5,
            r#"{"sequence":5}"#.to_owned(),
            base,
        );
        center_outbox::ActiveModel {
            id: Set(legacy.id().into_uuid()),
            sequence: Set(legacy.sequence()),
            instance_id: Set(legacy.instance_id().into_uuid()),
            payload_json: Set(legacy.payload_json().to_owned()),
            state: Set(legacy.state().as_str().to_owned()),
            retry_count: Set(legacy.retry_count()),
            created_at: Set(legacy.created_at()),
            acked_at: Set(legacy.acked_at()),
        }
        .insert(&store.database)
        .await?;
        let stored = store
            .find_outbox_entry(legacy.id())
            .await?
            .ok_or("legacy outbox entry is missing")?;
        assert_eq!(stored.payload_json(), legacy.payload_json());

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
