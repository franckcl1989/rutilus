use rutilus_center_protocol::{Envelope, EnvelopeMessage};
use rutilus_domain::{
    InstanceId, OperationId, OutboxEntry, OutboxEntryError, OutboxEntryId, OutboxEntryState,
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
use uuid::Uuid;

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
        insert_outbox_entry(
            &transaction,
            &entry,
            &protected,
            payload_operation_id(entry.payload_json()),
        )
        .await?;
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
        insert_outbox_entry(
            &self.database,
            entry,
            &payload_json,
            payload_operation_id(entry.payload_json()),
        )
        .await
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

    /// Lists the newest outbox entries of one instance, newest first,
    /// bounded by `limit` — the bounded twin of
    /// [`Self::list_outbox_entries`] (V4P-2).
    ///
    /// The read is the offer scan of the center's operation tracking view
    /// with the decrypt surface capped: the view needs at most one offer
    /// per displayed operation, and the newest entries are the newest
    /// offers — the facts (target, actor context, offer expiry) of the
    /// recent dispatches the view is built to track. The bound is not a
    /// visibility guarantee: an operation whose newest offer lies beyond
    /// the window simply renders without its offer facts, exactly like the
    /// dispatch scan's bounded pending queue. There is no `operation_id`
    /// column to direct the read at the offers of the displayed operations
    /// (the payload is a ciphertext envelope), so the newest-`limit` window
    /// is the smallest honest decryption surface. Like the unbounded twin,
    /// every stored envelope is decrypted back to its §9.4 plaintext
    /// payload.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants or its payload ciphertext cannot be
    /// authenticated, and [`CenterOutboxRepositoryError::CommandKeyMissing`]
    /// when a ciphertext row is read through a keyless store.
    pub async fn list_outbox_entries_bounded(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> Result<Vec<OutboxEntry>, CenterOutboxRepositoryError> {
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .order_by_desc(center_outbox::Column::Sequence)
            .order_by_desc(center_outbox::Column::Id)
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

    /// Acknowledges one outbound envelope (design §17, D4).
    ///
    /// The conditional update makes the write idempotent: only a `pending`
    /// row is updated, and a row that is already acknowledged is reported
    /// as [`AckOutcome::AlreadyAcknowledged`] instead of failing — the
    /// center may deliver its `Ack` more than once.
    ///
    /// An acknowledged offer row is delivered history (§15.4) — the retry
    /// and the reply-site fallback read the *newest* row per operation, so
    /// the older acknowledged rows of the same operation are dead weight.
    /// The ack therefore prunes them (R6-E-04): the newest acknowledged row
    /// of the operation is kept, every other acknowledged row of the same
    /// operation is deleted — the queue never grows one row per retry of a
    /// settled operation. The pruning is scoped to the row's own instance
    /// (W7-F-1): the sequence is per-instance, so the same operation id can
    /// legitimately ride in two instances' queues (an endpoint re-homed
    /// between dispatches of the same id), and one instance's ack must
    /// never prune the other instance's rows — those rows are the R6-E-01
    /// evidence surface of the other dispatch. Rows without an operation id
    /// (the site-side content queue) are never pruned, and pending rows are
    /// never pruned.
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
        // R6-E-04 / W7-F-1: prune the acknowledged history of the
        // just-acked row's operation, keeping the newest acknowledged row
        // of *this* instance. The just-updated row participates (it is
        // acked by now), so the keeper is the newest acknowledged row of
        // the instance whether it is this one or a newer retry's. The
        // instance filter is the fix of W7-F-1: without it, an ack on one
        // instance of a re-homed operation would delete the other
        // instance's acknowledged rows of the same operation id.
        let acked_row = center_outbox::Entity::find_by_id(entry_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        if let Some(model) = acked_row
            && let Some(operation_id) = model.operation_id
        {
            prune_acked_operation_history(&transaction, model.instance_id, operation_id).await?;
        }
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(outcome)
    }

    /// Finds the newest outbox row of one operation — the directed repair
    /// read over the plaintext `operation_id` column (R6-E-04).
    ///
    /// The dispatch retry's fall-through, the V5E-1 reply-site fallback, and
    /// the ack-time pruning all address one operation's rows directly, so
    /// none of them needs to decrypt the site's whole queue. Rows written
    /// before the `operation_id` migration carry `NULL`: the read then
    /// falls back to a payload scan of the instance's rows, backfills the
    /// column of the found row, and returns it — so a pre-migration
    /// acknowledged offer is never mistaken for a never-enqueued record
    /// (the F1 double-execution guard holds across the upgrade), and the
    /// column self-heals on first access.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any scanned
    /// stored row violates domain invariants or its payload ciphertext
    /// cannot be authenticated, and
    /// [`CenterOutboxRepositoryError::CommandKeyMissing`] when a ciphertext
    /// row is read through a keyless store.
    pub async fn find_outbox_entry_by_operation(
        &self,
        instance_id: InstanceId,
        operation_id: OperationId,
    ) -> Result<Option<OutboxEntry>, CenterOutboxRepositoryError> {
        let model = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(center_outbox::Column::OperationId.eq(operation_id.into_uuid()))
            .order_by_desc(center_outbox::Column::Sequence)
            .order_by_desc(center_outbox::Column::Id)
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        if let Some(model) = model {
            let entry_id = OutboxEntryId::from_uuid(model.id);
            return map_stored_outbox_entry(self, entry_id, &model).map(Some);
        }
        // W7-P-2: the fallback runs only for a queue that can actually hide
        // the offer. Pre-migration rows carry `NULL` in the column, so a
        // queue whose rows all carry the column proves the operation was
        // never enqueued — the miss answers immediately instead of
        // rescanning (and decrypting) the instance's whole queue on every
        // call, which a never-queued id would otherwise pay forever. The
        // existence check rides the (instance_id, operation_id) index:
        // SQLite indexes NULL keys, so `IS NULL` is an index range scan,
        // not a table scan.
        let null_row = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(center_outbox::Column::OperationId.is_null())
            .select_only()
            .column(center_outbox::Column::Id)
            .limit(1)
            .into_tuple::<(Uuid,)>()
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        if null_row.is_none() {
            return Ok(None);
        }
        // Pre-migration rows carry `NULL` in the column: find the newest
        // offer row of the operation by decrypting the NULL-column
        // payloads — a row whose column is set can never hide the target
        // operation (the indexed query already missed it) — backfill the
        // column, and return it.
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(center_outbox::Column::OperationId.is_null())
            .order_by_desc(center_outbox::Column::Sequence)
            .order_by_desc(center_outbox::Column::Id)
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        for model in models {
            let entry_id = OutboxEntryId::from_uuid(model.id);
            let entry = map_stored_outbox_entry(self, entry_id, &model)?;
            if payload_operation_id(entry.payload_json()) != Some(operation_id) {
                continue;
            }
            // The backfill is a write, so it runs under the write gate like
            // every other queue write; it cannot deadlock — no caller of
            // this read holds the *write gate* while awaiting the read.
            // (The center dispatch does call this read inside its per-site
            // dispatch gate, R6-C-1, but that is a separate lock, held
            // only for the duration of one dispatch, never across a
            // write-gate acquisition by the same task.)
            let _write_permit = self
                .write_gate
                .acquire()
                .await
                .map_err(CenterOutboxRepositoryError::Coordinate)?;
            center_outbox::Entity::update_many()
                .filter(center_outbox::Column::Id.eq(entry_id.into_uuid()))
                .set(center_outbox::ActiveModel {
                    operation_id: Set(Some(operation_id.into_uuid())),
                    ..Default::default()
                })
                .exec(&self.database)
                .await
                .map_err(CenterOutboxRepositoryError::Database)?;
            return Ok(Some(entry));
        }
        Ok(None)
    }

    /// Finds the newest outbox row of one operation across every instance —
    /// the cross-instance confirmation read of the R6-E-01 dispatch refusal
    /// (W7-E-3).
    ///
    /// An endpoint's site can change (re-home) while an `Unknown` outcome
    /// is unresolved: the offer that may have executed the write lives in
    /// the *original* site's queue, while the retry addresses the *new*
    /// site. The unknown-outcome refusal must therefore confirm the offer
    /// against any instance's queue — an `Unknown` row whose offer exists
    /// somewhere is the same physical write risk no matter which site's
    /// queue holds it, and the per-site read would silently unblock the
    /// re-homed retry and double-execute the BMC write.
    ///
    /// The read is the directed lookup over the plaintext `operation_id`
    /// column (R6-E-04) without the instance filter; the single-column
    /// `ix_center_outbox_operation` index serves it. Rows written before
    /// the `operation_id` migration carry `NULL`: exactly like the
    /// per-instance read, the lookup then falls back to a payload scan of
    /// the NULL-column rows (across instances — the pre-migration queue of
    /// any instance can hide the offer), backfills the found row, and
    /// returns it, so a pre-migration acknowledged offer is never mistaken
    /// for a never-enqueued record even after the endpoint moved. The
    /// sequence is per-instance, so the cross-instance "newest" ordering
    /// is by creation time, not by sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any scanned
    /// stored row violates domain invariants or its payload ciphertext
    /// cannot be authenticated, and
    /// [`CenterOutboxRepositoryError::CommandKeyMissing`] when a ciphertext
    /// row is read through a keyless store.
    pub async fn find_offer_by_operation_across_instances(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<OutboxEntry>, CenterOutboxRepositoryError> {
        let model = center_outbox::Entity::find()
            .filter(center_outbox::Column::OperationId.eq(operation_id.into_uuid()))
            .order_by_desc(center_outbox::Column::CreatedAt)
            .order_by_desc(center_outbox::Column::Id)
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        if let Some(model) = model {
            let entry_id = OutboxEntryId::from_uuid(model.id);
            return map_stored_outbox_entry(self, entry_id, &model).map(Some);
        }
        // W7-P-2: the NULL-existence gate of the per-instance read,
        // across instances — a miss on fully backfilled queues answers
        // without decrypting anything.
        let null_row = center_outbox::Entity::find()
            .filter(center_outbox::Column::OperationId.is_null())
            .select_only()
            .column(center_outbox::Column::Id)
            .limit(1)
            .into_tuple::<(Uuid,)>()
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        if null_row.is_none() {
            return Ok(None);
        }
        // Pre-migration rows: scan the NULL-column rows of every instance,
        // backfill the first match, and return it.
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::OperationId.is_null())
            .order_by_desc(center_outbox::Column::CreatedAt)
            .order_by_desc(center_outbox::Column::Id)
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        for model in models {
            let entry_id = OutboxEntryId::from_uuid(model.id);
            let entry = map_stored_outbox_entry(self, entry_id, &model)?;
            if payload_operation_id(entry.payload_json()) != Some(operation_id) {
                continue;
            }
            // The backfill is a write, so it runs under the write gate like
            // every other queue write; it cannot deadlock — no caller of
            // this read holds the *write gate* while awaiting the read.
            // (The center dispatch calls the cross-instance read inside
            // its per-site dispatch gate, R6-C-1 — a separate lock held
            // for one dispatch, never across a write-gate acquisition by
            // the same task.)
            let _write_permit = self
                .write_gate
                .acquire()
                .await
                .map_err(CenterOutboxRepositoryError::Coordinate)?;
            center_outbox::Entity::update_many()
                .filter(center_outbox::Column::Id.eq(entry_id.into_uuid()))
                .set(center_outbox::ActiveModel {
                    operation_id: Set(Some(operation_id.into_uuid())),
                    ..Default::default()
                })
                .exec(&self.database)
                .await
                .map_err(CenterOutboxRepositoryError::Database)?;
            return Ok(Some(entry));
        }
        Ok(None)
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
    operation_id: Option<OperationId>,
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
        operation_id: Set(operation_id.map(OperationId::into_uuid)),
    }
    .insert(database)
    .await
    .map_err(CenterOutboxRepositoryError::Database)?;
    Ok(())
}

/// The plaintext §15.6 operation id of one outbound envelope payload
/// (R6-E-04): `Some(id)` for an offer row, `None` for every other row. The
/// `operation_id` column mirrors this value, so a stored `operation_id`
/// always agrees with the decrypted payload of its row.
fn payload_operation_id(payload_json: &str) -> Option<OperationId> {
    let envelope: Envelope = serde_json::from_str(payload_json).ok()?;
    let EnvelopeMessage::OperationOffer(offer) = envelope.message? else {
        return None;
    };
    offer.operation_id.parse().ok()
}

/// Prunes the acknowledged history of one operation within one instance
/// (R6-E-04, W7-F-1): the newest acknowledged row of the operation in the
/// instance is kept, every other acknowledged row of the same operation
/// in the same instance is deleted.
///
/// The keeper is the newest row of the instance's queue for the operation
/// — the just-acknowledged row included — so a retry that re-delivered a
/// fresh offer under the same id keeps the newest acknowledged row and the
/// older ones disappear. The instance filter is the W7-F-1 fix: the
/// sequence is per-instance, so the same operation id can legitimately
/// ride in two instances' queues (an endpoint re-homed between dispatches
/// of the same id), and the pruning of one instance's history must never
/// delete the other instance's rows — those rows are the R6-E-01 evidence
/// surface of the other dispatch. Rows without an operation id (the
/// site-side content queue) are never touched — this helper only runs for
/// a row that carries one — and pending rows are never pruned: a pending
/// row is still deliverable.
///
/// # Errors
///
/// Returns [`CenterOutboxRepositoryError::Database`] when a query fails.
async fn prune_acked_operation_history<C>(
    database: &C,
    instance_id: Uuid,
    operation_id: Uuid,
) -> Result<(), CenterOutboxRepositoryError>
where
    C: ConnectionTrait,
{
    let Some(keeper) = center_outbox::Entity::find()
        .filter(center_outbox::Column::InstanceId.eq(instance_id))
        .filter(center_outbox::Column::OperationId.eq(operation_id))
        .filter(center_outbox::Column::State.eq("acked"))
        .order_by_desc(center_outbox::Column::Sequence)
        .order_by_desc(center_outbox::Column::Id)
        .one(database)
        .await
        .map_err(CenterOutboxRepositoryError::Database)?
    else {
        return Ok(());
    };
    center_outbox::Entity::delete_many()
        .filter(center_outbox::Column::InstanceId.eq(instance_id))
        .filter(center_outbox::Column::OperationId.eq(operation_id))
        .filter(center_outbox::Column::State.eq("acked"))
        .filter(center_outbox::Column::Id.ne(keeper.id))
        .exec(database)
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

    use rutilus_center_protocol::{Envelope, EnvelopeMessage, Heartbeat, OperationOffer};
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
    async fn bounded_listing_returns_only_the_newest_entries_newest_first()
    -> Result<(), Box<dyn Error>> {
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

        // The bounded scan (V4P-2) keeps the newest entries only, newest
        // first: the tracking view's decrypt surface is capped at the
        // window instead of the whole queue.
        let page = store.list_outbox_entries_bounded(site.id(), 2).await?;
        assert_eq!(
            page.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![3, 2],
            "the bound must keep the newest entries, newest first"
        );
        let all = store.list_outbox_entries_bounded(site.id(), 10).await?;
        assert_eq!(
            all.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "a bound above the queue size is the full newest-first listing"
        );
        assert!(
            store
                .list_outbox_entries_bounded(site.id(), 0)
                .await?
                .is_empty(),
            "a zero bound reads nothing"
        );

        // Another instance's entries never leak into this scan.
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
        let page = store.list_outbox_entries_bounded(site.id(), 2).await?;
        assert_eq!(
            page.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![3, 2]
        );

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
            operation_id: Set(None),
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
            operation_id: Set(None),
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

    /// One `OperationOffer` under a caller-chosen operation id — the offer
    /// shape the center's dispatch enqueues (R6-E-04 tests need two offers
    /// of the same operation to exercise the directed read and the ack
    /// pruning).
    fn offer_for(site: &SiteInstance, operation_id: OperationId) -> EnvelopeMessage {
        let command = RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
            AccountUserName::parse("jane").unwrap_or_else(|_| unreachable!("valid user name")),
            AccountPassword::parse("correct-horse-battery-staple".to_owned())
                .unwrap_or_else(|_| unreachable!("valid password")),
            RoleId::parse("Operator").unwrap_or_else(|_| unreachable!("valid role")),
        )));
        EnvelopeMessage::OperationOffer(OperationOffer {
            operation_id: operation_id.to_string(),
            endpoint_id: EndpointId::generate().to_string(),
            site_id: site.id().to_string(),
            command_json: serde_json::to_vec(&command)
                .unwrap_or_else(|_| unreachable!("serializable command")),
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix: 0,
            actor_context: String::from("actor"),
        })
    }

    #[tokio::test]
    async fn enqueue_writes_the_plaintext_operation_id_and_the_directed_read_returns_the_newest()
    -> Result<(), Box<dyn Error>> {
        // R6-E-04: the offer's operation id lands in the plaintext column
        // at enqueue time, and the directed read returns the newest row of
        // the operation without scanning the queue — while a content row
        // (no operation id) is never mistaken for an offer.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();

        store
            .enqueue_outbox_entry(site.id(), &offer_for(&site, operation_id), base)
            .await?;
        store
            .enqueue_outbox_entry(
                site.id(),
                &offer_for(&site, operation_id),
                base + Duration::SECOND,
            )
            .await?;
        let model = center_outbox::Entity::find()
            .filter(center_outbox::Column::OperationId.eq(operation_id.into_uuid()))
            .one(&store.database)
            .await?
            .ok_or("no row carries the plaintext operation id")?;
        assert_eq!(
            model.operation_id,
            Some(operation_id.into_uuid()),
            "the offer's operation id must be written in the clear at insert time"
        );

        let newest = store
            .find_outbox_entry_by_operation(site.id(), operation_id)
            .await?
            .ok_or("the directed read missed the operation")?;
        assert_eq!(
            newest.sequence(),
            2,
            "the directed read returns the newest row"
        );

        let content = EnvelopeMessage::Heartbeat(Heartbeat::default());
        store
            .enqueue_outbox_entry(site.id(), &content, base)
            .await?;
        let unknown = OperationId::generate();
        assert!(
            store
                .find_outbox_entry_by_operation(site.id(), unknown)
                .await?
                .is_none(),
            "an operation with no offer row reads as absent"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn ack_prunes_the_older_acked_rows_of_the_same_operation() -> Result<(), Box<dyn Error>> {
        // R6-E-04: an acknowledged offer row is delivered history, and the
        // retry reads only the newest row per operation — so the older
        // acknowledged rows of the same operation are pruned at ack time,
        // while pending rows (still deliverable) and other operations' rows
        // survive untouched.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        let other_id = OperationId::generate();

        let first = store
            .enqueue_outbox_entry(site.id(), &offer_for(&site, operation_id), base)
            .await?;
        let second = store
            .enqueue_outbox_entry(
                site.id(),
                &offer_for(&site, operation_id),
                base + Duration::SECOND,
            )
            .await?;
        let other = store
            .enqueue_outbox_entry(
                site.id(),
                &offer_for(&site, other_id),
                base + Duration::seconds(2),
            )
            .await?;

        // Acknowledging the older row prunes nothing yet — it IS the newest
        // acknowledged row of the operation, so it is kept.
        store
            .ack_outbox_entry(first.id(), base + Duration::seconds(3))
            .await?;
        assert_eq!(store.list_outbox_entries(site.id()).await?.len(), 3);

        // Acknowledging the retry's row prunes the older acknowledged one:
        // one acked row per operation remains, and the other operation's
        // pending row is untouched.
        store
            .ack_outbox_entry(second.id(), base + Duration::seconds(4))
            .await?;
        let rows = store.list_outbox_entries(site.id()).await?;
        assert_eq!(rows.len(), 2, "the older acked row must be pruned");
        assert!(
            rows.iter().any(|row| row.id() == second.id()),
            "the newest acked row of the operation is the keeper"
        );
        assert!(
            rows.iter().any(|row| row.id() == other.id()),
            "another operation's pending row must survive the pruning"
        );
        assert!(
            rows.iter().all(|row| row.id() != first.id()),
            "the older acked row must be gone"
        );
        assert_eq!(rows[1].state(), OutboxEntryState::Pending);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_directed_read_backfills_rows_written_before_the_operation_id_column()
    -> Result<(), Box<dyn Error>> {
        // R6-E-04: rows written before the migration carry `NULL` in the
        // operation_id column. The directed read must still find the newest
        // offer row of the operation — a pre-migration acknowledged offer
        // must never be mistaken for a never-enqueued record (the F1
        // double-execution guard) — and it backfills the column, so the
        // next read is the indexed query.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        let message = offer_for(&site, operation_id);
        let envelope = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(message.clone()),
        };
        let legacy = OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            1,
            serde_json::to_string(&envelope)?,
            base,
        );
        // A pre-migration row: written straight into the table without the
        // operation id, exactly as the pre-migration repository did.
        center_outbox::ActiveModel {
            id: Set(legacy.id().into_uuid()),
            sequence: Set(legacy.sequence()),
            instance_id: Set(legacy.instance_id().into_uuid()),
            payload_json: Set(legacy.payload_json().to_owned()),
            state: Set(legacy.state().as_str().to_owned()),
            retry_count: Set(legacy.retry_count()),
            created_at: Set(legacy.created_at()),
            acked_at: Set(legacy.acked_at()),
            operation_id: Set(None),
        }
        .insert(&store.database)
        .await?;

        let found = store
            .find_outbox_entry_by_operation(site.id(), operation_id)
            .await?
            .ok_or("the directed read must find the pre-migration offer")?;
        assert_eq!(found.id(), legacy.id());

        // The column is backfilled, so the directed read is now the indexed
        // query.
        let model = center_outbox::Entity::find_by_id(legacy.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("the legacy row is missing")?;
        assert_eq!(
            model.operation_id,
            Some(operation_id.into_uuid()),
            "the directed read must backfill the plaintext operation id"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn ack_pruning_is_scoped_to_the_acked_rows_instance() -> Result<(), Box<dyn Error>> {
        // W7-F-1: the ack pruning filters by (instance, operation) — the
        // sequence is per-instance, so the same operation id can ride in
        // two instances' queues (an endpoint re-homed between dispatches of
        // the same id), and one instance's ack must never prune the other
        // instance's acknowledged rows: those rows are the evidence surface
        // of the other dispatch (R6-E-01).
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site_a = site_instance(base);
        let site_b = site_instance(base + Duration::SECOND);
        store.create_instance(&site_a).await?;
        store.create_instance(&site_b).await?;
        let operation_id = OperationId::generate();

        // Site A holds one acknowledged offer row of the operation.
        let a_row = store
            .enqueue_outbox_entry(site_a.id(), &offer_for(&site_a, operation_id), base)
            .await?;
        store
            .ack_outbox_entry(a_row.id(), base + Duration::SECOND)
            .await?;

        // Site B holds two acknowledged rows and a fresh pending one; the
        // final ack prunes B's own older acknowledged rows but must leave
        // A's row alone.
        let b_first = store
            .enqueue_outbox_entry(site_b.id(), &offer_for(&site_b, operation_id), base)
            .await?;
        store
            .ack_outbox_entry(b_first.id(), base + Duration::SECOND)
            .await?;
        let b_second = store
            .enqueue_outbox_entry(
                site_b.id(),
                &offer_for(&site_b, operation_id),
                base + Duration::SECOND * 2,
            )
            .await?;
        store
            .ack_outbox_entry(b_second.id(), base + Duration::SECOND * 3)
            .await?;
        let b_pending = store
            .enqueue_outbox_entry(
                site_b.id(),
                &offer_for(&site_b, operation_id),
                base + Duration::SECOND * 4,
            )
            .await?;
        store
            .ack_outbox_entry(b_pending.id(), base + Duration::SECOND * 5)
            .await?;

        let rows_a = store.list_outbox_entries(site_a.id()).await?;
        assert_eq!(
            rows_a.len(),
            1,
            "site A's evidence row must survive the other instance's ack"
        );
        assert_eq!(rows_a[0].id(), a_row.id());
        assert_eq!(rows_a[0].state(), OutboxEntryState::Acked);
        let rows_b = store.list_outbox_entries(site_b.id()).await?;
        assert_eq!(
            rows_b.iter().map(OutboxEntry::id).collect::<Vec<_>>(),
            vec![b_pending.id()],
            "site B keeps only its own newest acknowledged row"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn a_directed_read_miss_on_a_backfilled_queue_never_decrypts_anything()
    -> Result<(), Box<dyn Error>> {
        // W7-P-2: once every row of the queue carries the operation_id
        // column, a directed read for a never-enqueued id returns
        // immediately — the NULL existence check proves no pre-migration
        // row can hide the offer, so no payload is decrypted. The corrupted
        // ciphertext row planted below would surface as `Corrupt` if any
        // scan touched it; the miss stays clean, proving the scan never
        // ran.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        let other_id = OperationId::generate();

        store
            .enqueue_outbox_entry(site.id(), &offer_for(&site, operation_id), base)
            .await?;
        // A pre-migration NULL row for another operation: the first
        // directed read backfills it, leaving no NULL rows behind.
        let legacy = OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            2,
            serde_json::to_string(&Envelope {
                sequence: 2,
                acked_sequence: 0,
                message: Some(offer_for(&site, other_id)),
            })?,
            base + Duration::SECOND,
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
            operation_id: Set(None),
        }
        .insert(&store.database)
        .await?;
        let found = store
            .find_outbox_entry_by_operation(site.id(), other_id)
            .await?
            .ok_or("the directed read must find the pre-migration offer")?;
        assert_eq!(found.id(), legacy.id());

        // A corrupted ciphertext row whose column is set: any payload scan
        // of the queue would decrypt it and fail as Corrupt.
        let corrupt_id = OutboxEntryId::generate();
        let corrupt_operation_id = OperationId::generate();
        center_outbox::ActiveModel {
            id: Set(corrupt_id.into_uuid()),
            sequence: Set(3),
            instance_id: Set(site.id().into_uuid()),
            payload_json: Set(String::from("RUTC1:not-a-real-envelope")),
            state: Set(String::from("pending")),
            retry_count: Set(0),
            created_at: Set(base + Duration::seconds(2)),
            acked_at: Set(None),
            operation_id: Set(Some(corrupt_operation_id.into_uuid())),
        }
        .insert(&store.database)
        .await?;

        // The queue holds no NULL rows: the miss for a never-enqueued id
        // is answered without decrypting anything — the corrupt row is
        // never touched.
        let unknown = OperationId::generate();
        assert!(
            store
                .find_outbox_entry_by_operation(site.id(), unknown)
                .await?
                .is_none(),
            "a miss on a fully backfilled queue must answer None without a payload scan"
        );
        // The corrupt row's own operation still reads as Corrupt when
        // addressed directly — the planted row is genuinely
        // undecryptable, which is what makes the clean miss above the
        // proof that no scan ran.
        assert!(matches!(
            store
                .find_outbox_entry_by_operation(site.id(), corrupt_operation_id)
                .await,
            Err(CenterOutboxRepositoryError::Corrupt { entry_id, .. })
                if entry_id == corrupt_id
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_cross_instance_offer_lookup_confirms_an_offer_in_any_instances_queue()
    -> Result<(), Box<dyn Error>> {
        // W7-E-3: the unknown-outcome confirmation must hold across an
        // endpoint re-home — the offer may live in the original site's
        // queue while the retry addresses the new site's. The cross-instance
        // lookup finds the row the per-site read of the new site cannot
        // see.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site_a = site_instance(base);
        let site_b = site_instance(base + Duration::SECOND);
        store.create_instance(&site_a).await?;
        store.create_instance(&site_b).await?;
        let operation_id = OperationId::generate();

        store
            .enqueue_outbox_entry(site_a.id(), &offer_for(&site_a, operation_id), base)
            .await?;

        // The new site's queue holds no row; the cross-instance read still
        // confirms the offer in the original site's queue.
        assert!(
            store
                .find_outbox_entry_by_operation(site_b.id(), operation_id)
                .await?
                .is_none(),
            "the per-site read of the new site must not see the old site's row"
        );
        let entry = store
            .find_offer_by_operation_across_instances(operation_id)
            .await?
            .ok_or("the cross-instance read must find the original site's row")?;
        assert_eq!(entry.instance_id(), site_a.id());

        // A never-enqueued operation reads as absent.
        assert!(
            store
                .find_offer_by_operation_across_instances(OperationId::generate())
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_cross_instance_offer_lookup_backfills_pre_migration_null_rows()
    -> Result<(), Box<dyn Error>> {
        // W7-E-3: the cross-instance fallback covers pre-migration NULL
        // rows — an acknowledged pre-migration offer in the original site's
        // queue is never mistaken for a never-enqueued record after the
        // endpoint moved — and backfills the found row like the per-instance
        // read.
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site_a = site_instance(base);
        let site_b = site_instance(base + Duration::SECOND);
        store.create_instance(&site_a).await?;
        store.create_instance(&site_b).await?;
        let operation_id = OperationId::generate();
        let message = offer_for(&site_a, operation_id);
        let envelope = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(message),
        };
        let legacy = OutboxEntry::new(
            OutboxEntryId::generate(),
            site_a.id(),
            1,
            serde_json::to_string(&envelope)?,
            base,
        );
        // A pre-migration row: written straight into the table without the
        // operation id, exactly as the pre-migration repository did.
        center_outbox::ActiveModel {
            id: Set(legacy.id().into_uuid()),
            sequence: Set(legacy.sequence()),
            instance_id: Set(legacy.instance_id().into_uuid()),
            payload_json: Set(legacy.payload_json().to_owned()),
            state: Set(legacy.state().as_str().to_owned()),
            retry_count: Set(legacy.retry_count()),
            created_at: Set(legacy.created_at()),
            acked_at: Set(legacy.acked_at()),
            operation_id: Set(None),
        }
        .insert(&store.database)
        .await?;

        let found = store
            .find_offer_by_operation_across_instances(operation_id)
            .await?
            .ok_or("the cross-instance read must find the pre-migration offer")?;
        assert_eq!(found.id(), legacy.id());
        assert_eq!(found.instance_id(), site_a.id());

        // The column is backfilled, so the read is now the indexed query.
        let model = center_outbox::Entity::find_by_id(legacy.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("the legacy row is missing")?;
        assert_eq!(
            model.operation_id,
            Some(operation_id.into_uuid()),
            "the cross-instance read must backfill the plaintext operation id"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
