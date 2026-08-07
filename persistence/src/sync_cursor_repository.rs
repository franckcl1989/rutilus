use rutilus_domain::{InstanceId, SyncCursor, SyncCursorId, SyncStream, SyncStreamParseError};
use rutilus_entity::sync_cursor;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, Set,
    TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Reads one per-instance sync-stream cursor (design §17).
    ///
    /// # Errors
    ///
    /// Returns [`SyncCursorRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn get_sync_cursor(
        &self,
        instance_id: InstanceId,
        stream: SyncStream,
    ) -> Result<Option<SyncCursor>, SyncCursorRepositoryError> {
        let Some(model) = sync_cursor::Entity::find()
            .filter(sync_cursor::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(sync_cursor::Column::Stream.eq(stream.as_str()))
            .one(&self.database)
            .await
            .map_err(SyncCursorRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_cursor(SyncCursorId::from_uuid(model.id), &model).map(Some)
    }

    /// Stores one per-instance sync-stream cursor (design §17).
    ///
    /// The write is an upsert keyed on the unique `(instance_id, stream)`
    /// pair, so the cursor of a stream is always exactly one row: a fresh
    /// stream inserts, an existing stream replaces its value and update
    /// time.
    ///
    /// # Errors
    ///
    /// Returns [`SyncCursorRepositoryError`] when write coordination fails,
    /// the transaction cannot commit, or the insert fails.
    pub async fn set_sync_cursor(
        &self,
        cursor: &SyncCursor,
    ) -> Result<(), SyncCursorRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SyncCursorRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(SyncCursorRepositoryError::Database)?;
        let existing = sync_cursor::Entity::find()
            .filter(sync_cursor::Column::InstanceId.eq(cursor.instance_id().into_uuid()))
            .filter(sync_cursor::Column::Stream.eq(cursor.stream().as_str()))
            .one(&transaction)
            .await
            .map_err(SyncCursorRepositoryError::Database)?;
        if let Some(model) = existing {
            let mut active = model.into_active_model();
            active.cursor_value = Set(cursor.cursor_value().to_owned());
            active.updated_at = Set(cursor.updated_at());
            active
                .update(&transaction)
                .await
                .map_err(SyncCursorRepositoryError::Database)?;
        } else {
            sync_cursor::ActiveModel {
                id: Set(cursor.id().into_uuid()),
                instance_id: Set(cursor.instance_id().into_uuid()),
                stream: Set(cursor.stream().as_str().to_owned()),
                cursor_value: Set(cursor.cursor_value().to_owned()),
                updated_at: Set(cursor.updated_at()),
            }
            .insert(&transaction)
            .await
            .map_err(SyncCursorRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(SyncCursorRepositoryError::Database)
    }
}

fn map_stored_cursor(
    cursor_id: SyncCursorId,
    model: &sync_cursor::Model,
) -> Result<SyncCursor, SyncCursorRepositoryError> {
    let stream = model
        .stream
        .parse::<SyncStream>()
        .map_err(StoredSyncCursorError::InvalidStream)
        .map_err(|source| SyncCursorRepositoryError::Corrupt { cursor_id, source })?;
    Ok(SyncCursor::new(
        cursor_id,
        InstanceId::from_uuid(model.instance_id),
        stream,
        model.cursor_value.clone(),
        model.updated_at,
    ))
}

/// A controlled failure while persisting or reading sync-stream cursors.
#[derive(Debug, Error)]
pub enum SyncCursorRepositoryError {
    #[error("sync cursor write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored sync cursor {cursor_id} is invalid: {source}")]
    Corrupt {
        cursor_id: SyncCursorId,
        #[source]
        source: StoredSyncCursorError,
    },
    #[error("sync cursor database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted cursor data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredSyncCursorError {
    #[error("stored sync stream is invalid: {0}")]
    InvalidStream(#[source] SyncStreamParseError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        InstanceId, InstanceKind, SiteInstance, SyncCursor, SyncCursorId, SyncStream,
    };
    use time::OffsetDateTime;

    use crate::SqliteStore;

    fn cursor_at(
        instance_id: InstanceId,
        stream: SyncStream,
        value: &str,
        updated_at: OffsetDateTime,
    ) -> SyncCursor {
        SyncCursor::new(
            SyncCursorId::generate(),
            instance_id,
            stream,
            String::from(value),
            updated_at,
        )
    }

    #[tokio::test]
    async fn cursors_upsert_per_instance_and_stream() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&site).await?;
        let instance_id = site.id();

        assert_eq!(
            store
                .get_sync_cursor(instance_id, SyncStream::Event)
                .await?,
            None
        );

        // A fresh stream inserts its cursor.
        let first = cursor_at(instance_id, SyncStream::Event, "100", base);
        store.set_sync_cursor(&first).await?;
        let stored = store
            .get_sync_cursor(instance_id, SyncStream::Event)
            .await?
            .ok_or("stored cursor is missing")?;
        assert_eq!(stored.cursor_value(), "100");

        // Re-setting the same stream replaces the value: exactly one row.
        let second = cursor_at(
            instance_id,
            SyncStream::Event,
            "200",
            base + time::Duration::SECOND,
        );
        store.set_sync_cursor(&second).await?;
        let stored = store
            .get_sync_cursor(instance_id, SyncStream::Event)
            .await?
            .ok_or("stored cursor is missing")?;
        assert_eq!(stored.cursor_value(), "200");
        assert_eq!(stored.updated_at(), base + time::Duration::SECOND);
        assert_eq!(stored.id(), first.id(), "the upsert keeps the original row");

        // Another stream of the same instance is its own cursor, and so is
        // the same stream of another instance.
        store
            .set_sync_cursor(&cursor_at(instance_id, SyncStream::Health, "5", base))
            .await?;
        let other = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Two"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&other).await?;
        let other_instance = other.id();
        store
            .set_sync_cursor(&cursor_at(other_instance, SyncStream::Event, "1", base))
            .await?;
        assert_eq!(
            store
                .get_sync_cursor(instance_id, SyncStream::Health)
                .await?
                .ok_or("the health cursor is missing")?
                .cursor_value(),
            "5"
        );
        assert_eq!(
            store
                .get_sync_cursor(other_instance, SyncStream::Event)
                .await?
                .ok_or("the other instance cursor is missing")?
                .cursor_value(),
            "1"
        );
        assert_eq!(
            store
                .get_sync_cursor(instance_id, SyncStream::Artifact)
                .await?,
            None
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
