use std::error::Error;

use rutilus_entity::{center_binding, center_inbox, center_outbox, instance, sync_cursor};
use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const CENTER_TABLES: [&str; 5] = [
    "instances",
    "center_bindings",
    "center_outbox",
    "center_inbox",
    "sync_cursors",
];

#[tokio::test]
async fn center_tables_migration_creates_and_drops_the_five_tables() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Idempotency: the migration history replays cleanly twice, so an
    // interrupted upgrade can resume without a half-created schema.
    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_tables(&database, true).await?;

    Migrator::down(&database, None).await?;
    assert_tables(&database, false).await?;

    Ok(())
}

// Every center-shape table constraint is spelled out as its own
// insert-and-assert so a failure pinpoints the exact rule (kind and state
// vocabularies, the pending/bound/revoked column shapes, the
// single-center-binding partial unique index, the per-instance outbox
// sequence, the operation-id idempotency key, the per-stream cursor
// uniqueness, and the foreign keys), which exceeds the pedantic line budget.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn center_tables_constraints_and_foreign_keys_hold() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let now = OffsetDateTime::now_utc();

    // One registered site and one center identity round-trip; the kind CHECK
    // pins the vocabulary, and the foreign keys refuse unknown instances.
    let site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(site_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let center_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(center_id),
        display_name: Set(String::from("Center One")),
        instance_kind: Set(String::from("center")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let unknown_kind = instance::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Standalone")),
        instance_kind: Set(String::from("standalone")),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_kind.is_err(),
        "an unknown instance kind must be refused"
    );

    // A pending binding round-trips with its code hash and expiry; the shape
    // CHECK refuses a pending row with a bind time, a bound row that still
    // carries the code hash, and an unknown state.
    let binding_id = Uuid::now_v7();
    let code_hash = vec![0x5a; 32];
    center_binding::ActiveModel {
        id: Set(binding_id),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(code_hash.clone())),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("pending")),
        bound_at: Set(None),
        expires_at: Set(Some(now + time::Duration::minutes(15))),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let stored_binding = center_binding::Entity::find_by_id(binding_id)
        .one(&database)
        .await?
        .ok_or("inserted binding is missing")?;
    assert_eq!(stored_binding.state, "pending");
    assert_eq!(stored_binding.binding_code_hash, Some(code_hash));

    let unknown_state = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(vec![0x5a; 32])),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("binding")),
        bound_at: Set(None),
        expires_at: Set(Some(now + time::Duration::minutes(15))),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_state.is_err(),
        "an unknown binding state must be refused"
    );
    let bound_while_pending = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(vec![0x5a; 32])),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("pending")),
        bound_at: Set(Some(now)),
        expires_at: Set(Some(now + time::Duration::minutes(15))),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        bound_while_pending.is_err(),
        "a pending binding must not carry a bind time"
    );
    let hash_after_bound = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(vec![0x5a; 32])),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("bound")),
        bound_at: Set(Some(now)),
        expires_at: Set(None),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        hash_after_bound.is_err(),
        "a bound binding must not carry the consumed code hash"
    );

    // The single-center-binding rule: a second active binding for the same
    // site is refused by the partial unique index, while a revoked binding
    // no longer counts and the site can re-register.
    let second_pending = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(vec![0x6b; 32])),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("pending")),
        bound_at: Set(None),
        expires_at: Set(Some(now + time::Duration::minutes(15))),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        second_pending.is_err(),
        "a site must have at most one active binding"
    );
    // A revoked row does not count as active, so it can coexist with the
    // outstanding pending row as a historical record.
    let revoked_row = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(None),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("revoked")),
        bound_at: Set(None),
        expires_at: Set(None),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        revoked_row.is_ok(),
        "a revoked binding must not count as active"
    );

    // Once the pending binding is revoked, the site can re-register: the
    // partial unique index no longer sees an active row.
    let revoke_pending = center_binding::ActiveModel {
        id: Set(binding_id),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(None),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("revoked")),
        bound_at: Set(None),
        expires_at: Set(None),
        created_at: Set(now),
    }
    .update(&database)
    .await;
    assert!(
        revoke_pending.is_ok(),
        "the pending binding must be revocable"
    );
    let rebind = center_binding::ActiveModel {
        id: Set(Uuid::now_v7()),
        center_url: Set(String::from("https://center.example")),
        binding_code_hash: Set(Some(vec![0x6b; 32])),
        site_instance_id: Set(site_id),
        site_cert_fingerprint: Set(None),
        state: Set(String::from("pending")),
        bound_at: Set(None),
        expires_at: Set(Some(now + time::Duration::minutes(15))),
        created_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        rebind.is_ok(),
        "a revoked binding must not count as active, so the site can re-register"
    );

    // The outbox: the per-instance sequence is unique, the state vocabulary
    // is pinned, and an acked row must carry its ack time.
    center_outbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        sequence: Set(1),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"sequence":1}"#)),
        state: Set(String::from("pending")),
        retry_count: Set(0),
        created_at: Set(now),
        acked_at: Set(None),
    }
    .insert(&database)
    .await?;
    let duplicate_sequence = center_outbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        sequence: Set(1),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"sequence":1}"#)),
        state: Set(String::from("pending")),
        retry_count: Set(0),
        created_at: Set(now),
        acked_at: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        duplicate_sequence.is_err(),
        "the per-instance outbox sequence must be unique"
    );
    // The same sequence is fine for another instance: the uniqueness is
    // per-instance.
    center_outbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        sequence: Set(1),
        instance_id: Set(center_id),
        payload_json: Set(String::from(r#"{"sequence":1}"#)),
        state: Set(String::from("pending")),
        retry_count: Set(0),
        created_at: Set(now),
        acked_at: Set(None),
    }
    .insert(&database)
    .await?;
    let acked_without_time = center_outbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        sequence: Set(2),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"sequence":2}"#)),
        state: Set(String::from("acked")),
        retry_count: Set(0),
        created_at: Set(now),
        acked_at: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        acked_without_time.is_err(),
        "an acked outbox entry must carry its ack time"
    );
    let negative_retries = center_outbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        sequence: Set(3),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"sequence":3}"#)),
        state: Set(String::from("pending")),
        retry_count: Set(-1),
        created_at: Set(now),
        acked_at: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        negative_retries.is_err(),
        "a negative retry count must be refused"
    );

    // The inbox: the operation id is the atomic idempotency key, the state
    // vocabulary is pinned, and the instance foreign key is enforced.
    let operation_id = Uuid::now_v7();
    center_inbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(operation_id.simple().to_string()),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"operation_id":"1"}"#)),
        state: Set(String::from("received")),
        expires_at: Set(now + time::Duration::hours(1)),
        received_at: Set(now),
    }
    .insert(&database)
    .await?;
    let duplicate_operation = center_inbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(operation_id.simple().to_string()),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"operation_id":"1"}"#)),
        state: Set(String::from("received")),
        expires_at: Set(now + time::Duration::hours(1)),
        received_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        duplicate_operation.is_err(),
        "the same operation id must never land twice"
    );
    let unknown_inbox_state = center_inbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7().simple().to_string()),
        instance_id: Set(site_id),
        payload_json: Set(String::from(r#"{"operation_id":"2"}"#)),
        state: Set(String::from("queued")),
        expires_at: Set(now + time::Duration::hours(1)),
        received_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_inbox_state.is_err(),
        "an unknown inbox state must be refused"
    );
    let unknown_instance = center_inbox::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7().simple().to_string()),
        instance_id: Set(Uuid::now_v7()),
        payload_json: Set(String::from(r#"{"operation_id":"3"}"#)),
        state: Set(String::from("received")),
        expires_at: Set(now + time::Duration::hours(1)),
        received_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_instance.is_err(),
        "an inbox entry must belong to a registered instance"
    );

    // The cursors: one row per (instance, stream), with the stream
    // vocabulary pinned.
    sync_cursor::ActiveModel {
        id: Set(Uuid::now_v7()),
        instance_id: Set(site_id),
        stream: Set(String::from("event")),
        cursor_value: Set(String::from("100")),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    let duplicate_stream = sync_cursor::ActiveModel {
        id: Set(Uuid::now_v7()),
        instance_id: Set(site_id),
        stream: Set(String::from("event")),
        cursor_value: Set(String::from("101")),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        duplicate_stream.is_err(),
        "one cursor per (instance, stream) must be unique"
    );
    // The same stream is fine for another instance.
    sync_cursor::ActiveModel {
        id: Set(Uuid::now_v7()),
        instance_id: Set(center_id),
        stream: Set(String::from("event")),
        cursor_value: Set(String::from("1")),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    let unknown_stream = sync_cursor::ActiveModel {
        id: Set(Uuid::now_v7()),
        instance_id: Set(site_id),
        stream: Set(String::from("telemetry")),
        cursor_value: Set(String::from("0")),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_stream.is_err(),
        "an unknown sync stream must be refused"
    );

    // Deleting a registered site cascades its queues, bindings, and cursors
    // away (the foreign keys all name instances.id).
    instance::Entity::delete_by_id(site_id)
        .exec(&database)
        .await?;
    assert_eq!(
        center_binding::Entity::find().all(&database).await?.len(),
        0,
        "the site's bindings must cascade away with the instance"
    );
    assert_eq!(
        center_outbox::Entity::find().all(&database).await?.len(),
        1,
        "the site's outbox must cascade away with the instance, leaving the center's own row"
    );
    assert_eq!(
        center_inbox::Entity::find().all(&database).await?.len(),
        0,
        "the site's inbox must cascade away with the instance"
    );
    assert_eq!(
        sync_cursor::Entity::find().all(&database).await?.len(),
        1,
        "the site's cursors must cascade away with the instance, leaving the center's own row"
    );

    Ok(())
}

async fn assert_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in CENTER_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}

/// Opens one database in a fresh temporary directory.
///
/// The `TempDir` is returned with the connection so it outlives `connect`:
/// dropping it here would unlink the database file while the pool's eager
/// connection still holds it open — harmless on Windows (an open file cannot
/// be deleted), but on Linux the unlink succeeds and the first write
/// statement then fails while creating the rollback journal (the journal
/// open stats the journal path (database path plus "-journal"), which no longer exists, surfacing as
/// `SQLITE_IOERR_FSTAT` / "disk I/O error" on CI).
async fn connect() -> Result<(tempfile::TempDir, DatabaseConnection), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;
    Ok((directory, database))
}
