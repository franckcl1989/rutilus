use std::error::Error;

use rutilus_entity::event;
use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const EVENT_TABLES: [&str; 1] = ["events"];

/// The full `Event_v1` severity vocabulary, in the codes the domain
/// `EventSeverity` persists. The database CHECK must accept exactly these
/// and nothing else.
const EVENT_SEVERITIES: [&str; 3] = ["ok", "warning", "critical"];

#[tokio::test]
async fn events_migration_preserves_severity_and_dedup_invariants() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_event_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_event_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_event_tables(&database, false).await?;

    Ok(())
}

// Every §14.4 constraint is spelled out as its own insert-and-assert so a
// failure pinpoints the exact rule (each severity code accepted, the
// unknown code refused by the CHECK, and the three dedup-collision cases),
// which exceeds the pedantic line budget; the domain and infra crates allow
// the same lint on their exhaustive assertion tests.
#[allow(clippy::too_many_lines)]
async fn verify_event_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let endpoint_id = Uuid::now_v7();
    let event_timestamp = now - time::Duration::SECOND;
    let dedup_key = String::from("Alert.1.0.PowerSupplyFailure\u{1F}1773973891234567890");

    let event_id = Uuid::now_v7();
    event::ActiveModel {
        id: Set(event_id),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("Alert.1.0.PowerSupplyFailure")),
        severity: Set(String::from("critical")),
        message: Set(Some(String::from("a power supply lost input"))),
        event_timestamp: Set(event_timestamp),
        observed_at: Set(now),
        dedup_key: Set(dedup_key.clone()),
        site_id: Set(None),
    }
    .insert(database)
    .await?;
    let stored = event::Entity::find_by_id(event_id)
        .one(database)
        .await?
        .ok_or("inserted event is missing")?;
    assert_eq!(stored.endpoint_id, endpoint_id);
    assert_eq!(stored.message_id, "Alert.1.0.PowerSupplyFailure");
    assert_eq!(stored.severity, "critical");
    assert_eq!(stored.message.as_deref(), Some("a power supply lost input"));
    assert_eq!(stored.event_timestamp, event_timestamp);
    assert_eq!(stored.observed_at, now);
    assert_eq!(stored.dedup_key, dedup_key);

    // Every §14.4 severity code is accepted by the CHECK constraint, so a
    // stored row always maps to a domain `EventSeverity`.
    for severity in EVENT_SEVERITIES {
        event::ActiveModel {
            id: Set(Uuid::now_v7()),
            endpoint_id: Set(endpoint_id),
            message_id: Set(String::from("ResourceEvent.1.0.LanResetType")),
            severity: Set(String::from(severity)),
            message: Set(None),
            event_timestamp: Set(event_timestamp),
            observed_at: Set(now),
            dedup_key: Set(format!("ResourceEvent.1.0.LanResetType\u{1F}{severity}")),
            site_id: Set(None),
        }
        .insert(database)
        .await?;
    }

    // A severity no product build can classify must be rejected at the
    // database, so rehydration never has to guess an event severity.
    let invalid_severity = event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("Alert.1.0.PowerSupplyFailure")),
        severity: Set(String::from("informational")),
        message: Set(None),
        event_timestamp: Set(event_timestamp),
        observed_at: Set(now),
        dedup_key: Set(String::from(
            "Alert.1.0.PowerSupplyFailure\u{1F}informational",
        )),
        site_id: Set(None),
    }
    .insert(database)
    .await;
    assert!(invalid_severity.is_err());

    // §14.4 去除明显重复: the same endpoint with the same dedup key keeps
    // only the first row — the second insert must be refused by the unique
    // index. A different endpoint or a different key is a different event.
    let duplicate = event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("Alert.1.0.PowerSupplyFailure")),
        severity: Set(String::from("critical")),
        message: Set(Some(String::from("a power supply lost input"))),
        event_timestamp: Set(event_timestamp),
        observed_at: Set(now),
        dedup_key: Set(dedup_key.clone()),
        site_id: Set(None),
    }
    .insert(database)
    .await;
    assert!(
        duplicate.is_err(),
        "the same (endpoint_id, dedup_key) must be refused as a duplicate"
    );

    let other_endpoint = event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(Uuid::now_v7()),
        message_id: Set(String::from("Alert.1.0.PowerSupplyFailure")),
        severity: Set(String::from("critical")),
        message: Set(None),
        event_timestamp: Set(event_timestamp),
        observed_at: Set(now),
        dedup_key: Set(dedup_key.clone()),
        site_id: Set(None),
    }
    .insert(database)
    .await;
    assert!(
        other_endpoint.is_ok(),
        "a different endpoint is a new event"
    );

    let other_key = event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("ResourceEvent.1.0.LanResetType")),
        severity: Set(String::from("warning")),
        message: Set(None),
        event_timestamp: Set(event_timestamp),
        observed_at: Set(now),
        dedup_key: Set(String::from(
            "ResourceEvent.1.0.LanResetType\u{1F}1773973891234567890",
        )),
        site_id: Set(None),
    }
    .insert(database)
    .await;
    assert!(other_key.is_ok(), "a different dedup key is a new event");

    Ok(())
}

async fn assert_event_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in EVENT_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
