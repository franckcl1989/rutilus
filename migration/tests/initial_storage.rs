use std::error::Error;

use rutilus_entity::{
    credential, credential_version, endpoint, endpoint_address, endpoint_capability,
    endpoint_credential,
    endpoint_trust::{self, TrustMode},
};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, IntoActiveModel,
    Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const STORAGE_TABLES: [&str; 7] = [
    "credentials",
    "credential_versions",
    "endpoints",
    "endpoint_addresses",
    "endpoint_capabilities",
    "endpoint_trust",
    "endpoint_credentials",
];

#[tokio::test]
async fn migrations_preserve_storage_invariants() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_storage_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    let credential_id = verify_credential_constraints(&database, now).await?;
    verify_endpoint_constraints(&database, now, credential_id).await?;

    Migrator::down(&database, None).await?;
    assert_storage_tables(&database, false).await?;

    Ok(())
}

async fn assert_storage_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in STORAGE_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}

async fn verify_credential_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let credential_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    credential::ActiveModel {
        id: Set(credential_id),
        name: Set(String::from("lab-admin")),
        username: Set(String::from("administrator")),
        active_version_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    credential_version::ActiveModel {
        id: Set(version_id),
        credential_id: Set(credential_id),
        encrypted_secret: Set(vec![1; 32]),
        nonce: Set(vec![2; 24]),
        created_at: Set(now),
    }
    .insert(database)
    .await?;

    let mut stored_credential = credential::Entity::find_by_id(credential_id)
        .one(database)
        .await?
        .ok_or("inserted credential is missing")?
        .into_active_model();
    stored_credential.active_version_id = Set(Some(version_id));
    stored_credential.update(database).await?;

    let other_credential_id = Uuid::now_v7();
    let other_version_id = Uuid::now_v7();
    credential::ActiveModel {
        id: Set(other_credential_id),
        name: Set(String::from("lab-operator")),
        username: Set(String::from("operator")),
        active_version_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    credential_version::ActiveModel {
        id: Set(other_version_id),
        credential_id: Set(other_credential_id),
        encrypted_secret: Set(vec![5; 32]),
        nonce: Set(vec![6; 24]),
        created_at: Set(now),
    }
    .insert(database)
    .await?;

    let mut mismatched_credential = credential::Entity::find_by_id(credential_id)
        .one(database)
        .await?
        .ok_or("inserted credential is missing")?
        .into_active_model();
    mismatched_credential.active_version_id = Set(Some(other_version_id));
    assert!(mismatched_credential.update(database).await.is_err());

    Ok(credential_id)
}

async fn verify_endpoint_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
    credential_id: Uuid,
) -> Result<(), Box<dyn Error>> {
    let endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(endpoint_id),
        display_name: Set(String::from("Rack A BMC")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    endpoint_address::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        address: Set(String::from("https://192.0.2.10")),
        is_active: Set(true),
        created_at: Set(now),
        retired_at: Set(None),
    }
    .insert(database)
    .await?;

    let duplicate_active_address = endpoint_address::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        address: Set(String::from("https://192.0.2.11")),
        is_active: Set(true),
        created_at: Set(now),
        retired_at: Set(None),
    }
    .insert(database)
    .await;
    assert!(duplicate_active_address.is_err());

    endpoint_trust::ActiveModel {
        endpoint_id: Set(endpoint_id),
        trust_mode: Set(TrustMode::PinnedCertificate),
        certificate_sha256: Set(Some(vec![3; 32])),
        certificate_der: Set(Some(vec![4; 128])),
        trusted_at: Set(now),
    }
    .insert(database)
    .await?;
    endpoint_credential::ActiveModel {
        endpoint_id: Set(endpoint_id),
        credential_id: Set(credential_id),
        assigned_at: Set(now),
    }
    .insert(database)
    .await?;

    verify_endpoint_capability_constraints(database, endpoint_id, now).await?;

    let unknown_endpoint_binding = endpoint_credential::ActiveModel {
        endpoint_id: Set(Uuid::now_v7()),
        credential_id: Set(credential_id),
        assigned_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(unknown_endpoint_binding.is_err());

    Ok(())
}

async fn verify_endpoint_capability_constraints(
    database: &DatabaseConnection,
    endpoint_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    for (capability, state) in [
        ("session-service", "supported"),
        ("systems", "read-only"),
        ("chassis", "unauthorized"),
        ("managers", "temporarily-unavailable"),
        ("event-service", "schema-incompatible"),
        ("update-service", "not-advertised"),
        ("telemetry-service", "not-compiled"),
    ] {
        endpoint_capability::ActiveModel {
            endpoint_id: Set(endpoint_id),
            capability: Set(String::from(capability)),
            state: Set(String::from(state)),
            observed_at: Set(now),
        }
        .insert(database)
        .await?;
    }

    let duplicate_capability = endpoint_capability::ActiveModel {
        endpoint_id: Set(endpoint_id),
        capability: Set(String::from("systems")),
        state: Set(String::from("supported")),
        observed_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(duplicate_capability.is_err());

    let invalid_capability_state = endpoint_capability::ActiveModel {
        endpoint_id: Set(endpoint_id),
        capability: Set(String::from("chassis")),
        state: Set(String::from("unknown")),
        observed_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_capability_state.is_err());

    let unknown_endpoint_capability = endpoint_capability::ActiveModel {
        endpoint_id: Set(Uuid::now_v7()),
        capability: Set(String::from("managers")),
        state: Set(String::from("not-advertised")),
        observed_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(unknown_endpoint_capability.is_err());

    Ok(())
}
