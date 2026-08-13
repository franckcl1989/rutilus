use std::error::Error;

use rutilus_entity::{
    credential, endpoint, endpoint_address, endpoint_capability, endpoint_credential,
    endpoint_trust, instance, resource, resource_decode_failure, resource_snapshot,
};
use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const ENDPOINT_HEALTH_CHECKS_MIGRATION: &str = "m20260813_000002_endpoint_health_checks";

#[tokio::test]
async fn health_checks_accept_the_domain_vocabulary_and_refuse_foreign_values()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let now = OffsetDateTime::now_utc();

    // The domain vocabulary persists: `unknown` before the first completed
    // refresh, `ok` after it, and a non-negative refresh generation.
    for (health, refresh_generation) in [("unknown", 0_i64), ("ok", 1_i64), ("ok", 7_i64)] {
        let inserted = endpoint::ActiveModel {
            id: Set(Uuid::now_v7()),
            display_name: Set(String::from("Rack A PDU")),
            created_at: Set(now),
            updated_at: Set(now),
            site_id: Set(None),
            refresh_generation: Set(refresh_generation),
            health: Set(String::from(health)),
        }
        .insert(&database)
        .await?;
        let stored = endpoint::Entity::find_by_id(inserted.id)
            .one(&database)
            .await?
            .ok_or("inserted endpoint row is missing")?;
        assert_eq!(stored.health, health);
        assert_eq!(stored.refresh_generation, refresh_generation);
    }

    // A health cut the domain cannot produce is refused.
    let foreign_health = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack B PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(0),
        health: Set(String::from("degraded")),
    }
    .insert(&database)
    .await;
    assert!(
        foreign_health.is_err(),
        "a health cut outside the unknown/ok vocabulary must be refused"
    );

    // A negative refresh generation is refused: the domain's `u64`
    // watermark can never project below zero.
    let negative_generation = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack C PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(-1),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await;
    assert!(
        negative_generation.is_err(),
        "a negative refresh generation must be refused"
    );

    Ok(())
}

#[tokio::test]
async fn health_checks_rebuild_preserves_endpoints_and_every_cascade_child()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the health-check rebuild: the endpoint
    // tables still have the pre-check shapes, which the seeded rows prove.
    // The step count is the migration's own registration position, so the
    // test stays correct however later slices extend the registration list.
    let steps = migrations_before(ENDPOINT_HEALTH_CHECKS_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let seeded = seed_endpoint_family(&database).await?;

    // The rebuild preserves the parent and every cascade child — a bare
    // parent drop would silently cascade the child rows away.
    Migrator::up(&database, None).await?;
    assert!(
        endpoint::Entity::find_by_id(seeded.endpoint_id)
            .one(&database)
            .await?
            .is_some(),
        "the endpoint row must survive the rebuild"
    );
    assert!(
        endpoint_address::Entity::find_by_id(seeded.address_id)
            .one(&database)
            .await?
            .is_some(),
        "the endpoint_address row must survive the rebuild"
    );
    assert!(
        endpoint_trust::Entity::find_by_id(seeded.endpoint_id)
            .one(&database)
            .await?
            .is_some(),
        "the endpoint_trust row must survive the rebuild"
    );
    assert!(
        endpoint_credential::Entity::find_by_id(seeded.endpoint_id)
            .one(&database)
            .await?
            .is_some(),
        "the endpoint_credentials row must survive the rebuild"
    );
    assert!(
        endpoint_capability::Entity::find_by_id((seeded.endpoint_id, "power".to_owned()))
            .one(&database)
            .await?
            .is_some(),
        "the endpoint_capabilities row must survive the rebuild"
    );
    assert!(
        resource::Entity::find_by_id(seeded.resource_id)
            .one(&database)
            .await?
            .is_some(),
        "the resources row must survive the rebuild"
    );
    assert!(
        resource_snapshot::Entity::find_by_id((seeded.resource_id, 3_i64))
            .one(&database)
            .await?
            .is_some(),
        "the resource_snapshots row must survive the rebuild"
    );
    assert!(
        resource_decode_failure::Entity::find_by_id((
            seeded.endpoint_id,
            2_i64,
            "/redfish/v1/Systems/1".to_owned()
        ))
        .one(&database)
        .await?
        .is_some(),
        "the resource_decode_failures row must survive the rebuild"
    );

    Ok(())
}

#[tokio::test]
async fn down_restores_the_pre_check_shape_and_preserves_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let now = OffsetDateTime::now_utc();
    let inserted = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack A PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(5),
        health: Set(String::from("ok")),
    }
    .insert(&database)
    .await?;

    // Roll back through the health-check migration only: the endpoints
    // columns are unchanged by the downgrade, so the row written under the
    // checked shape survives.
    Migrator::down(&database, Some(1)).await?;
    let stored = endpoint::Entity::find_by_id(inserted.id)
        .one(&database)
        .await?
        .ok_or("the endpoint row must survive the downgrade")?;
    assert_eq!(stored.health, "ok");
    assert_eq!(stored.refresh_generation, 5);

    // The restored schema refuses nothing anymore: the values the widened
    // CHECK rejected are accepted again (the documented restore contract
    // restores the exact 000012 columns without the two constraints).
    let foreign_health = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack B PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(0),
        health: Set(String::from("degraded")),
    }
    .insert(&database)
    .await;
    assert!(
        foreign_health.is_ok(),
        "the rolled-back schema must not know the health CHECK"
    );
    let negative_generation = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack C PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(-1),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await;
    assert!(
        negative_generation.is_ok(),
        "the rolled-back schema must not know the generation CHECK"
    );

    Ok(())
}

/// The rows one endpoint family needs to prove the rebuild: the parent and
/// one row in every cascade child (addresses, TLS trust, credential
/// binding, capability ledger, resource, snapshot, and decode failure).
// The `_id` postfix mirrors the domain's column names for every row id this
// fixture seeds, so the uniform suffix is deliberate (clippy
// `struct_field_names`).
#[allow(clippy::struct_field_names)]
struct SeededEndpointFamily {
    endpoint_id: Uuid,
    address_id: Uuid,
    resource_id: Uuid,
}

// The seed enumerates every column of the parent and all seven cascade
// children, so the function exceeds the pedantic line budget (same
// exception as the rebuild migrations' copy steps).
#[allow(clippy::too_many_lines)]
async fn seed_endpoint_family(
    database: &DatabaseConnection,
) -> Result<SeededEndpointFamily, Box<dyn Error>> {
    let now = OffsetDateTime::now_utc();
    let site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(site_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(database)
    .await?;
    let endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(endpoint_id),
        display_name: Set(String::from("Rack A PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(site_id)),
        refresh_generation: Set(3),
        health: Set(String::from("ok")),
    }
    .insert(database)
    .await?;
    let credential_id = Uuid::now_v7();
    credential::ActiveModel {
        id: Set(credential_id),
        name: Set(String::from("Rack A credential")),
        username: Set(String::from("svc")),
        active_version_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    let address_id = Uuid::now_v7();
    endpoint_address::ActiveModel {
        id: Set(address_id),
        endpoint_id: Set(endpoint_id),
        address: Set(String::from("https://192.0.2.10")),
        is_active: Set(true),
        created_at: Set(now),
        retired_at: Set(None),
    }
    .insert(database)
    .await?;
    endpoint_trust::ActiveModel {
        endpoint_id: Set(endpoint_id),
        trust_mode: Set(endpoint_trust::TrustMode::PinnedCertificate),
        certificate_sha256: Set(Some(vec![0xAB; 32])),
        certificate_der: Set(Some(vec![0xCD; 16])),
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
    endpoint_capability::ActiveModel {
        endpoint_id: Set(endpoint_id),
        capability: Set(String::from("power")),
        state: Set(String::from("supported")),
        observed_at: Set(now),
    }
    .insert(database)
    .await?;
    let resource_id = Uuid::now_v7();
    resource::ActiveModel {
        id: Set(resource_id),
        endpoint_id: Set(endpoint_id),
        odata_id: Set(String::from("/redfish/v1/Power")),
        feature: Set(String::from("power")),
        created_at: Set(now),
    }
    .insert(database)
    .await?;
    resource_snapshot::ActiveModel {
        resource_id: Set(resource_id),
        generation: Set(3),
        odata_type: Set(Some(String::from("#Power.v1_6_1.Power"))),
        etag: Set(Some(String::from("\"abc\""))),
        typed_payload_json: Set(String::from(r#"{"power": "on"}"#)),
        observed_at: Set(now),
    }
    .insert(database)
    .await?;
    resource_decode_failure::ActiveModel {
        endpoint_id: Set(endpoint_id),
        generation: Set(2),
        odata_uri: Set(String::from("/redfish/v1/Systems/1")),
        odata_type: Set(None),
        feature: Set(String::from("systems")),
        oem_namespace: Set(None),
        error_summary: Set(String::from("unexpected payload shape")),
        extended_info_json: Set(String::from("[]")),
    }
    .insert(database)
    .await?;
    Ok(SeededEndpointFamily {
        endpoint_id,
        address_id,
        resource_id,
    })
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("endpoint health checks migration is not registered")?;
    Ok(u32::try_from(position)?)
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
