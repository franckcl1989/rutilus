use std::error::Error;

use rutilus_entity::{
    audit_event, credential, credential_version, endpoint, endpoint_address, endpoint_capability,
    endpoint_credential,
    endpoint_trust::{self, TrustMode},
    resource, resource_snapshot,
};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, IntoActiveModel,
    Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const STORAGE_TABLES: [&str; 10] = [
    "audit_events",
    "credentials",
    "credential_versions",
    "endpoints",
    "endpoint_addresses",
    "endpoint_capabilities",
    "endpoint_trust",
    "endpoint_credentials",
    "resources",
    "resource_snapshots",
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
    verify_resource_snapshot_constraints(&database, now).await?;
    verify_audit_event_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_storage_tables(&database, false).await?;

    Ok(())
}

async fn verify_audit_event_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let operation_id = Uuid::now_v7();
    audit_event_model(operation_id, 1, "started", now)
        .insert(database)
        .await?;
    let mut progress = audit_event_model(operation_id, 2, "progress", now);
    progress.progress = Set(Some(String::from("endpoint-created")));
    progress.insert(database).await?;
    let mut succeeded = audit_event_model(operation_id, 3, "succeeded", now);
    succeeded.verification = Set(Some(String::from("confirmed")));
    succeeded.insert(database).await?;

    assert!(
        audit_event_model(operation_id, 1, "started", now)
            .insert(database)
            .await
            .is_err()
    );
    assert!(
        audit_event_model(Uuid::now_v7(), 0, "started", now)
            .insert(database)
            .await
            .is_err()
    );
    assert!(
        audit_event_model(Uuid::now_v7(), 2, "started", now)
            .insert(database)
            .await
            .is_err()
    );

    let mut invalid_actor = audit_event_model(Uuid::now_v7(), 1, "started", now);
    invalid_actor.actor = Set(String::from("unknown"));
    assert!(invalid_actor.insert(database).await.is_err());

    let mut invalid_target = audit_event_model(Uuid::now_v7(), 1, "started", now);
    invalid_target.target_endpoint_address = Set(None);
    assert!(invalid_target.insert(database).await.is_err());

    let mut invalid_parameters = audit_event_model(Uuid::now_v7(), 1, "started", now);
    invalid_parameters.credential_id = Set(None);
    assert!(invalid_parameters.insert(database).await.is_err());

    let mut missing_trust = audit_event_model(Uuid::now_v7(), 1, "started", now);
    missing_trust.trust_mode = Set(None);
    assert!(missing_trust.insert(database).await.is_err());

    let mut invalid_action = audit_event_model(Uuid::now_v7(), 1, "started", now);
    invalid_action.redfish_operation = Set(String::from("none"));
    assert!(invalid_action.insert(database).await.is_err());

    let mut invalid_progress = audit_event_model(Uuid::now_v7(), 2, "progress", now);
    invalid_progress.progress = Set(Some(String::from("row-validated")));
    assert!(invalid_progress.insert(database).await.is_err());
    assert!(
        audit_event_model(Uuid::now_v7(), 2, "progress", now)
            .insert(database)
            .await
            .is_err()
    );

    assert!(
        audit_event_model(Uuid::now_v7(), 2, "succeeded", now)
            .insert(database)
            .await
            .is_err()
    );

    let mut invalid_failure = audit_event_model(Uuid::now_v7(), 2, "failed", now);
    invalid_failure.verification = Set(Some(String::from("inconclusive")));
    assert!(invalid_failure.insert(database).await.is_err());

    let mut missing_row_count = audit_event_model(Uuid::now_v7(), 1, "started", now);
    missing_row_count.target_kind = Set(String::from("product"));
    missing_row_count.target_endpoint_address = Set(None);
    missing_row_count.parameter_kind = Set(String::from("csv-endpoint-import"));
    missing_row_count.credential_id = Set(None);
    missing_row_count.trust_mode = Set(None);
    missing_row_count.permission = Set(String::from("manage-endpoints"));
    missing_row_count.action = Set(String::from("import-endpoints"));
    missing_row_count.redfish_operation = Set(String::from("none"));
    assert!(missing_row_count.insert(database).await.is_err());
    Ok(())
}

fn audit_event_model(
    operation_id: Uuid,
    event_sequence: i64,
    outcome: &str,
    occurred_at: OffsetDateTime,
) -> audit_event::ActiveModel {
    audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(operation_id),
        event_sequence: Set(event_sequence),
        actor: Set(String::from("local-operator")),
        actor_principal_id: Set(None),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("endpoint-address")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(Some(String::from("https://192.0.2.90"))),
        parameter_kind: Set(String::from("endpoint-enrollment")),
        credential_id: Set(Some(Uuid::now_v7())),
        trust_mode: Set(Some(String::from("pinned-certificate"))),
        row_count: Set(None),
        permission: Set(String::from("manage-endpoints")),
        action: Set(String::from("enroll-endpoint")),
        redfish_operation: Set(String::from("probe-core-capabilities")),
        outcome: Set(String::from(outcome)),
        progress: Set(None),
        failure: Set(None),
        verification: Set(None),
        occurred_at: Set(occurred_at),
    }
}

async fn verify_resource_snapshot_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(endpoint_id),
        display_name: Set(String::from("Snapshot BMC")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    let resource_id = Uuid::now_v7();
    resource_model(
        resource_id,
        endpoint_id,
        "/redfish/v1/Systems/1",
        "systems",
        now,
    )
    .insert(database)
    .await?;
    resource_snapshot::ActiveModel {
        resource_id: Set(resource_id),
        generation: Set(1),
        odata_type: Set(Some(String::from("#ComputerSystem.v1_20_0.ComputerSystem"))),
        etag: Set(Some(String::from("\"generation-one\""))),
        typed_payload_json: Set(String::from(r#"{"Id":"1","Name":"System"}"#)),
        observed_at: Set(now),
    }
    .insert(database)
    .await?;
    snapshot_model(resource_id, 2, now).insert(database).await?;
    for (odata_id, feature) in [
        ("/redfish/v1/", "service-root"),
        ("/redfish/v1/Chassis/1", "chassis"),
        ("/redfish/v1/Managers/1", "managers"),
    ] {
        resource_model(Uuid::now_v7(), endpoint_id, odata_id, feature, now)
            .insert(database)
            .await?;
    }

    let duplicate_resource = resource_model(
        Uuid::now_v7(),
        endpoint_id,
        "/redfish/v1/Systems/1",
        "systems",
        now,
    )
    .insert(database)
    .await;
    assert!(duplicate_resource.is_err());

    let invalid_feature = resource_model(
        Uuid::now_v7(),
        endpoint_id,
        "/redfish/v1/Unknown/1",
        "unknown",
        now,
    )
    .insert(database)
    .await;
    assert!(invalid_feature.is_err());

    let unknown_endpoint = resource_model(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "/redfish/v1/Managers/1",
        "managers",
        now,
    )
    .insert(database)
    .await;
    assert!(unknown_endpoint.is_err());

    let duplicate_generation = snapshot_model(resource_id, 1, now).insert(database).await;
    assert!(duplicate_generation.is_err());

    let invalid_generation = snapshot_model(resource_id, 0, now).insert(database).await;
    assert!(invalid_generation.is_err());

    let unknown_resource = snapshot_model(Uuid::now_v7(), 1, now)
        .insert(database)
        .await;
    assert!(unknown_resource.is_err());

    endpoint::Entity::delete_by_id(endpoint_id)
        .exec(database)
        .await?;
    assert!(
        resource::Entity::find_by_id(resource_id)
            .one(database)
            .await?
            .is_none()
    );
    assert!(
        resource_snapshot::Entity::find_by_id((resource_id, 1))
            .one(database)
            .await?
            .is_none()
    );
    Ok(())
}

fn resource_model(
    id: Uuid,
    endpoint_id: Uuid,
    odata_id: &str,
    feature: &str,
    created_at: OffsetDateTime,
) -> resource::ActiveModel {
    resource::ActiveModel {
        id: Set(id),
        endpoint_id: Set(endpoint_id),
        odata_id: Set(String::from(odata_id)),
        feature: Set(String::from(feature)),
        created_at: Set(created_at),
    }
}

fn snapshot_model(
    resource_id: Uuid,
    generation: i64,
    observed_at: OffsetDateTime,
) -> resource_snapshot::ActiveModel {
    resource_snapshot::ActiveModel {
        resource_id: Set(resource_id),
        generation: Set(generation),
        odata_type: Set(None),
        etag: Set(None),
        typed_payload_json: Set(String::from("{}")),
        observed_at: Set(observed_at),
    }
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
