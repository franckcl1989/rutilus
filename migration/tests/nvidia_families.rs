use std::error::Error;

use rutilus_entity::{endpoint, resource, resource_snapshot};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

/// The 000003 allow-list plus the 0.5.0 NVIDIA system-config-profile code:
/// the follow-up migration must accept every code the original migration
/// accepted and the new family code on top.
const FEATURE_CODES_WITH_NVIDIA: [&str; 34] = [
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "nvidia-system-config-profile",
    "processors",
    "memory",
    "storages",
    "network-adapters",
    "ethernet-interfaces",
    "accounts",
    "bios",
    "boot-options",
    "secure-boot",
    "power",
    "thermal",
    "sensors",
    "controls",
    "log-services",
    "manager-network-protocol",
    "host-interfaces",
    "pcie-devices",
    "assembly",
    "software-inventory",
    "event-service",
    "event-subscription",
    "telemetry-service",
    "metric-definition",
    "metric-report",
    "task-service",
    "task",
];

/// The 000003 allow-list, which `down` must restore exactly (the NVIDIA code
/// becomes unparseable again).
const FEATURE_CODES_BEFORE_NVIDIA: [&str; 33] = [
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "processors",
    "memory",
    "storages",
    "network-adapters",
    "ethernet-interfaces",
    "accounts",
    "bios",
    "boot-options",
    "secure-boot",
    "power",
    "thermal",
    "sensors",
    "controls",
    "log-services",
    "manager-network-protocol",
    "host-interfaces",
    "pcie-devices",
    "assembly",
    "software-inventory",
    "event-service",
    "event-subscription",
    "telemetry-service",
    "metric-definition",
    "metric-report",
    "task-service",
    "task",
];

#[tokio::test]
async fn nvidia_families_migration_extends_the_feature_allow_list() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;

    let now = OffsetDateTime::now_utc();
    let endpoint_id = seed_endpoint(&database, now).await?;

    // A resource and snapshot stored under the 000003 schema survive the
    // rebuild: the rebuild copies every row, so the follow-up migration must
    // not lose observations. The odata path is deliberately distinct from
    // the allow-list loop's fixture paths below, so the seed does not collide
    // with the loop's own "processors" row on the unique
    // (endpoint_id, odata_id) index.
    let preexisting_resource_id = seed_resource(
        &database,
        endpoint_id,
        "processors",
        "/redfish/v1/fixtures/preexisting",
        now,
    )
    .await?;
    seed_snapshot(&database, preexisting_resource_id, now).await?;

    // The follow-up migration accepts every 000003 code plus the new NVIDIA
    // family code, and refuses anything else.
    for code in FEATURE_CODES_WITH_NVIDIA {
        let odata_id = format!("/redfish/v1/fixtures/{code}");
        let resource_id = seed_resource(&database, endpoint_id, code, &odata_id, now).await?;
        assert_eq!(
            resource::Entity::find_by_id(resource_id)
                .one(&database)
                .await?
                .ok_or("inserted resource is missing")?
                .feature,
            code
        );
    }
    assert!(
        seed_resource(
            &database,
            endpoint_id,
            "unknown-feature",
            "/redfish/v1/fixtures/unknown-feature",
            now,
        )
        .await
        .is_err()
    );
    // A capability code stays unparseable as a feature code, exactly like
    // the 000003 constraint refused it.
    assert!(
        seed_resource(
            &database,
            endpoint_id,
            "oem-nvidia-profiles",
            "/redfish/v1/fixtures/oem-nvidia-profiles",
            now,
        )
        .await
        .is_err()
    );

    // The pre-existing snapshot row survives the rebuild, proving the copy
    // step preserved the whole snapshot table.
    let stored_snapshot = resource_snapshot::Entity::find_by_id((preexisting_resource_id, 1))
        .one(&database)
        .await?
        .ok_or("the pre-existing snapshot must survive the rebuild")?;
    assert_eq!(stored_snapshot.generation, 1);

    // `down` restores the 000003 allow-list: the NVIDIA code is refused
    // again and every original code still works. The row stored under the
    // NVIDIA code cannot be represented by the 000003 schema, so it is
    // removed first — exactly what a real downgrade must do with rows that
    // only the newer schema can hold (the rebuild copies every remaining row
    // into the restored tables).
    resource::Entity::delete_many()
        .filter(resource::Column::Feature.eq("nvidia-system-config-profile"))
        .exec(&database)
        .await?;
    // Down only the migrations stacked after the batch-operations slice:
    // `down(None)` would unwind the whole history and drop the `resources`
    // table the assertions below seed into, while this test only needs the
    // original NVIDIA follow-up undone. Everything registered after 000011
    // unwinds first (the family, product-user, audit, center, and
    // feature-list slices plus this batch's additions), so the restore
    // lands on the exact pre-000001 allow-list the test asserts. The step
    // count is the registration tail after the named migration, so the
    // test stays correct however later slices extend the registration
    // list.
    let steps = migrations_after("m20260805_000011_batch_operations")?;
    Migrator::down(&database, Some(steps)).await?;
    assert!(
        seed_resource(
            &database,
            endpoint_id,
            "nvidia-system-config-profile",
            "/redfish/v1/fixtures/nvidia-system-config-profile",
            now,
        )
        .await
        .is_err()
    );
    for code in FEATURE_CODES_BEFORE_NVIDIA {
        // The pre-down rows still exist, so the downgraded seeds use their
        // own odata prefix to stay clear of the unique (endpoint_id,
        // odata_id) pairs.
        let odata_id = format!("/redfish/v1/fixtures/downgraded/{code}");
        let resource_id = seed_resource(&database, endpoint_id, code, &odata_id, now).await?;
        assert_eq!(
            resource::Entity::find_by_id(resource_id)
                .one(&database)
                .await?
                .ok_or("inserted resource is missing")?
                .feature,
            code
        );
    }
    Ok(())
}

/// Seeds one endpoint row and returns its id.
async fn seed_endpoint(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(endpoint_id),
        display_name: Set(String::from("NVIDIA BMC")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(0),
        health: Set(String::from("unknown")),
    }
    .insert(database)
    .await?;
    Ok(endpoint_id)
}

/// Seeds one resource row; a rejected feature code fails the insert through
/// the rebuilt `ck_resources_feature` CHECK. The odata path is an explicit
/// argument so a seed can avoid colliding with another row's
/// `(endpoint_id, odata_id)` unique pair.
async fn seed_resource(
    database: &DatabaseConnection,
    endpoint_id: Uuid,
    feature: &str,
    odata_id: &str,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let resource_id = Uuid::now_v7();
    resource::ActiveModel {
        id: Set(resource_id),
        endpoint_id: Set(endpoint_id),
        odata_id: Set(odata_id.to_owned()),
        feature: Set(feature.to_owned()),
        created_at: Set(now),
    }
    .insert(database)
    .await?;
    Ok(resource_id)
}

/// Seeds one snapshot row under the given resource.
async fn seed_snapshot(
    database: &DatabaseConnection,
    resource_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    resource_snapshot::ActiveModel {
        resource_id: Set(resource_id),
        generation: Set(1),
        odata_type: Set(None),
        etag: Set(None),
        typed_payload_json: Set(String::from(r#"{"Id":"1"}"#)),
        observed_at: Set(now),
    }
    .insert(database)
    .await?;
    Ok(())
}

/// The number of registered migrations after the named migration.
fn migrations_after(name: &str) -> Result<u32, Box<dyn Error>> {
    let position = Migrator::migrations()
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("the named migration is not registered")?;
    Ok(u32::try_from(Migrator::migrations().len() - position - 1)?)
}
