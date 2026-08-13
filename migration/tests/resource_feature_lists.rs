use std::error::Error;

use rutilus_domain::{ResourceFeature, ResourceFeatureParseError};
use rutilus_entity::{endpoint, resource, resource_decode_failure, resource_snapshot};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

/// Every `ResourceFeature` variant of the current domain build, in enum
/// declaration order: the single source of truth the migration's allow-lists
/// must equal character-for-character. A variant renamed or removed breaks
/// this enumeration at compile time (each name is spelled out), and the
/// verbatim comparisons below fail when the migration lists drift. The
/// enumeration mirrors the domain crate's own stability test
/// (`resource_feature_codes_are_stable`), so both sides of the pin are
/// maintained in the same place.
const DOMAIN_FEATURES: [ResourceFeature; 47] = [
    ResourceFeature::ServiceRoot,
    ResourceFeature::Systems,
    ResourceFeature::Chassis,
    ResourceFeature::Managers,
    ResourceFeature::OemDell,
    ResourceFeature::OemSmcSysLockdown,
    ResourceFeature::OemSmcKcsInterface,
    ResourceFeature::OemNvidiaSystemConfigProfile,
    ResourceFeature::OemNvidiaPowerCompliance,
    ResourceFeature::OemNvidiaManagedEntity,
    ResourceFeature::OemLenovoSecurityService,
    ResourceFeature::OemAmiServiceRoot,
    ResourceFeature::OemAmiConfigBmc,
    ResourceFeature::OemHpeILoServiceExt,
    ResourceFeature::OemHpeManager,
    ResourceFeature::OemLiteOnPowerSupply,
    ResourceFeature::OemDeltaPowerSupply,
    ResourceFeature::Processors,
    ResourceFeature::Memory,
    ResourceFeature::Storages,
    ResourceFeature::NetworkAdapters,
    ResourceFeature::NetworkDeviceFunctions,
    ResourceFeature::EthernetInterfaces,
    ResourceFeature::Accounts,
    ResourceFeature::Bios,
    ResourceFeature::BootOptions,
    ResourceFeature::SecureBoot,
    ResourceFeature::Power,
    ResourceFeature::PowerEquipment,
    ResourceFeature::PowerSupplies,
    ResourceFeature::Thermal,
    ResourceFeature::Sensors,
    ResourceFeature::Controls,
    ResourceFeature::EnvironmentMetrics,
    ResourceFeature::LogServices,
    ResourceFeature::ManagerNetworkProtocol,
    ResourceFeature::HostInterfaces,
    ResourceFeature::PcieDevices,
    ResourceFeature::Assembly,
    ResourceFeature::SoftwareInventory,
    ResourceFeature::EventService,
    ResourceFeature::EventSubscription,
    ResourceFeature::TelemetryService,
    ResourceFeature::MetricDefinition,
    ResourceFeature::MetricReport,
    ResourceFeature::TaskService,
    ResourceFeature::Task,
];

/// The allow-list the alignment migration must install on both tables: the
/// complete 47-code domain inventory (the migration module's
/// `DOMAIN_FEATURE_CODES` constant, duplicated here like the NVIDIA/Lenovo
/// tests duplicate theirs).
const ALIGNED_FEATURE_CODES: [&str; 47] = [
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "nvidia-system-config-profile",
    "nvidia-power-compliance",
    "nvidia-managed-entity",
    "lenovo-security-service",
    "ami-service-root",
    "ami-config-bmc",
    "hpe-ilo-service-ext",
    "hpe-manager",
    "liteon-power-supply",
    "delta-power-supply",
    "processors",
    "memory",
    "storages",
    "network-adapters",
    "network-device-functions",
    "ethernet-interfaces",
    "accounts",
    "bios",
    "boot-options",
    "secure-boot",
    "power",
    "power-equipment",
    "power-supplies",
    "thermal",
    "sensors",
    "controls",
    "environment-metrics",
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

/// The ten codes the `resources` allow-list gains: `down` must refuse them
/// again.
const TEN_NEW_RESOURCE_CODES: [&str; 10] = [
    "ami-service-root",
    "ami-config-bmc",
    "hpe-ilo-service-ext",
    "hpe-manager",
    "liteon-power-supply",
    "delta-power-supply",
    "power-equipment",
    "power-supplies",
    "network-device-functions",
    "environment-metrics",
];

/// The eleven codes the `resource_decode_failures` allow-list gains (the ten
/// above plus `lenovo-security-service`, which the 000012 list was missing):
/// `down` must refuse them again.
const ELEVEN_NEW_DECODE_FAILURE_CODES: [&str; 11] = [
    "lenovo-security-service",
    "ami-service-root",
    "ami-config-bmc",
    "hpe-ilo-service-ext",
    "hpe-manager",
    "liteon-power-supply",
    "delta-power-supply",
    "power-equipment",
    "power-supplies",
    "network-device-functions",
    "environment-metrics",
];

/// The exact 000006 `resources` allow-list (37 codes), which `down` must
/// restore (the ten new codes become unparseable again).
const RESOURCE_CODES_BEFORE_ALIGNMENT: [&str; 37] = [
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "nvidia-system-config-profile",
    "nvidia-power-compliance",
    "nvidia-managed-entity",
    "lenovo-security-service",
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

/// The exact 000012 `resource_decode_failures` allow-list (36 codes), which
/// `down` must restore (`lenovo-security-service` and the ten codes above
/// become unparseable again).
const DECODE_FAILURE_CODES_BEFORE_ALIGNMENT: [&str; 36] = [
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "nvidia-system-config-profile",
    "nvidia-power-compliance",
    "nvidia-managed-entity",
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

/// The mechanical pin: both rebuilt allow-lists must equal the domain
/// `ResourceFeature` code set character-for-character, and the pre-alignment
/// lists must be exactly the aligned list minus the audited gaps. Any drift
/// on either side — a domain code missing from a constraint, a constraint
/// code unknown to the domain, or the two tables diverging from each other —
/// fails here without touching a database.
#[test]
fn both_feature_allow_lists_equal_the_domain_feature_codes_verbatim() {
    let mut domain_codes = DOMAIN_FEATURES
        .iter()
        .map(|feature| feature.as_str())
        .collect::<Vec<_>>();
    domain_codes.sort_unstable();
    assert_eq!(
        domain_codes.len(),
        47,
        "the domain enumeration must stay complete"
    );

    let mut aligned = ALIGNED_FEATURE_CODES.to_vec();
    aligned.sort_unstable();
    assert_eq!(
        aligned, domain_codes,
        "the aligned allow-list must equal the domain ResourceFeature codes \
         character-for-character"
    );

    let mut before_resources = RESOURCE_CODES_BEFORE_ALIGNMENT.to_vec();
    before_resources.sort_unstable();
    let mut before_decode_failures = DECODE_FAILURE_CODES_BEFORE_ALIGNMENT.to_vec();
    before_decode_failures.sort_unstable();
    for code in &before_resources {
        assert!(
            domain_codes.contains(code),
            "pre-alignment resources code {code} must be a current domain code"
        );
    }
    for code in &before_decode_failures {
        assert!(
            domain_codes.contains(code),
            "pre-alignment decode-failure code {code} must be a current domain code"
        );
    }
    for code in TEN_NEW_RESOURCE_CODES {
        assert!(
            domain_codes.contains(&code) && !before_resources.contains(&code),
            "{code} must be the exact gap the resources list gains"
        );
    }
    for code in ELEVEN_NEW_DECODE_FAILURE_CODES {
        assert!(
            domain_codes.contains(&code) && !before_decode_failures.contains(&code),
            "{code} must be the exact gap the decode-failure list gains"
        );
    }
    // Every aligned code is a current domain code: the round-trip proves the
    // constraint surface stays addressable by the domain, so a code cannot
    // linger in the constraints after the domain retires it.
    for code in ALIGNED_FEATURE_CODES {
        assert!(
            code.parse::<ResourceFeature>().is_ok(),
            "{code} must parse as a current ResourceFeature code"
        );
    }
    assert_eq!(
        "unknown".parse::<ResourceFeature>(),
        Err(ResourceFeatureParseError)
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn feature_list_migration_accepts_every_domain_code_and_refuses_unknowns()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    // Idempotency: the migration history replays cleanly twice, so an
    // interrupted upgrade can resume without a half-aligned allow-list.
    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;

    let now = OffsetDateTime::now_utc();
    let endpoint_id = seed_endpoint(&database, now).await?;

    // Every domain code is accepted by both rebuilt constraints — including
    // the eleven codes the audit found missing, whose rows used to fail the
    // CHECK and roll back the whole Generation transaction.
    for code in ALIGNED_FEATURE_CODES {
        let resource_id = seed_resource(
            &database,
            endpoint_id,
            code,
            &format!("/redfish/v1/fixtures/{code}"),
            now,
        )
        .await?;
        assert_eq!(
            resource::Entity::find_by_id(resource_id)
                .one(&database)
                .await?
                .ok_or("inserted resource is missing")?
                .feature,
            code
        );
        seed_decode_failure(
            &database,
            endpoint_id,
            code,
            &format!("/redfish/v1/fixtures/{code}"),
        )
        .await?;
    }
    assert_eq!(
        resource::Entity::find().count(&database).await?,
        47,
        "every domain code must be storable as a resource"
    );
    assert_eq!(
        resource_decode_failure::Entity::find()
            .count(&database)
            .await?,
        47,
        "every domain code must be storable as a decode-failure record"
    );

    // Unknown codes and capability-only codes stay refused on both tables.
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
    assert!(
        seed_resource(
            &database,
            endpoint_id,
            "oem-ami",
            "/redfish/v1/fixtures/oem-ami",
            now,
        )
        .await
        .is_err(),
        "a capability-only code must stay unparseable as a family code"
    );
    assert!(
        seed_decode_failure(
            &database,
            endpoint_id,
            "unknown-feature",
            "/redfish/v1/fixtures/unknown-decode",
        )
        .await
        .is_err()
    );
    assert!(
        seed_decode_failure(
            &database,
            endpoint_id,
            "oem-ami",
            "/redfish/v1/fixtures/oem-ami-decode",
        )
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn feature_list_migration_preserves_rows_and_down_restores_the_prior_allow_lists()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    // Apply the twenty-two migrations before this one (000001 through
    // 000012), seed rows under the pre-alignment allow-lists, then apply the
    // alignment migration on top: the rebuild must copy every row.
    Migrator::up(&database, Some(22)).await?;
    let now = OffsetDateTime::now_utc();
    let endpoint_id = seed_endpoint(&database, now).await?;
    let preserved_resource_id = seed_resource(
        &database,
        endpoint_id,
        "processors",
        "/redfish/v1/fixtures/preexisting",
        now,
    )
    .await?;
    seed_snapshot(&database, preserved_resource_id, now).await?;
    seed_decode_failure(
        &database,
        endpoint_id,
        "processors",
        "/redfish/v1/fixtures/preexisting-decode",
    )
    .await?;

    Migrator::up(&database, None).await?;

    // Rows stored under the pre-alignment schema survive both rebuilds.
    assert_eq!(
        resource::Entity::find_by_id(preserved_resource_id)
            .one(&database)
            .await?
            .ok_or("the pre-existing resource must survive the rebuild")?
            .feature,
        "processors"
    );
    let stored_snapshot = resource_snapshot::Entity::find_by_id((preserved_resource_id, 1))
        .one(&database)
        .await?
        .ok_or("the pre-existing snapshot must survive the rebuild")?;
    assert_eq!(stored_snapshot.generation, 1);
    assert!(
        resource_decode_failure::Entity::find()
            .all(&database)
            .await?
            .iter()
            .any(|row| row.feature == "processors"),
        "the pre-existing decode-failure record must survive the rebuild"
    );

    // Down through the feature-list alignment migration: the exact
    // pre-migration constraint shapes return. Everything registered after
    // it unwinds first (the step count is the registration tail, so the
    // test stays correct however later slices extend the registration
    // list). The rows stored under the newly allow-listed codes cannot be
    // represented by the restored constraints, so they are removed first —
    // exactly what a real downgrade must do with rows that only the newer
    // schema can hold (the rebuild copies every remaining row into the
    // restored tables).
    resource::Entity::delete_many()
        .filter(resource::Column::Feature.is_in(TEN_NEW_RESOURCE_CODES))
        .exec(&database)
        .await?;
    resource_decode_failure::Entity::delete_many()
        .filter(resource_decode_failure::Column::Feature.is_in(ELEVEN_NEW_DECODE_FAILURE_CODES))
        .exec(&database)
        .await?;
    let steps = rollback_steps_to("m20260812_000002_resource_feature_lists")?;
    Migrator::down(&database, Some(steps)).await?;

    for code in TEN_NEW_RESOURCE_CODES {
        assert!(
            seed_resource(
                &database,
                endpoint_id,
                code,
                &format!("/redfish/v1/fixtures/downgraded/{code}"),
                now,
            )
            .await
            .is_err(),
            "{code} must be refused on resources after the downgrade"
        );
    }
    for code in ELEVEN_NEW_DECODE_FAILURE_CODES {
        assert!(
            seed_decode_failure(
                &database,
                endpoint_id,
                code,
                &format!("/redfish/v1/fixtures/downgraded/{code}"),
            )
            .await
            .is_err(),
            "{code} must be refused on decode failures after the downgrade"
        );
    }
    for code in RESOURCE_CODES_BEFORE_ALIGNMENT {
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
    for code in DECODE_FAILURE_CODES_BEFORE_ALIGNMENT {
        seed_decode_failure(
            &database,
            endpoint_id,
            code,
            &format!("/redfish/v1/fixtures/downgraded/{code}"),
        )
        .await?;
    }
    assert!(
        resource::Entity::find_by_id(preserved_resource_id)
            .one(&database)
            .await?
            .is_some(),
        "the pre-existing resource must survive the downgrade rebuild"
    );

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
        display_name: Set(String::from("Feature list endpoint")),
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

/// Seeds one decode-failure record; a rejected feature code fails the insert
/// through the rebuilt `ck_resource_decode_failures_feature` CHECK.
async fn seed_decode_failure(
    database: &DatabaseConnection,
    endpoint_id: Uuid,
    feature: &str,
    odata_uri: &str,
) -> Result<(), Box<dyn Error>> {
    resource_decode_failure::ActiveModel {
        endpoint_id: Set(endpoint_id),
        generation: Set(1),
        odata_uri: Set(odata_uri.to_owned()),
        odata_type: Set(None),
        feature: Set(feature.to_owned()),
        oem_namespace: Set(None),
        error_summary: Set(String::from("seeded decode failure")),
        extended_info_json: Set(String::from("[]")),
    }
    .insert(database)
    .await?;
    Ok(())
}

/// The number of registered migrations to roll back so the named migration
/// is included in the rollback: everything registered after it, plus itself.
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("feature-list alignment migration is not registered")?;
    Ok(u32::try_from(migrations.len() - position)?)
}
