#![forbid(unsafe_code)]
//! # Bare-SQL boundary (§7.3)
//!
//! The migration crate is the only production code that may run raw SQL,
//! and only for the `SQLite` DDL the `SeaQuery` builders cannot express (the
//! DDL-only exception, §7.3 of the design document): `execute_unprepared`
//! statements must start with `CREATE`, `ALTER`, `DROP`, or `PRAGMA`, and
//! DML is forbidden — the rebuild data copies (`INSERT ... SELECT`) go
//! through the query builder (`select_from`). `tests/bare_sql_gate.rs`
//! enforces the boundary mechanically.

use sea_orm_migration::prelude::*;

mod m20260805_000001_initial_storage;
mod m20260805_000002_endpoint_capabilities;
mod m20260805_000003_resource_snapshots;
mod m20260805_000004_audit_events;
mod m20260805_000005_operations;
mod m20260805_000006_remote_tasks;
mod m20260805_000007_artifacts;
mod m20260805_000008_events;
mod m20260805_000009_telemetry;
mod m20260805_000010_groups_tags;
mod m20260805_000011_batch_operations;
mod m20260807_000001_nvidia_families;
mod m20260807_000002_operation_failure_kinds;
mod m20260807_000003_nvidia_families;
mod m20260807_000005_product_users;
mod m20260807_000006_lenovo_families;
mod m20260807_000007_audit_action_shapes;
mod m20260807_000008_audit_execute_operation;
mod m20260807_000009_center_tables;
mod m20260810_000001_center_data_sites;
mod m20260810_000002_center_role_sites;
mod m20260812_000001_resource_decode_failures;
mod m20260812_000002_resource_feature_lists;
mod m20260813_000001_audit_center_actions;
mod m20260813_000002_endpoint_health_checks;
mod m20260813_000003_audit_failure_vocabulary;
mod m20260813_000004_audit_operation_vocabulary;
mod m20260814_000001_center_outbox_operation_ids;
mod m20260814_000002_audit_paging_index;
mod m20260814_000003_center_outbox_operation_lookup;

/// The 000004 down's restore DDL, exposed for the migration test that pins
/// the restored shape byte for byte against the 000003 forward shape
/// (`tests/audit_operation_vocabulary.rs`).
pub use m20260813_000004_audit_operation_vocabulary::AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260805_000001_initial_storage::Migration),
            Box::new(m20260805_000002_endpoint_capabilities::Migration),
            Box::new(m20260805_000003_resource_snapshots::Migration),
            Box::new(m20260805_000004_audit_events::Migration),
            Box::new(m20260805_000005_operations::Migration),
            Box::new(m20260805_000006_remote_tasks::Migration),
            Box::new(m20260805_000007_artifacts::Migration),
            Box::new(m20260805_000008_events::Migration),
            Box::new(m20260805_000009_telemetry::Migration),
            Box::new(m20260805_000010_groups_tags::Migration),
            Box::new(m20260805_000011_batch_operations::Migration),
            Box::new(m20260807_000001_nvidia_families::Migration),
            Box::new(m20260807_000002_operation_failure_kinds::Migration),
            Box::new(m20260807_000003_nvidia_families::Migration),
            Box::new(m20260807_000005_product_users::Migration),
            Box::new(m20260807_000006_lenovo_families::Migration),
            Box::new(m20260807_000007_audit_action_shapes::Migration),
            Box::new(m20260807_000008_audit_execute_operation::Migration),
            Box::new(m20260807_000009_center_tables::Migration),
            Box::new(m20260810_000001_center_data_sites::Migration),
            Box::new(m20260810_000002_center_role_sites::Migration),
            Box::new(m20260812_000001_resource_decode_failures::Migration),
            Box::new(m20260812_000002_resource_feature_lists::Migration),
            Box::new(m20260813_000001_audit_center_actions::Migration),
            Box::new(m20260813_000002_endpoint_health_checks::Migration),
            Box::new(m20260813_000003_audit_failure_vocabulary::Migration),
            Box::new(m20260813_000004_audit_operation_vocabulary::Migration),
            Box::new(m20260814_000001_center_outbox_operation_ids::Migration),
            Box::new(m20260814_000002_audit_paging_index::Migration),
            Box::new(m20260814_000003_center_outbox_operation_lookup::Migration),
        ]
    }
}
