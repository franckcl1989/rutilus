#![forbid(unsafe_code)]

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
            Box::new(m20260807_000007_audit_action_shapes::Migration),
            Box::new(m20260807_000006_lenovo_families::Migration),
            Box::new(m20260807_000008_audit_execute_operation::Migration),
        ]
    }
}
