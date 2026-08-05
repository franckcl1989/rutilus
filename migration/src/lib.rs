#![forbid(unsafe_code)]

use sea_orm_migration::prelude::*;

mod m20260805_000001_initial_storage;
mod m20260805_000002_endpoint_capabilities;
mod m20260805_000003_resource_snapshots;
mod m20260805_000004_audit_events;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260805_000001_initial_storage::Migration),
            Box::new(m20260805_000002_endpoint_capabilities::Migration),
            Box::new(m20260805_000003_resource_snapshots::Migration),
            Box::new(m20260805_000004_audit_events::Migration),
        ]
    }
}
