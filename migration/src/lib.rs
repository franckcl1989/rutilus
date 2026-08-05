#![forbid(unsafe_code)]

use sea_orm_migration::prelude::*;

mod m20260805_000001_initial_storage;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260805_000001_initial_storage::Migration)]
    }
}
