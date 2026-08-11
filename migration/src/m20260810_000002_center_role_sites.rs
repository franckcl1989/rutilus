use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Adds the D3 site scope to the §16.1 role assignments (0.7.0 S5).
///
/// "Center 角色可以限定到某些 Site" (§16.1) — a role assignment can name
/// one site, and the scoped role then applies only to that site. This
/// migration adds the nullable `site_id` column to `role_assignments`,
/// naming `instances(id)` (a deleted site removes its scoped assignments)
/// and pins the scope vocabulary with a CHECK: only the `operator` and
/// `viewer` roles may be site-scoped. The `administrator` role's §16.1
/// duties are global — endpoint and credential management, user and binding
/// management, backup and restore — so an administrator assignment can
/// never silently carry a site scope that the permission judgment would
/// ignore.
///
/// # Why the table is rebuilt
///
/// `SQLite` has no `ALTER TABLE ... DROP CONSTRAINT` and no way to add a
/// CHECK to an existing table, so the new constraint requires the standard
/// table-rebuild procedure (the nvidia-families precedent): the table is
/// recreated with the exact 000005 shape plus the new column and CHECK,
/// every row is copied, and the old table is dropped. Nothing references
/// `role_assignments` (the foreign keys point OUT of it), so the rebuild
/// touches exactly this one table, and the copied rows carry no assignee
/// references into it — the rebuild needs no `PRAGMA foreign_keys` handling.
///
/// The `down` rebuilds back to the exact 000005 shape (no `site_id`, no
/// scope CHECK).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild(manager).await
    }
}

async fn rebuild(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    // The rebuild is symmetric: in both directions the source table's rows
    // are copied into the new shape without `site_id` — the up direction
    // starts from a table that has no such column yet, and the down
    // direction discards the scope (the migration rolls the scope back).
    connection
        .execute_unprepared(
            "CREATE TABLE role_assignments_rebuild (\
             principal_id UUID NOT NULL PRIMARY KEY,\
             role TEXT NOT NULL,\
             assigned_by UUID,\
             assigned_at TEXT NOT NULL,\
             site_id UUID NULL REFERENCES instances(id) ON DELETE CASCADE,\
             CONSTRAINT ck_role_assignments_role \
               CHECK (role IN ('administrator', 'operator', 'viewer')),\
             CONSTRAINT ck_role_assignments_site_scope \
               CHECK (site_id IS NULL OR role IN ('operator', 'viewer')),\
             CONSTRAINT fk_role_assignments_principal \
               FOREIGN KEY (principal_id) REFERENCES principals(id) \
               ON UPDATE CASCADE ON DELETE CASCADE,\
             CONSTRAINT fk_role_assignments_assigner \
               FOREIGN KEY (assigned_by) REFERENCES principals(id) \
               ON UPDATE CASCADE ON DELETE SET NULL)",
        )
        .await?;
    // The copy goes through the SeaQuery builder (`INSERT ... SELECT` via
    // `select_from`), so the rebuild's raw-SQL surface stays DDL-only — the
    // §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
    connection
        .execute(
            &Query::insert()
                .into_table(RoleAssignmentShape::RebuildTable)
                .columns([
                    RoleAssignmentShape::PrincipalId,
                    RoleAssignmentShape::Role,
                    RoleAssignmentShape::AssignedBy,
                    RoleAssignmentShape::AssignedAt,
                ])
                .select_from(
                    Query::select()
                        .column(RoleAssignmentShape::PrincipalId)
                        .column(RoleAssignmentShape::Role)
                        .column(RoleAssignmentShape::AssignedBy)
                        .column(RoleAssignmentShape::AssignedAt)
                        .from(RoleAssignmentShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    connection
        .execute_unprepared("DROP TABLE role_assignments")
        .await?;
    connection
        .execute_unprepared("ALTER TABLE role_assignments_rebuild RENAME TO role_assignments")
        .await
        .map(|_| ())
}

/// The two `role_assignments` shapes the rebuild alternates between; the
/// column variants are shared because both shapes carry the same columns.
#[derive(DeriveIden)]
enum RoleAssignmentShape {
    #[sea_orm(iden = "role_assignments")]
    Table,
    #[sea_orm(iden = "role_assignments_rebuild")]
    RebuildTable,
    PrincipalId,
    Role,
    AssignedBy,
    AssignedAt,
}
