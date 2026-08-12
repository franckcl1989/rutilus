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
/// The rebuild helper is split by direction: `rebuild_up` recreates the
/// full 000010 shape (with `site_id` and the scope CHECK), and `rebuild_down`
/// recreates the exact 000005 shape — the four original columns, the role
/// CHECK, and the two principal foreign keys, with no `site_id` column and
/// no scope CHECK — while the data copy and the drop/rename tail are shared.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_up(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_down(manager).await
    }
}

/// The up direction: recreates the table with the full 000010 shape — the
/// nullable `site_id` column naming `instances(id)` and the
/// scope-vocabulary CHECK, on top of the 000005 shape — then copies every
/// row and swaps the rebuild into place.
async fn rebuild_up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
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
    copy_shared_columns(manager).await?;
    finish_rebuild(manager).await
}

/// The down direction: recreates the table with the exact 000005 shape —
/// the four original columns, the role CHECK, and the two principal
/// foreign keys, with no `site_id` column and no scope CHECK. The copy
/// names only the four shared columns, so the scope is discarded as the
/// migration rolls back.
async fn rebuild_down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    connection
        .execute_unprepared(
            "CREATE TABLE role_assignments_rebuild (\
             principal_id UUID NOT NULL PRIMARY KEY,\
             role TEXT NOT NULL,\
             assigned_by UUID,\
             assigned_at TEXT NOT NULL,\
             CONSTRAINT ck_role_assignments_role \
               CHECK (role IN ('administrator', 'operator', 'viewer')),\
             CONSTRAINT fk_role_assignments_principal \
               FOREIGN KEY (principal_id) REFERENCES principals(id) \
               ON UPDATE CASCADE ON DELETE CASCADE,\
             CONSTRAINT fk_role_assignments_assigner \
               FOREIGN KEY (assigned_by) REFERENCES principals(id) \
               ON UPDATE CASCADE ON DELETE SET NULL)",
        )
        .await?;
    copy_shared_columns(manager).await?;
    finish_rebuild(manager).await
}

/// The data copy into the rebuild table, shared by both directions: it
/// names exactly the four columns both shapes carry, so the up direction
/// maps the 000005-shaped source one-to-one and the down direction
/// discards `site_id` (the migration rolls the scope back). The copy goes
/// through the `SeaQuery` builder (`INSERT ... SELECT` via `select_from`),
/// so the rebuild's raw-SQL surface stays DDL-only — the §7.3 bare-SQL gate
/// in `tests/bare_sql_gate.rs` enforces that.
async fn copy_shared_columns(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .get_connection()
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
        .await
        .map(|_| ())
}

/// The standard rebuild tail, shared by both directions: drop the old table
/// and rename the rebuilt one into place.
async fn finish_rebuild(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let connection = manager.get_connection();
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
