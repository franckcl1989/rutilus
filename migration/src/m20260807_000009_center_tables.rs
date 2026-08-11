use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// The 0.7.0 center-shape storage (design §17, D2/D4/D6).
///
/// # The five tables
///
/// - `instances` — one registered deployment identity (D6). On the center
///   side a row names one registered site; on the site side the row names
///   the site's own identity — a single-center binding means exactly one
///   row. The `instance_kind` CHECK pins the `site`/`center` vocabulary.
/// - `center_bindings` — one site-to-center binding record (D2, D6). A
///   pending binding carries only the SHA-256 hash of the one-time binding
///   code and its short expiry (never the code itself); binding the site
///   clears both and records the bind time and the site certificate
///   fingerprint. The state CHECK pins the `pending`/`bound`/`revoked`
///   vocabulary, and the shape CHECK pins the column contract of each state
///   (a pending row carries the code hash and expiry, a bound row carries
///   the bind time, a revoked row carries neither) so a row can never
///   silently mean something else. The single-center-binding rule is a
///   partial unique index over `(site_instance_id) WHERE state IN
///   ('pending', 'bound')`: at most one active binding per site, while a
///   revoked binding no longer counts so the site can re-register.
/// - `center_outbox` — envelopes queued for delivery to the center (D4).
///   The unique `(instance_id, sequence)` index pins the per-instance
///   monotonic sequence; `payload_json` holds the §9.4 `TypedPayloadJson`
///   serialization of a `center-protocol` `Envelope` as opaque text,
///   deliberately without a JSON CHECK exactly like
///   `operations.command`; the state and ack-pairing CHECKs pin the
///   `pending`/`acked` lifecycle and its `acked_at` contract.
/// - `center_inbox` — envelopes received from the center (D4). The unique
///   `operation_id` index is the atomic §17.5 idempotency refusal behind the
///   repository's duplicate decision; the state CHECK pins the
///   `received`/`accepted`/`rejected`/`completed` lifecycle, and
///   `expires_at` bounds how long the offered operation stays actionable.
/// - `sync_cursors` — one per-instance sync-stream cursor (§17). The unique
///   `(instance_id, stream)` index makes the upsert atomic; the stream CHECK
///   pins the four sync streams (`endpoint`, `health`, `event`, `artifact`).
///
/// Every foreign key names `instances.id` and cascades with the instance, so
/// deleting a registered site removes its bindings, queues, and cursors.
///
/// The whole up (and the symmetric down) commits atomically on `SQLite`: the
/// five tables and their indexes must land as one unit or not at all.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_instances(manager).await?;
        create_center_bindings(manager).await?;
        create_center_outbox(manager).await?;
        create_center_inbox(manager).await?;
        create_sync_cursors(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse creation order: every dependent table first, because the
        // foreign keys name the instances table, which must exist until
        // every dependent table is gone.
        manager
            .drop_table(Table::drop().table(SyncCursor::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CenterInbox::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CenterOutbox::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(CenterBinding::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Instance::Table).to_owned())
            .await
    }
}

async fn create_instances(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Instance::Table)
                .col(ColumnDef::new(Instance::Id).uuid().not_null().primary_key())
                .col(
                    ColumnDef::new(Instance::DisplayName)
                        .string_len(128)
                        .not_null(),
                )
                .col(ColumnDef::new(Instance::Kind).string().not_null())
                .col(
                    ColumnDef::new(Instance::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_instances_kind",
                    Expr::col(Instance::Kind).is_in(["site", "center"]),
                ))
                .to_owned(),
        )
        .await
}

async fn create_center_bindings(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CenterBinding::Table)
                .col(
                    ColumnDef::new(CenterBinding::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CenterBinding::CenterUrl)
                        .string_len(512)
                        .not_null(),
                )
                .col(ColumnDef::new(CenterBinding::BindingCodeHash).binary())
                .col(
                    ColumnDef::new(CenterBinding::SiteInstanceId)
                        .uuid()
                        .not_null(),
                )
                .col(ColumnDef::new(CenterBinding::SiteCertFingerprint).string_len(512))
                .col(ColumnDef::new(CenterBinding::State).string().not_null())
                .col(ColumnDef::new(CenterBinding::BoundAt).timestamp_with_time_zone())
                .col(ColumnDef::new(CenterBinding::ExpiresAt).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(CenterBinding::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_center_bindings_state",
                    Expr::col(CenterBinding::State).is_in(["pending", "bound", "revoked"]),
                ))
                // The column contract of each state, mirroring the domain
                // `CenterBinding` shape: only a pending binding carries the
                // code hash and its expiry, only a bound binding carries the
                // bind time, and a revoked binding carries neither.
                .check((
                    "ck_center_bindings_shape",
                    Expr::col(CenterBinding::State)
                        .eq("pending")
                        .and(Expr::col(CenterBinding::BindingCodeHash).is_not_null())
                        .and(Expr::col(CenterBinding::ExpiresAt).is_not_null())
                        .and(Expr::col(CenterBinding::BoundAt).is_null())
                        .or(Expr::col(CenterBinding::State)
                            .eq("bound")
                            .and(Expr::col(CenterBinding::BindingCodeHash).is_null())
                            .and(Expr::col(CenterBinding::ExpiresAt).is_null())
                            .and(Expr::col(CenterBinding::BoundAt).is_not_null()))
                        .or(Expr::col(CenterBinding::State)
                            .eq("revoked")
                            .and(Expr::col(CenterBinding::BindingCodeHash).is_null())
                            .and(Expr::col(CenterBinding::ExpiresAt).is_null())),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_center_bindings_instance")
                        .from(CenterBinding::Table, CenterBinding::SiteInstanceId)
                        .to(Instance::Table, Instance::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // The single-center-binding rule (D6): at most one active (pending or
    // bound) binding per site. `SQLite` cannot express a partial unique
    // index through the SeaQuery index builder, so the WHERE clause is raw
    // DDL like the CHECK-widening `ALTER`s of the rebuild migrations (the
    // §7.3 DDL-only exception).
    manager
        .get_connection()
        .execute_unprepared(
            "CREATE UNIQUE INDEX uq_center_bindings_active_site \
             ON center_bindings (site_instance_id) WHERE state IN ('pending', 'bound')",
        )
        .await?;
    // The presented-code lookup: the center matches a presented code hash to
    // its pending registration.
    manager
        .create_index(
            Index::create()
                .name("ix_center_bindings_code_hash")
                .table(CenterBinding::Table)
                .col(CenterBinding::BindingCodeHash)
                .to_owned(),
        )
        .await
}

async fn create_center_outbox(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CenterOutbox::Table)
                .col(
                    ColumnDef::new(CenterOutbox::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CenterOutbox::Sequence)
                        .big_integer()
                        .not_null(),
                )
                .col(ColumnDef::new(CenterOutbox::InstanceId).uuid().not_null())
                .col(ColumnDef::new(CenterOutbox::PayloadJson).text().not_null())
                .col(ColumnDef::new(CenterOutbox::State).string().not_null())
                .col(
                    ColumnDef::new(CenterOutbox::RetryCount)
                        .integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CenterOutbox::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(CenterOutbox::AckedAt).timestamp_with_time_zone())
                .check((
                    "ck_center_outbox_state",
                    Expr::col(CenterOutbox::State).is_in(["pending", "acked"]),
                ))
                .check((
                    "ck_center_outbox_retry_count",
                    Expr::col(CenterOutbox::RetryCount).gte(0),
                ))
                .check((
                    "ck_center_outbox_ack_pairing",
                    Expr::col(CenterOutbox::State)
                        .eq("pending")
                        .and(Expr::col(CenterOutbox::AckedAt).is_null())
                        .or(Expr::col(CenterOutbox::State)
                            .eq("acked")
                            .and(Expr::col(CenterOutbox::AckedAt).is_not_null())),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_center_outbox_instance")
                        .from(CenterOutbox::Table, CenterOutbox::InstanceId)
                        .to(Instance::Table, Instance::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // The per-instance sequence is monotonic: one envelope per sequence
    // number, and the unique index makes a duplicate sequence an atomic
    // refusal instead of a check-then-insert race.
    manager
        .create_index(
            Index::create()
                .name("uq_center_outbox_instance_sequence")
                .table(CenterOutbox::Table)
                .col(CenterOutbox::InstanceId)
                .col(CenterOutbox::Sequence)
                .unique()
                .to_owned(),
        )
        .await?;
    // The delivery scan: pending envelopes of one instance in sequence order.
    manager
        .create_index(
            Index::create()
                .name("ix_center_outbox_instance_state")
                .table(CenterOutbox::Table)
                .col(CenterOutbox::InstanceId)
                .col(CenterOutbox::State)
                .to_owned(),
        )
        .await
}

async fn create_center_inbox(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CenterInbox::Table)
                .col(
                    ColumnDef::new(CenterInbox::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(CenterInbox::OperationId)
                        .string_len(36)
                        .not_null(),
                )
                .col(ColumnDef::new(CenterInbox::InstanceId).uuid().not_null())
                .col(ColumnDef::new(CenterInbox::PayloadJson).text().not_null())
                .col(ColumnDef::new(CenterInbox::State).string().not_null())
                .col(
                    ColumnDef::new(CenterInbox::ExpiresAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(CenterInbox::ReceivedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_center_inbox_state",
                    Expr::col(CenterInbox::State).is_in([
                        "received",
                        "accepted",
                        "rejected",
                        "completed",
                    ]),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_center_inbox_instance")
                        .from(CenterInbox::Table, CenterInbox::InstanceId)
                        .to(Instance::Table, Instance::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // The §17.5 idempotency key: the same operation id can never land twice,
    // and the unique index is the atomic duplicate refusal behind the
    // repository's duplicate decision.
    manager
        .create_index(
            Index::create()
                .name("uq_center_inbox_operation_id")
                .table(CenterInbox::Table)
                .col(CenterInbox::OperationId)
                .unique()
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("ix_center_inbox_instance")
                .table(CenterInbox::Table)
                .col(CenterInbox::InstanceId)
                .to_owned(),
        )
        .await
}

async fn create_sync_cursors(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(SyncCursor::Table)
                .col(
                    ColumnDef::new(SyncCursor::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(SyncCursor::InstanceId).uuid().not_null())
                .col(ColumnDef::new(SyncCursor::Stream).string().not_null())
                .col(ColumnDef::new(SyncCursor::CursorValue).text().not_null())
                .col(
                    ColumnDef::new(SyncCursor::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_sync_cursors_stream",
                    Expr::col(SyncCursor::Stream)
                        .is_in(["endpoint", "health", "event", "artifact"]),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_sync_cursors_instance")
                        .from(SyncCursor::Table, SyncCursor::InstanceId)
                        .to(Instance::Table, Instance::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // One cursor per (instance, stream): the unique index makes the upsert
    // atomic.
    manager
        .create_index(
            Index::create()
                .name("uq_sync_cursors_instance_stream")
                .table(SyncCursor::Table)
                .col(SyncCursor::InstanceId)
                .col(SyncCursor::Stream)
                .unique()
                .to_owned(),
        )
        .await
}

#[derive(DeriveIden)]
enum Instance {
    #[sea_orm(iden = "instances")]
    Table,
    Id,
    DisplayName,
    #[sea_orm(iden = "instance_kind")]
    Kind,
    CreatedAt,
}

#[derive(DeriveIden)]
enum CenterBinding {
    #[sea_orm(iden = "center_bindings")]
    Table,
    Id,
    CenterUrl,
    BindingCodeHash,
    SiteInstanceId,
    SiteCertFingerprint,
    State,
    BoundAt,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum CenterOutbox {
    #[sea_orm(iden = "center_outbox")]
    Table,
    Id,
    Sequence,
    InstanceId,
    PayloadJson,
    State,
    RetryCount,
    CreatedAt,
    AckedAt,
}

#[derive(DeriveIden)]
enum CenterInbox {
    #[sea_orm(iden = "center_inbox")]
    Table,
    Id,
    OperationId,
    InstanceId,
    PayloadJson,
    State,
    ExpiresAt,
    ReceivedAt,
}

#[derive(DeriveIden)]
enum SyncCursor {
    #[sea_orm(iden = "sync_cursors")]
    Table,
    Id,
    InstanceId,
    Stream,
    CursorValue,
    UpdatedAt,
}
