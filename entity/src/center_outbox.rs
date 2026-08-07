use sea_orm::entity::prelude::*;

/// One envelope queued for delivery to the center (design §17, D4).
///
/// `sequence` is the envelope's per-instance sequence number (the §15.2
/// `Envelope.sequence`); the unique `(instance_id, sequence)` index pins the
/// per-instance monotonicity. `payload_json` holds the serde JSON
/// serialization of a `center-protocol` `Envelope` — the §9.4
/// `TypedPayloadJson` rule: the column can only ever hold JSON produced by a
/// type successfully serialized, never arbitrary hand-written JSON, and the
/// database does not parse the structure. `state` is the stable
/// `OutboxEntryState` code (`pending` or `acked`); the migration CHECKs the
/// allow-list and pins the ack pairing (`acked` rows carry `acked_at`).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "center_outbox")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub sequence: i64,
    pub instance_id: Uuid,
    pub payload_json: String,
    pub state: String,
    pub retry_count: i64,
    pub created_at: TimeDateTimeWithTimeZone,
    pub acked_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::instance::Entity",
        from = "Column::InstanceId",
        to = "super::instance::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Instance,
}

impl Related<super::instance::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Instance.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
