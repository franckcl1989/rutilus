use sea_orm::entity::prelude::*;

/// One envelope queued for delivery to the center (design §17, D4).
///
/// `sequence` is the envelope's per-instance sequence number (the §15.2
/// `Envelope.sequence`); the unique `(instance_id, sequence)` index pins the
/// per-instance monotonicity. `payload_json` holds the at-rest protection of
/// the serde JSON serialization of a `center-protocol` `Envelope`: the §9.4
/// `TypedPayloadJson` rule (the plaintext can only ever come from a type
/// successfully serialized, never arbitrary hand-written JSON, and the
/// database does not parse the structure), persisted by the repository as a
/// `RUTC1:` ciphertext envelope under the instance master key — or as the
/// legacy plaintext JSON of rows written before at-rest encryption. `state`
/// is the stable `OutboxEntryState` code (`pending` or `acked`); the
/// migration CHECKs the allow-list and pins the ack pairing (`acked` rows
/// carry `acked_at`).
///
/// `operation_id` is the plaintext §15.6 operation id of an offer row
/// (R6-E-04) — `NULL` for the content rows of the site-side queue. The id is
/// not a secret (it rides in the clear inside the envelope payload and on
/// the wire), and the repository writes it from the same payload it stores,
/// so the column always agrees with the decrypted envelope; the column lets
/// the dispatch retry's fall-through reads, the V5E-1 reply-site fallback,
/// and the ack-time pruning address one operation's rows without decrypting
/// the whole queue.
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
    pub operation_id: Option<Uuid>,
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
