use sea_orm::entity::prelude::*;

/// One envelope received from the center (design §17, D4).
///
/// `operation_id` is the idempotency key of the §17.5 rule: the unique index
/// refuses a second row for the same operation id, so the repository's
/// duplicate decision is atomic. `payload_json` holds the at-rest protection
/// of the serde JSON serialization of a `center-protocol` `Envelope` — the
/// §9.4 `TypedPayloadJson` rule, exactly like `center_outbox.payload_json`:
/// the repository persists a `RUTC1:` ciphertext envelope under the instance
/// master key (bound to the operation id), or reads the legacy plaintext
/// JSON of rows written before at-rest encryption. `state` is the stable
/// `InboxEntryState` code (`received`, `accepted`, `rejected`, or
/// `completed`); the migration CHECKs the allow-list, and `expires_at`
/// bounds how long the offered operation stays actionable.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "center_inbox")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub operation_id: String,
    pub instance_id: Uuid,
    pub payload_json: String,
    pub state: String,
    pub expires_at: TimeDateTimeWithTimeZone,
    pub received_at: TimeDateTimeWithTimeZone,
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
