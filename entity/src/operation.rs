use sea_orm::entity::prelude::*;

/// One persisted product Operation (§13.1).
///
/// Every write request becomes a row here before any Redfish call, so the
/// product can resume an interrupted operation after a restart. `source` and
/// `state` are stable product codes (see the domain `OperationSource` and
/// `OperationState` enums); the migration enforces the allowed code sets with
/// CHECK constraints so the recovery scanner never has to parse a code this
/// build cannot classify.
///
/// `command` is the serde JSON serialization of the typed domain
/// `RedfishCommand` — the §9.4 `TypedPayloadJson` rule applied to commands:
/// it can only ever come from a type successfully serialized, never from
/// arbitrary hand-written JSON, and the database does not parse the structure.
/// The repository rehydrates it through the domain type, and a payload no
/// current build can deserialize is refused as a corrupt aggregate instead of
/// half-understood.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub source: String,
    pub state: String,
    /// The typed write command as serde JSON; see the model-level doc.
    pub command: String,
    /// The §13.7 batch parent this operation belongs to, when it is a batch
    /// child. Batch children are ordinary single-target operations — the
    /// executor, scheduler, recovery, and audit paths never need this column
    /// — so it lives only here, at the entity and persistence layer, and the
    /// domain `Operation` aggregate does not carry it. Deleting the batch
    /// cascades the child away (migration 000011).
    pub batch_id: Option<Uuid>,
    /// The §13.7 failure classification of a `failed` operation, when the
    /// product can prove why it failed in product vocabulary. The value is a
    /// stable `FailureKind` code (migration 000012 CHECKs the allow-list); the
    /// repository rehydrates it through the domain type and refuses unknown
    /// codes as a corrupt record, mirroring the state and source codes. It
    /// lives only here — the domain `Operation` aggregate does not carry it —
    /// because reporting is the only reader: batch outcome summaries bucket a
    /// classified failure as `unsupported` instead of `failed`.
    pub failure_kind: Option<String>,
    /// When the operation was accepted, before any Redfish interaction.
    pub created_at: TimeDateTimeWithTimeZone,
    /// When the state last changed; `created_at` until the first transition.
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::operation_target::Entity")]
    Targets,
}

impl Related<super::operation_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Targets.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
