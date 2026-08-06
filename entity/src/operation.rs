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
