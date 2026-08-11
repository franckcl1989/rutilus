use sea_orm::entity::prelude::*;

/// One persisted batch parent (§13.7).
///
/// A batch submission becomes one row here plus one ordinary single-target
/// child row in `operations` per submitted endpoint (the child rows reference
/// this table through `operations.batch_id` and cascade away with it). The
/// parent deliberately stores no target list and no state: the targets are a
/// fact of the child operations and the batch state is derived from their
/// individual states, so nothing here can drift out of sync with the working
/// records. `source` is a stable product code (see the domain `OperationSource`
/// enum); the migration enforces the allowed code set with a CHECK constraint,
/// and `command` is the at-rest-protected serialization of the typed domain
/// `RedfishCommand` — the §9.4 `TypedPayloadJson` rule applied to commands
/// and encrypted exactly like `operations.command`: the `RUTC1:`-prefixed
/// `XChaCha20-Poly1305` ciphertext envelope under the instance master key,
/// bound to the batch id, with legacy plaintext rows readable as before.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "batch_operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub source: String,
    /// The typed write command, protected at rest; see the model-level doc.
    pub command: String,
    /// When the batch was accepted, before any Redfish interaction.
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
