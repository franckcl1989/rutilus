use sea_orm::entity::prelude::*;

/// One persisted telemetry series (design §9.3 事件和遥测, §14.4 Telemetry).
///
/// A series is one metric value of one `MetricReport` of one endpoint (see
/// the domain `TelemetrySeries` doc for the identity design): `endpoint_id`
/// names the endpoint and `series_key` is the report identity plus the
/// metric id, so the same metric id in two different reports is two series.
/// The unique index on `(endpoint_id, series_key)` is the persistence
/// find-or-create key, enforced in the database so a racing duplicate is
/// refused, never double-inserted.
///
/// `endpoint_id` deliberately has no foreign key, mirroring `events` and the
/// audit records: a series row must outlive its endpoint, because the
/// retained sample history is the product's own record and is bounded by the
/// retention policy, not by endpoint lifecycle — deleting an endpoint must
/// never silently cascade the trend history away.
///
/// `sample_count` is the number of currently retained samples — the bounded
/// history (§14.4) the persistence maintains: `append_sample` increments it
/// and `prune_before` recomputes it. The migration's CHECK constraint
/// refuses a negative count, and rehydration re-validates the stored value,
/// so the metadata never silently disagrees with the `telemetry_samples`
/// rows.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "telemetry_series")]
pub struct Model {
    /// The stable identity of this series.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The endpoint whose `MetricReport` this series samples; no foreign key
    /// (see the model-level doc).
    pub endpoint_id: Uuid,
    /// The series identity: report identity + metric id (domain `SeriesKey`).
    pub series_key: String,
    /// The number of currently retained samples.
    pub sample_count: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::telemetry_sample::Entity")]
    TelemetrySample,
}

impl Related<super::telemetry_sample::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TelemetrySample.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
