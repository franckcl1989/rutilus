use sea_orm::entity::prelude::*;

/// One persisted telemetry reading (design §9.3 事件和遥测, §14.4 Telemetry).
///
/// A sample is one scalar reading the product's sampler took from one metric
/// of one `MetricReport` of one endpoint: `series_id` names the series (see
/// the domain `TelemetrySeries` doc), `observed_at` is the product clock's
/// sampling time, `bmc_timestamp` optionally preserves the BMC's own
/// `MetricValue.Timestamp` beside it (see the domain `TelemetrySample` doc),
/// and `value` is the reading as an `SQLite` `REAL`.
///
/// `value` is `NOT NULL` because `SQLite` stores NaN as NULL, so a non-finite
/// NaN reading is refused by the database; infinities, however, `SQLite`
/// accepts, so the domain constructor is the enforcement point for
/// finiteness and rehydration re-validates the stored value — a row this
/// build cannot rehydrate is reported as corrupt rather than half-read
/// (§7.6 不伪装).
///
/// The foreign key with `ON DELETE CASCADE` ties the history to its series:
/// deleting the series row (the sampler's "stop tracking this metric")
/// removes its samples with it, atomically in the database.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "telemetry_samples")]
pub struct Model {
    /// The monotonically increasing row identity, in insertion order. It is
    /// the deterministic tie-break of the newest-first listing for readings
    /// observed at the same instant.
    #[sea_orm(primary_key)]
    pub id: i64,
    /// The series this reading belongs to; deleted with its series
    /// (`ON DELETE CASCADE`).
    pub series_id: Uuid,
    /// When the product's sampler took this reading — the ordering and
    /// retention key.
    pub observed_at: TimeDateTimeWithTimeZone,
    /// The BMC's own `MetricValue.Timestamp` when the source reported one:
    /// display metadata beside the product clock, never an ordering key
    /// (see the domain `TelemetrySample` doc).
    pub bmc_timestamp: Option<TimeDateTimeWithTimeZone>,
    /// The scalar reading.
    pub value: f64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::telemetry_series::Entity",
        from = "Column::SeriesId",
        to = "super::telemetry_series::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    TelemetrySeries,
}

impl Related<super::telemetry_series::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TelemetrySeries.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
