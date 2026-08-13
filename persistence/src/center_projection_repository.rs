//! The center-side projection repository (design §15.5, 0.7.0 S5).
//!
//! The center projects the site reports into the same tables the site
//! uses (§9.3 reuse decision): `endpoints` plus the active address and
//! trust rows, `resources`/`resource_snapshots`, `events`, and `artifacts`,
//! with the `site_id` association column (migration 000010) naming the
//! reporting site on every row.
//!
//! Every write is idempotent — an upsert or an idempotent delete — so the
//! §15.4 at-least-once delivery never doubles a row, and every write is
//! site-scoped: the reporting site's instance id is checked against the
//! stored association, so one site's frames can never overwrite another
//! site's projection. Data conflicts are reported as
//! [`rutilus_application::ProjectionWriteOutcome::Ignored`] — the same
//! pattern as the §14.4 event dedup — so the use case can absorb a
//! conflicting frame without matching on repository error variants; the
//! error variants of [`CenterProjectionRepositoryError`] are boundary
//! failures only.

use rutilus_application::{
    CenterEndpointProjection, CenterTrustMode, EndpointProjectionWrite, ProjectionIgnoreReason,
    ProjectionWriteOutcome, ResourceProjectionWrite,
};
use rutilus_domain::{EndpointId, InstanceId};
use rutilus_entity::{endpoint, endpoint_address, endpoint_trust, resource, resource_snapshot};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    QuerySelect, Set, SqlErr, TransactionTrait,
};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::SqliteStore;

impl SqliteStore {
    /// Upserts the endpoint projection of one §15.5 snapshot: the
    /// `endpoints` row, its active address, and its trust mode.
    ///
    /// The write is site-scoped and idempotent: an existing projection of
    /// another site is refused (the frame is absorbed), a frame whose
    /// refresh generation is older than the stored projection is refused
    /// (an older inventory cut must never roll back the `refresh_generation`
    /// and `health` of a newer one — the same semantics as the per-generation
    /// detail snapshots), and a re-reported snapshot of the same or a newer
    /// generation replaces the summary in place.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError`] for coordination or
    /// database failures; data conflicts are reported as the ignored
    /// outcome.
    // The endpoint upsert spells out the row, address, and trust writes
    // with their site-scope checks, which exceeds the pedantic line budget
    // (the repository tests allow the same lint on their exhaustive
    // assertion tests).
    #[allow(clippy::too_many_lines)]
    pub async fn upsert_endpoint_projection(
        &self,
        projection: &EndpointProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> Result<ProjectionWriteOutcome, CenterProjectionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterProjectionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let endpoint_id = projection.endpoint_id();
        let stored = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        if let Some(stored) = stored.as_ref() {
            if stored.site_id != Some(site.into_uuid()) {
                transaction
                    .rollback()
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
                return Ok(ProjectionWriteOutcome::Ignored {
                    reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite,
                });
            }
            // The refresh-generation guard: the stored generation is the
            // watermark of the newest inventory cut the center applied, and
            // an older frame describes a superseded cut — it must never
            // overwrite the newer `refresh_generation`/`health`, so the
            // whole frame is absorbed. A negative stored generation (a row
            // no current build could have written) is treated as the newest
            // possible watermark, mirroring the list view, so it is never
            // clobbered.
            let stored_generation = u64::try_from(stored.refresh_generation).unwrap_or(u64::MAX);
            if projection.refresh_generation() < stored_generation {
                transaction
                    .rollback()
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
                return Ok(ProjectionWriteOutcome::Ignored {
                    reason: ProjectionIgnoreReason::StaleGeneration,
                });
            }
            let mut active = stored.clone().into_active_model();
            active.display_name = Set(projection.display_name().to_owned());
            active.refresh_generation = Set(stored_integer(projection.refresh_generation())?);
            active.health = Set(projection.health().to_owned());
            active.updated_at = Set(now);
            active
                .update(&transaction)
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
        } else {
            endpoint::ActiveModel {
                id: Set(endpoint_id.into_uuid()),
                display_name: Set(projection.display_name().to_owned()),
                created_at: Set(now),
                updated_at: Set(now),
                site_id: Set(Some(site.into_uuid())),
                refresh_generation: Set(stored_integer(projection.refresh_generation())?),
                health: Set(projection.health().to_owned()),
            }
            .insert(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        }
        // The active address is replaced in place, but only when the
        // reported address changed: a re-reported snapshot with the same
        // address keeps the stored row untouched (no delete + re-insert
        // churn), while a changed address is deleted and re-inserted. The
        // delete removes every address row of the endpoint — the center's
        // projection never creates address history, so the active row is
        // the only one. A unique address conflict (the address is already
        // projected for another endpoint) rolls the whole transaction back
        // — the previous address row survives — and the frame is absorbed.
        let active_address = endpoint_address::Entity::find()
            .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(endpoint_address::Column::IsActive.eq(true))
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        if active_address
            .as_ref()
            .is_none_or(|row| row.address != projection.address())
        {
            endpoint_address::Entity::delete_many()
                .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
                .exec(&transaction)
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            let address_insert = endpoint_address::ActiveModel {
                id: Set(Uuid::now_v7()),
                endpoint_id: Set(endpoint_id.into_uuid()),
                address: Set(projection.address().to_owned()),
                is_active: Set(true),
                created_at: Set(now),
                retired_at: Set(None),
            }
            .insert(&transaction)
            .await;
            if let Err(error) = address_insert {
                if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
                    transaction
                        .rollback()
                        .await
                        .map_err(CenterProjectionRepositoryError::Database)?;
                    return Ok(ProjectionWriteOutcome::Ignored {
                        reason: ProjectionIgnoreReason::AddressAlreadyProjected,
                    });
                }
                return Err(CenterProjectionRepositoryError::Database(error));
            }
        }
        // The trust mode row is replaced in place only when the reported
        // decision changed, mirroring the address skip; the certificate
        // material stays on the site (§15.5 — the center never sees
        // endpoint certificates).
        let trust = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        if trust
            .as_ref()
            .is_none_or(|row| row.trust_mode != stored_trust_mode(projection.trust_mode()))
        {
            endpoint_trust::Entity::delete_many()
                .filter(endpoint_trust::Column::EndpointId.eq(endpoint_id.into_uuid()))
                .exec(&transaction)
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            endpoint_trust::ActiveModel {
                endpoint_id: Set(endpoint_id.into_uuid()),
                trust_mode: Set(stored_trust_mode(projection.trust_mode())),
                certificate_sha256: Set(None),
                certificate_der: Set(None),
                trusted_at: Set(now),
            }
            .insert(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        Ok(ProjectionWriteOutcome::Applied)
    }

    /// Removes the endpoint projection of one site: the row, its addresses,
    /// its trust row, and — by the existing cascade — its resources.
    ///
    /// The delete is idempotent — an endpoint that is already gone leaves
    /// the goal state holding — and site-scoped.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError`] for coordination or
    /// database failures; a cross-site conflict is reported as the ignored
    /// outcome.
    pub async fn delete_endpoint_projection(
        &self,
        endpoint_id: EndpointId,
        site: InstanceId,
    ) -> Result<ProjectionWriteOutcome, CenterProjectionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterProjectionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let stored = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let Some(stored) = stored else {
            // The projection is already gone; the delete is idempotent.
            transaction
                .commit()
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            return Ok(ProjectionWriteOutcome::Applied);
        };
        if stored.site_id != Some(site.into_uuid()) {
            transaction
                .rollback()
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            return Ok(ProjectionWriteOutcome::Ignored {
                reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite,
            });
        }
        endpoint::Entity::delete_by_id(endpoint_id.into_uuid())
            .exec(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        Ok(ProjectionWriteOutcome::Applied)
    }

    /// Upserts the resource projection of one §15.5 delta: the identity row
    /// keyed by `(endpoint_id, odata_id)` and one snapshot row per
    /// generation.
    ///
    /// The write is site-scoped (the endpoint's projection must belong to
    /// the reporting site) and idempotent (a re-delivered delta replaces
    /// the same generation in place), with the same generation guard as the
    /// endpoint projection (an older cut is refused whole).
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError`] for coordination or
    /// database failures; an unknown or cross-site endpoint is reported as
    /// the ignored outcome.
    // The resource upsert spells out the site scope, the identity row, the
    // generation guard, and the snapshot upsert, which exceeds the pedantic
    // line budget (the endpoint projection upsert allows the same lint for
    // the same reason).
    #[allow(clippy::too_many_lines)]
    pub async fn upsert_resource_projection(
        &self,
        projection: &ResourceProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> Result<ProjectionWriteOutcome, CenterProjectionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterProjectionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let endpoint_id = projection.endpoint_id();
        let stored = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let Some(stored) = stored else {
            transaction
                .rollback()
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            return Ok(ProjectionWriteOutcome::Ignored {
                reason: ProjectionIgnoreReason::UnknownEndpoint,
            });
        };
        if stored.site_id != Some(site.into_uuid()) {
            transaction
                .rollback()
                .await
                .map_err(CenterProjectionRepositoryError::Database)?;
            return Ok(ProjectionWriteOutcome::Ignored {
                reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite,
            });
        }
        let resource_id = if let Some(stored) = resource::Entity::find()
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource::Column::OdataId.eq(projection.odata_id()))
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?
        {
            stored.id
        } else {
            let id = Uuid::now_v7();
            resource::ActiveModel {
                id: Set(id),
                endpoint_id: Set(endpoint_id.into_uuid()),
                odata_id: Set(projection.odata_id().to_owned()),
                feature: Set(projection.feature().as_str().to_owned()),
                created_at: Set(now),
            }
            .insert(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
            id
        };
        // The generation guard mirrors the endpoint projection's refresh
        // watermark: the newest stored snapshot generation is the watermark
        // of the newest inventory cut the center applied, and a delta of an
        // older cut must never overwrite it, so the whole frame is absorbed
        // (an older frame describes a superseded cut — the same semantics
        // as the per-generation detail snapshots on the site side). A
        // negative stored generation (a row no current build could have
        // written) is treated as the newest possible watermark, mirroring
        // the endpoint row, so it is never clobbered.
        let stored_generation = resource_snapshot::Entity::find()
            .filter(resource_snapshot::Column::ResourceId.eq(resource_id))
            .select_only()
            .column_as(
                Expr::col(resource_snapshot::Column::Generation).max(),
                "max",
            )
            .into_tuple::<(Option<i64>,)>()
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?
            .and_then(|(maximum,)| maximum);
        if let Some(maximum) = stored_generation {
            let watermark = u64::try_from(maximum).unwrap_or(u64::MAX);
            if projection.generation() < watermark {
                transaction
                    .rollback()
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
                return Ok(ProjectionWriteOutcome::Ignored {
                    reason: ProjectionIgnoreReason::StaleGeneration,
                });
            }
        }
        let generation = stored_integer(projection.generation())?;
        resource_snapshot::Entity::insert(resource_snapshot::ActiveModel {
            resource_id: Set(resource_id),
            generation: Set(generation),
            odata_type: Set(projection.odata_type().map(str::to_owned)),
            etag: Set(projection.etag().map(str::to_owned)),
            typed_payload_json: Set(projection.payload().unwrap_or_default().to_owned()),
            observed_at: Set(projection.observed_at()),
        })
        .on_conflict(
            sea_orm::sea_query::OnConflict::columns([
                resource_snapshot::Column::ResourceId,
                resource_snapshot::Column::Generation,
            ])
            .update_columns([
                resource_snapshot::Column::OdataType,
                resource_snapshot::Column::Etag,
                resource_snapshot::Column::TypedPayloadJson,
                resource_snapshot::Column::ObservedAt,
            ])
            .to_owned(),
        )
        .exec(&transaction)
        .await
        .map_err(CenterProjectionRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        Ok(ProjectionWriteOutcome::Applied)
    }

    /// Removes one resource projection of a site; an endpoint that is
    /// already gone (its resources cascaded away) leaves the goal state
    /// holding.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError`] for coordination or
    /// database failures; a cross-site conflict is reported as the ignored
    /// outcome.
    pub async fn delete_resource_projection(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
        site: InstanceId,
    ) -> Result<ProjectionWriteOutcome, CenterProjectionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterProjectionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let stored = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        match stored {
            None => {
                // The endpoint is gone; its resources cascaded away.
                transaction
                    .commit()
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
            }
            Some(stored) => {
                if stored.site_id != Some(site.into_uuid()) {
                    transaction
                        .rollback()
                        .await
                        .map_err(CenterProjectionRepositoryError::Database)?;
                    return Ok(ProjectionWriteOutcome::Ignored {
                        reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite,
                    });
                }
                resource::Entity::delete_many()
                    .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
                    .filter(resource::Column::OdataId.eq(odata_id))
                    .exec(&transaction)
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
                transaction
                    .commit()
                    .await
                    .map_err(CenterProjectionRepositoryError::Database)?;
            }
        }
        Ok(ProjectionWriteOutcome::Applied)
    }

    /// Reads the endpoint projection row of one endpoint — the dispatch
    /// routing lookup (§15.6).
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when the query
    /// fails.
    pub async fn find_endpoint_projection(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Option<CenterEndpointProjection>, CenterProjectionRepositoryError> {
        let Some(model) = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?
        else {
            return Ok(None);
        };
        Ok(Some(CenterEndpointProjection::new(
            endpoint_id,
            model.site_id.map(InstanceId::from_uuid),
        )))
    }

    /// Reports whether one resource projection exists for an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when the query
    /// fails.
    pub async fn has_resource_projection(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
    ) -> Result<bool, CenterProjectionRepositoryError> {
        Ok(resource::Entity::find()
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource::Column::OdataId.eq(odata_id))
            .one(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?
            .is_some())
    }

    /// Resolves the projection rows of many endpoint ids in one `IN` query —
    /// the §15.5 ownership preload of one event batch.
    ///
    /// The map holds exactly one entry per endpoint id that has a projection
    /// row; ids without a row are absent. An empty id set is answered
    /// without a query.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when the query
    /// fails.
    pub async fn find_endpoint_projections(
        &self,
        endpoint_ids: &[EndpointId],
    ) -> Result<HashMap<EndpointId, CenterEndpointProjection>, CenterProjectionRepositoryError>
    {
        let ids = endpoint_ids
            .iter()
            .map(|endpoint_id| endpoint_id.into_uuid())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let models = endpoint::Entity::find()
            .filter(endpoint::Column::Id.is_in(ids))
            .all(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        Ok(models
            .into_iter()
            .map(|model| {
                (
                    EndpointId::from_uuid(model.id),
                    CenterEndpointProjection::new(
                        EndpointId::from_uuid(model.id),
                        model.site_id.map(InstanceId::from_uuid),
                    ),
                )
            })
            .collect())
    }

    /// Lists the projected endpoints of one site — or of every site when
    /// `site` is `None` — with their active addresses (§15.5 endpoint
    /// view).
    ///
    /// The view is the center's read of the site reports: identity, display
    /// name, active address, health cut, and the refresh-generation
    /// watermark. Rows without a site association (never expected on the
    /// center database) are listed only by the unscoped query.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when a query
    /// fails.
    pub async fn list_projected_endpoints(
        &self,
        site: Option<InstanceId>,
    ) -> Result<Vec<ProjectedEndpointSummary>, CenterProjectionRepositoryError> {
        let mut models = endpoint::Entity::find();
        if let Some(site) = site {
            models = models.filter(endpoint::Column::SiteId.eq(site.into_uuid()));
        }
        let models = models
            .order_by_asc(endpoint::Column::DisplayName)
            .order_by_asc(endpoint::Column::Id)
            .all(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        if models.is_empty() {
            return Ok(Vec::new());
        }
        let endpoint_ids = models.iter().map(|model| model.id).collect::<HashSet<_>>();
        let addresses = endpoint_address::Entity::find()
            .filter(endpoint_address::Column::IsActive.eq(true))
            .filter(endpoint_address::Column::EndpointId.is_in(endpoint_ids))
            .all(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let addresses = addresses
            .into_iter()
            .map(|model| (model.endpoint_id, model.address))
            .collect::<HashMap<_, _>>();
        Ok(models
            .into_iter()
            .map(|model| {
                ProjectedEndpointSummary::new(
                    EndpointId::from_uuid(model.id),
                    model.site_id.map(InstanceId::from_uuid),
                    model.display_name,
                    addresses.get(&model.id).cloned().unwrap_or_default(),
                    model.health,
                    u64::try_from(model.refresh_generation).unwrap_or(u64::MAX),
                )
            })
            .collect())
    }

    /// The projection summary of one site: the projected endpoint count and
    /// the newest projection write time (§15.5 site view — the
    /// last-refresh watermark).
    ///
    /// The summary is one SQL aggregation (`COUNT` + `MAX`) instead of
    /// materializing every row of the site, so a large site never loads its
    /// projections to count them; the `MAX` keeps the stored timestamp at
    /// full precision, where the previous Rust-side re-read truncated it to
    /// whole seconds.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when a query
    /// fails.
    pub async fn center_site_projection_summary(
        &self,
        site: InstanceId,
    ) -> Result<(u64, Option<OffsetDateTime>), CenterProjectionRepositoryError> {
        let (count, last_refresh_at) = endpoint::Entity::find()
            .filter(endpoint::Column::SiteId.eq(site.into_uuid()))
            .select_only()
            .column_as(Expr::col(endpoint::Column::Id).count(), "count")
            .column_as(
                Expr::col(endpoint::Column::UpdatedAt).max(),
                "last_refresh_at",
            )
            .into_tuple::<(i64, Option<OffsetDateTime>)>()
            .one(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?
            .unwrap_or((0, None));
        Ok((u64::try_from(count).unwrap_or(u64::MAX), last_refresh_at))
    }
}

/// One projected endpoint row of the center's §15.5 view: the identity, the
/// owning site, the active address, the health cut, and the refresh
/// watermark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedEndpointSummary {
    endpoint_id: EndpointId,
    site_id: Option<InstanceId>,
    display_name: String,
    address: String,
    health: String,
    refresh_generation: u64,
}

impl ProjectedEndpointSummary {
    #[must_use]
    pub const fn new(
        endpoint_id: EndpointId,
        site_id: Option<InstanceId>,
        display_name: String,
        address: String,
        health: String,
        refresh_generation: u64,
    ) -> Self {
        Self {
            endpoint_id,
            site_id,
            display_name,
            address,
            health,
            refresh_generation,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub const fn site_id(&self) -> Option<InstanceId> {
        self.site_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub fn health(&self) -> &str {
        &self.health
    }

    #[must_use]
    pub const fn refresh_generation(&self) -> u64 {
        self.refresh_generation
    }
}

/// Maps one projection `u64` to the `SQLite` `INTEGER` range.
fn stored_integer(value: u64) -> Result<i64, CenterProjectionRepositoryError> {
    i64::try_from(value).map_err(|_| CenterProjectionRepositoryError::IntegerOverflow)
}

/// Maps one center trust decision to the stored trust-mode column.
fn stored_trust_mode(mode: CenterTrustMode) -> endpoint_trust::TrustMode {
    match mode {
        CenterTrustMode::SystemCa => endpoint_trust::TrustMode::SystemCa,
        CenterTrustMode::PinnedCertificate => endpoint_trust::TrustMode::PinnedCertificate,
    }
}

/// A controlled failure while projecting the §15.5 center views.
#[derive(Debug, Error)]
pub enum CenterProjectionRepositoryError {
    #[error("projection write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("a projection value cannot be stored in the SQLite INTEGER range")]
    IntegerOverflow,
    #[error("the event append failed: {0}")]
    Event(#[source] crate::EventRepositoryError),
    #[error("the artifact declaration failed: {0}")]
    Artifact(#[source] crate::ArtifactRepositoryError),
    #[error("projection database operation failed: {0}")]
    Database(#[source] DbErr),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_application::{
        CenterTrustMode, EndpointProjectionWrite, ProjectionIgnoreReason, ProjectionWriteOutcome,
        ResourceProjectionWrite,
    };
    use rutilus_domain::{EndpointId, InstanceId, InstanceKind, ResourceFeature, SiteInstance};
    use rutilus_entity::{endpoint_address, endpoint_trust, resource, resource_snapshot};
    use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    /// One endpoint projection fixture: a fixed display name and health cut
    /// with the given address, trust decision, and generation watermark.
    fn projection_write(
        endpoint_id: EndpointId,
        address: &str,
        trust_mode: CenterTrustMode,
        refresh_generation: u64,
    ) -> EndpointProjectionWrite {
        EndpointProjectionWrite::new(
            endpoint_id,
            String::from("Rack A PDU"),
            String::from(address),
            trust_mode,
            refresh_generation,
            String::from("ok"),
        )
    }

    /// One registered site and a store in a fresh temporary directory.
    async fn site_and_store() -> Result<(tempfile::TempDir, SqliteStore, InstanceId), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            OffsetDateTime::now_utc(),
        );
        store.create_instance(&site).await?;
        Ok((directory, store, site.id()))
    }

    // The churn test spells out its exhaustive write/read/rewrite
    // assertions, which exceeds the pedantic line budget (the stress suite
    // allows the same lint on its exhaustive assertion tests).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn endpoint_projection_upsert_skips_address_and_trust_churn_when_unchanged()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, site_id) = site_and_store().await?;
        let base = OffsetDateTime::now_utc();
        let endpoint_id = EndpointId::generate();

        assert_eq!(
            store
                .upsert_endpoint_projection(
                    &projection_write(
                        endpoint_id,
                        "https://192.0.2.10",
                        CenterTrustMode::SystemCa,
                        3,
                    ),
                    site_id,
                    base,
                )
                .await?,
            ProjectionWriteOutcome::Applied
        );
        let address_row = endpoint_address::Entity::find()
            .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .one(&store.database)
            .await?
            .ok_or("the address row is missing")?;
        let address_created_at = address_row.created_at;
        let trust_row = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("the trust row is missing")?;
        let trust_trusted_at = trust_row.trusted_at;

        // The §15.4 redelivery of the identical snapshot is applied without
        // churning the address and trust rows: their creation times survive.
        assert_eq!(
            store
                .upsert_endpoint_projection(
                    &projection_write(
                        endpoint_id,
                        "https://192.0.2.10",
                        CenterTrustMode::SystemCa,
                        3,
                    ),
                    site_id,
                    base + Duration::SECOND,
                )
                .await?,
            ProjectionWriteOutcome::Applied
        );
        let address_row = endpoint_address::Entity::find()
            .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .one(&store.database)
            .await?
            .ok_or("the address row is missing")?;
        assert_eq!(
            address_row.created_at, address_created_at,
            "an unchanged redelivery must not re-create the address row"
        );
        assert_eq!(address_row.address, "https://192.0.2.10");
        let trust_row = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("the trust row is missing")?;
        assert_eq!(
            trust_row.trusted_at, trust_trusted_at,
            "an unchanged redelivery must not re-create the trust row"
        );

        // A changed address still replaces the row in place — exactly one
        // row, carrying the new value.
        assert_eq!(
            store
                .upsert_endpoint_projection(
                    &projection_write(
                        endpoint_id,
                        "https://192.0.2.11",
                        CenterTrustMode::SystemCa,
                        3,
                    ),
                    site_id,
                    base + Duration::SECOND * 2,
                )
                .await?,
            ProjectionWriteOutcome::Applied
        );
        let address_row = endpoint_address::Entity::find()
            .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .one(&store.database)
            .await?
            .ok_or("the address row is missing")?;
        assert_eq!(address_row.address, "https://192.0.2.11");
        assert_eq!(
            endpoint_address::Entity::find()
                .filter(endpoint_address::Column::EndpointId.eq(endpoint_id.into_uuid()))
                .count(&store.database)
                .await?,
            1,
            "the replacement must keep exactly one address row"
        );
        // A changed trust decision replaces the trust row in place.
        assert_eq!(
            store
                .upsert_endpoint_projection(
                    &projection_write(
                        endpoint_id,
                        "https://192.0.2.11",
                        CenterTrustMode::PinnedCertificate,
                        3,
                    ),
                    site_id,
                    base + Duration::SECOND * 3,
                )
                .await?,
            ProjectionWriteOutcome::Applied
        );
        let trust_row = endpoint_trust::Entity::find_by_id(endpoint_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("the trust row is missing")?;
        assert_eq!(
            trust_row.trust_mode,
            endpoint_trust::TrustMode::PinnedCertificate
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn batch_endpoint_projection_lookup_resolves_exactly_the_projected_ids()
    -> Result<(), Box<dyn Error>> {
        let (directory, store, site_id) = site_and_store().await?;
        let base = OffsetDateTime::now_utc();
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        let unknown = EndpointId::generate();
        for (index, endpoint_id) in [first, second].into_iter().enumerate() {
            store
                .upsert_endpoint_projection(
                    &projection_write(
                        endpoint_id,
                        &format!("https://192.0.2.{}", 10 + index),
                        CenterTrustMode::SystemCa,
                        1,
                    ),
                    site_id,
                    base,
                )
                .await?;
        }

        // The batch lookup resolves exactly the projected ids — the unknown
        // id is absent, whatever the input order — and names the site.
        let resolved = store
            .find_endpoint_projections(&[first, unknown, second])
            .await?;
        assert_eq!(resolved.len(), 2);
        assert_eq!(
            resolved
                .get(&first)
                .and_then(CenterEndpointProjection::site_id),
            Some(site_id)
        );
        assert_eq!(
            resolved
                .get(&second)
                .and_then(CenterEndpointProjection::site_id),
            Some(site_id)
        );
        assert!(!resolved.contains_key(&unknown));
        // An empty id set is answered without a query.
        assert!(store.find_endpoint_projections(&[]).await?.is_empty());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn resource_projection_refuses_older_generations() -> Result<(), Box<dyn Error>> {
        let (directory, store, site_id) = site_and_store().await?;
        let base = OffsetDateTime::now_utc();
        let endpoint_id = EndpointId::generate();
        store
            .upsert_endpoint_projection(
                &projection_write(
                    endpoint_id,
                    "https://192.0.2.10",
                    CenterTrustMode::SystemCa,
                    1,
                ),
                site_id,
                base,
            )
            .await?;
        let resource = ResourceProjectionWrite::new(
            endpoint_id,
            String::from("/redfish/v1/Systems/1"),
            ResourceFeature::Systems,
            Some(String::from("#ComputerSystem.v1_20_0.ComputerSystem")),
            None,
            5,
            Some(String::from(r#"{"Name":"System"}"#)),
            base,
        );
        let generation_of = |generation: u64| {
            ResourceProjectionWrite::new(
                endpoint_id,
                String::from("/redfish/v1/Systems/1"),
                ResourceFeature::Systems,
                Some(String::from("#ComputerSystem.v1_20_0.ComputerSystem")),
                None,
                generation,
                Some(String::from(r#"{"Name":"System"}"#)),
                base,
            )
        };

        // The first cut lands; a cut of an older generation is absorbed
        // whole, exactly like the endpoint projection's stale frame.
        assert_eq!(
            store
                .upsert_resource_projection(&resource, site_id, base)
                .await?,
            ProjectionWriteOutcome::Applied
        );
        assert!(matches!(
            store
                .upsert_resource_projection(&generation_of(4), site_id, base)
                .await,
            Ok(ProjectionWriteOutcome::Ignored {
                reason: ProjectionIgnoreReason::StaleGeneration
            })
        ));
        // The same-generation redelivery replaces in place (§15.4), and the
        // next generation appends its own snapshot row.
        assert_eq!(
            store
                .upsert_resource_projection(&resource, site_id, base)
                .await?,
            ProjectionWriteOutcome::Applied
        );
        assert_eq!(
            store
                .upsert_resource_projection(&generation_of(6), site_id, base)
                .await?,
            ProjectionWriteOutcome::Applied
        );
        let resource_row = resource::Entity::find()
            .filter(resource::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .filter(resource::Column::OdataId.eq("/redfish/v1/Systems/1"))
            .one(&store.database)
            .await?
            .ok_or("the resource row is missing")?;
        assert_eq!(
            resource_snapshot::Entity::find()
                .filter(resource_snapshot::Column::ResourceId.eq(resource_row.id))
                .count(&store.database)
                .await?,
            2,
            "only the accepted generations 5 and 6 may have snapshot rows"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }
}
