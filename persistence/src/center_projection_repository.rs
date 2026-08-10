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
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    Set, SqlErr, TransactionTrait,
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
    /// another site is refused (the frame is absorbed), and a re-reported
    /// snapshot replaces the summary in place.
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
        // The active address is replaced in place: the address row is
        // deleted and re-inserted with the reported address. A unique
        // address conflict (the address is already projected for another
        // endpoint) rolls the whole transaction back — the previous address
        // row survives — and the frame is absorbed.
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
        // The trust mode row is replaced in place; the certificate material
        // stays on the site (§15.5 — the center never sees endpoint
        // certificates).
        endpoint_trust::Entity::delete_many()
            .filter(endpoint_trust::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .exec(&transaction)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        endpoint_trust::ActiveModel {
            endpoint_id: Set(endpoint_id.into_uuid()),
            trust_mode: Set(match projection.trust_mode() {
                CenterTrustMode::SystemCa => endpoint_trust::TrustMode::SystemCa,
                CenterTrustMode::PinnedCertificate => endpoint_trust::TrustMode::PinnedCertificate,
            }),
            certificate_sha256: Set(None),
            certificate_der: Set(None),
            trusted_at: Set(now),
        }
        .insert(&transaction)
        .await
        .map_err(CenterProjectionRepositoryError::Database)?;
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
    /// the same generation in place).
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError`] for coordination or
    /// database failures; an unknown or cross-site endpoint is reported as
    /// the ignored outcome.
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
    /// # Errors
    ///
    /// Returns [`CenterProjectionRepositoryError::Database`] when a query
    /// fails.
    pub async fn center_site_projection_summary(
        &self,
        site: InstanceId,
    ) -> Result<(u64, Option<OffsetDateTime>), CenterProjectionRepositoryError> {
        let rows = endpoint::Entity::find()
            .filter(endpoint::Column::SiteId.eq(site.into_uuid()))
            .all(&self.database)
            .await
            .map_err(CenterProjectionRepositoryError::Database)?;
        let count = u64::try_from(rows.len()).unwrap_or(u64::MAX);
        let last_refresh_at = rows
            .into_iter()
            .map(|row| row.updated_at)
            .max()
            .map(|value| OffsetDateTime::from_unix_timestamp(value.unix_timestamp()))
            .transpose()
            .map_err(|_| {
                CenterProjectionRepositoryError::Database(DbErr::Custom(
                    "a stored projection timestamp cannot be re-read".to_owned(),
                ))
            })?;
        Ok((count, last_refresh_at))
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
