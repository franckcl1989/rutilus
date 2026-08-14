//! The center's projection of the §15.5 site reports (0.7.0 S5).
//!
//! The site reports its endpoint projections, resource deltas, event
//! batches, and artifacts through the §15.4 reliable outbox; the center
//! projects them into its views. The storage decision is the §9.3 reuse:
//! the center writes into the same tables the site uses — `endpoints` (plus
//! the active address and trust rows), `resources`/`resource_snapshots`,
//! `events`, and `artifacts` — with the `site_id` association column naming
//! the reporting site on every row.
//!
//! # Convergence and idempotency
//!
//! The center consumes the site's deltas with the same at-least-once
//! discipline the wire provides (§15.4): every write is an idempotent
//! upsert, a `Delete` delta removes the projected rows (the §21 deletion
//! convergence — the site's endpoint-level delete is consumed as the
//! endpoint projection going away), and the per-stream
//! [`rutilus_domain::SyncCursor`] records the highest processed frame
//! sequence so a re-delivered frame is skipped instead of re-applied. A
//! frame that fails to decode (a malformed id, an invalid timestamp, a
//! feature outside the allow-list) is absorbed once — logged and skipped,
//! with the cursor advanced — while a boundary failure propagates and the
//! connection re-delivers the frame.
//!
//! A site-reported event is recorded truthfully (V5C-6): `observed_at` is
//! the center's receive time — never the event's own timestamp — and the
//! BMC timestamp is kept separately in the record's `event_timestamp`, the
//! same two-clock record the site side keeps. A record whose BMC timestamp
//! runs after the receive time is refused by the domain timeline invariant
//! exactly like the site side refuses it at ingestion (a received event
//! cannot have a future timestamp): the record is logged and skipped like
//! any other undecodable record, and the batch cursor advances, so a
//! permanently mis-clocked report never wedges the event stream.
//!
//! # The artifact assembly
//!
//! An [`ArtifactManifest`] declares the artifact under the site's own
//! artifact id (re-declaration keeps the stored row); the following
//! [`ArtifactChunk`] frames are written at the exact offset their
//! zero-based `index` positions (`index * CENTER_ARTIFACT_CHUNK_SIZE`), so
//! a re-delivered chunk lands on the same bytes instead of duplicating
//! them, and a chunk the persisted progress already covers is absorbed.
//! When the last byte lands, the complete file is verified against the
//! declared SHA-256 and marked `Ready`, or `Failed` on a digest mismatch
//! (§14.3 明确失败).

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::PathBuf;

use rutilus_center_protocol::{
    ArtifactChunk, ArtifactManifest, EndpointSnapshot, EnvelopeMessage, EventBatch, EventRecord,
    ResourceDelta, ResourceDeltaOp, ResourceSummary, TlsTrust,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactName, ArtifactState, EndpointId, Event, EventId, EventSeverity,
    InstanceId, MessageId, ResourceFeature, Sha256Hex, SyncCursor, SyncCursorId, SyncStream,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    ArtifactRepository, BoundaryFuture, CenterCursor, artifact_store::ARTIFACT_MAX_SIZE_BYTES,
    center::session::ResolvedSite,
};

/// The reserved message id of the §15.5 absorption dead-letter rows
/// (V5E-3).
///
/// Every ownership-absorbed event record of a batch is reflected as a
/// durable dead-letter event row under this id before the cursor advances,
/// so an absorption is never silently lost: the row names the record's
/// endpoint, its original message id, and the reporting site in its message
/// text, and carries the record's own severity-level fact as a `Warning`.
/// The id is the product's own reserved `Center` registry namespace — no
/// BMC reports under it — and the dead-letter row's dedup key (this id plus
/// the record's own event timestamp) never collides with the dedup key of
/// the original record's message id, so a later legitimate report of the
/// same event still stores its own row.
const CENTER_ABSORBED_EVENT_MESSAGE_ID: &str = "Center.1.0.EventAbsorbed";

/// The assumed payload size of every chunk of a site's artifact transfer.
///
/// The wire carries each chunk's zero-based `index` but no byte size; the
/// site chunks every artifact at the standard transfer chunk size (the
/// final chunk may be shorter), so index `i` owns the
/// `[i * CENTER_ARTIFACT_CHUNK_SIZE, (i + 1) * CENTER_ARTIFACT_CHUNK_SIZE)`
/// range of the file. A site configured with a different chunk size cannot
/// be positioned; its chunks are absorbed as out-of-order rather than
/// miswritten.
const CENTER_ARTIFACT_CHUNK_SIZE: u64 = crate::center_sync::CENTER_ARTIFACT_CHUNK_BYTES as u64;

/// The trust decision the site recorded for one reported endpoint.
///
/// The center's projection keeps the trust *mode* only — the certificate
/// material stays on the site (§15.5 — the center never sees endpoint
/// credentials or sessions).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CenterTrustMode {
    /// The endpoint was verified against the system CA store.
    SystemCa,
    /// The endpoint certificate was explicitly pinned (§10.4).
    PinnedCertificate,
}

/// The decoded center-side projection of one remote endpoint (§15.5).
///
/// The projection carries the summary the site reported: the identity, the
/// display name, the address, the trust decision, the refresh generation
/// watermark, and the health cut of the site's inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointProjectionWrite {
    endpoint_id: EndpointId,
    display_name: String,
    address: String,
    trust_mode: CenterTrustMode,
    refresh_generation: u64,
    health: String,
}

impl EndpointProjectionWrite {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        endpoint_id: EndpointId,
        display_name: String,
        address: String,
        trust_mode: CenterTrustMode,
        refresh_generation: u64,
        health: String,
    ) -> Self {
        Self {
            endpoint_id,
            display_name,
            address,
            trust_mode,
            refresh_generation,
            health,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
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
    pub const fn trust_mode(&self) -> CenterTrustMode {
        self.trust_mode
    }

    #[must_use]
    pub const fn refresh_generation(&self) -> u64 {
        self.refresh_generation
    }

    #[must_use]
    pub fn health(&self) -> &str {
        &self.health
    }
}

/// The decoded center-side projection of one resource (§15.5).
///
/// The resource rows reuse the site's `resources`/`resource_snapshots`
/// tables: the identity row keyed by `(endpoint_id, odata_id)` and one
/// snapshot row per generation carrying the raw decoded document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceProjectionWrite {
    endpoint_id: EndpointId,
    odata_id: String,
    feature: ResourceFeature,
    odata_type: Option<String>,
    etag: Option<String>,
    generation: u64,
    payload: Option<String>,
    observed_at: OffsetDateTime,
}

impl ResourceProjectionWrite {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        endpoint_id: EndpointId,
        odata_id: String,
        feature: ResourceFeature,
        odata_type: Option<String>,
        etag: Option<String>,
        generation: u64,
        payload: Option<String>,
        observed_at: OffsetDateTime,
    ) -> Self {
        Self {
            endpoint_id,
            odata_id,
            feature,
            odata_type,
            etag,
            generation,
            payload,
            observed_at,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub fn odata_id(&self) -> &str {
        &self.odata_id
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    #[must_use]
    pub fn odata_type(&self) -> Option<&str> {
        self.odata_type.as_deref()
    }

    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }
}

/// The center-side projection row of one remote endpoint, as read back for
/// the dispatch routing (§15.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterEndpointProjection {
    endpoint_id: EndpointId,
    site_id: Option<InstanceId>,
}

impl CenterEndpointProjection {
    #[must_use]
    pub const fn new(endpoint_id: EndpointId, site_id: Option<InstanceId>) -> Self {
        Self {
            endpoint_id,
            site_id,
        }
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// The owning site of the projection; `None` for a row without a site
    /// association (never expected on the center database).
    #[must_use]
    pub const fn site_id(&self) -> Option<InstanceId> {
        self.site_id
    }
}

/// Why a projection write was absorbed instead of applied.
///
/// These are data conflicts the persistence layer classifies — the same
/// pattern as the event dedup — so the use case can log and move on without
/// matching on repository error variants: a re-delivered or conflicting
/// frame must never wedge the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionIgnoreReason {
    /// The endpoint projection already belongs to another site; the write
    /// would cross the site boundary.
    EndpointBelongsToOtherSite,
    /// The reported address is already projected for another endpoint.
    AddressAlreadyProjected,
    /// A resource delta names an endpoint the center has not projected.
    UnknownEndpoint,
    /// The frame's refresh generation is older than the stored projection;
    /// the write would roll back a newer inventory cut.
    StaleGeneration,
}

/// The outcome of one projection write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionWriteOutcome {
    /// The projection was applied.
    Applied,
    /// The write was refused by a data conflict; the frame is absorbed.
    Ignored { reason: ProjectionIgnoreReason },
}

/// The persistence boundary of the center-side projection (design §15.5,
/// S5).
///
/// Every write is idempotent (an upsert or an idempotent delete) so the
/// at-least-once delivery of §15.4 never doubles a row, and every write is
/// site-scoped: the reporting site's instance id is stored on the row and
/// checked against the stored association, so one site's frames can never
/// overwrite another site's projection. Data conflicts are reported as
/// [`ProjectionWriteOutcome::Ignored`]; the error variants are boundary
/// failures only.
pub trait CenterProjectionRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Upserts the endpoint projection of one snapshot (the `endpoints`
    /// row, its active address, and its trust mode).
    fn upsert_endpoint<'a>(
        &'a self,
        projection: &'a EndpointProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>>;

    /// Removes the endpoint projection of one site (the row, its addresses,
    /// its trust row, and — by cascade — its resources).
    fn delete_endpoint(
        &self,
        endpoint_id: EndpointId,
        site: InstanceId,
    ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>>;

    /// Upserts the resource projection of one delta: the identity row keyed
    /// by `(endpoint_id, odata_id)` and one snapshot row per generation.
    fn upsert_resource<'a>(
        &'a self,
        projection: &'a ResourceProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>>;

    /// Removes one resource projection of a site.
    fn delete_resource(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
        site: InstanceId,
    ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>>;

    /// Appends one site-reported event, deduplicated by the §14.4
    /// `(endpoint_id, dedup_key)` rule with the site association recorded.
    fn upsert_event<'a>(
        &'a self,
        event: &'a Event,
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Declares one site-reported artifact manifest under the site's own
    /// artifact id; a re-declared identity keeps the stored row (§15.4).
    fn declare_artifact<'a>(
        &'a self,
        artifact: &'a Artifact,
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads the owning site of one site-reported artifact; `None` when the
    /// artifact is unknown or its row carries no site association.
    fn find_artifact_site(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<InstanceId>, Self::Error>>;

    /// Reads the endpoint projection row of one endpoint — the dispatch
    /// routing lookup (§15.6).
    fn find_endpoint_projection(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<CenterEndpointProjection>, Self::Error>>;

    /// Reports whether one resource projection exists for an endpoint.
    fn has_resource(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
    ) -> BoundaryFuture<'_, Result<bool, Self::Error>>;

    /// Resolves the projection rows of many endpoint ids as one batch —
    /// the §15.5 ownership preload of one event batch.
    ///
    /// The returned map holds exactly one entry per endpoint id that has a
    /// projection row; ids without a row are absent. The default
    /// implementation resolves every id through
    /// [`Self::find_endpoint_projection`]; a store with batch query support
    /// resolves the whole set with one `IN` lookup.
    fn find_endpoint_projections<'a>(
        &'a self,
        endpoint_ids: &'a [EndpointId],
    ) -> BoundaryFuture<'a, Result<HashMap<EndpointId, CenterEndpointProjection>, Self::Error>>
    {
        Box::pin(async move {
            let mut projections = HashMap::with_capacity(endpoint_ids.len());
            for endpoint_id in endpoint_ids {
                if let Some(projection) = self.find_endpoint_projection(*endpoint_id).await? {
                    projections.insert(*endpoint_id, projection);
                }
            }
            Ok(projections)
        })
    }

    /// Appends many site-reported events as one batch (§15.5), deduplicated
    /// by the §14.4 `(endpoint_id, dedup_key)` rule with the site
    /// association recorded — the batch counterpart of
    /// [`Self::upsert_event`].
    ///
    /// The default implementation appends every event through
    /// [`Self::upsert_event`]; a store with batch write support appends the
    /// whole batch under one write-gate acquisition and one transaction, so
    /// a boundary failure re-delivers and re-applies every record of the
    /// batch whole (the §15.4 at-least-once discipline).
    fn upsert_events<'a>(
        &'a self,
        events: &'a [Event],
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            for event in events {
                self.upsert_event(event, site).await?;
            }
            Ok(())
        })
    }
}

impl<Repository> CenterProjectionRepository for &Repository
where
    Repository: CenterProjectionRepository + ?Sized,
{
    type Error = Repository::Error;

    fn upsert_endpoint<'a>(
        &'a self,
        projection: &'a EndpointProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
        Repository::upsert_endpoint(*self, projection, site, now)
    }

    fn delete_endpoint(
        &self,
        endpoint_id: EndpointId,
        site: InstanceId,
    ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
        Repository::delete_endpoint(*self, endpoint_id, site)
    }

    fn upsert_resource<'a>(
        &'a self,
        projection: &'a ResourceProjectionWrite,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
        Repository::upsert_resource(*self, projection, site, now)
    }

    fn delete_resource(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
        site: InstanceId,
    ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
        Repository::delete_resource(*self, endpoint_id, odata_id, site)
    }

    fn upsert_event<'a>(
        &'a self,
        event: &'a Event,
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::upsert_event(*self, event, site)
    }

    fn declare_artifact<'a>(
        &'a self,
        artifact: &'a Artifact,
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::declare_artifact(*self, artifact, site)
    }

    fn find_artifact_site(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<InstanceId>, Self::Error>> {
        Repository::find_artifact_site(*self, artifact_id)
    }

    fn find_endpoint_projection(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<CenterEndpointProjection>, Self::Error>> {
        Repository::find_endpoint_projection(*self, endpoint_id)
    }

    fn has_resource(
        &self,
        endpoint_id: EndpointId,
        odata_id: &str,
    ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
        Repository::has_resource(*self, endpoint_id, odata_id)
    }

    fn find_endpoint_projections<'a>(
        &'a self,
        endpoint_ids: &'a [EndpointId],
    ) -> BoundaryFuture<'a, Result<HashMap<EndpointId, CenterEndpointProjection>, Self::Error>>
    {
        Repository::find_endpoint_projections(*self, endpoint_ids)
    }

    fn upsert_events<'a>(
        &'a self,
        events: &'a [Event],
        site: InstanceId,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::upsert_events(*self, events, site)
    }
}

/// The content-frame boundary of the processor: the projection consumes
/// every §15.5 content frame of a site report.
pub trait CenterContentConsumer: Send + Sync {
    /// The consumer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Handles one content frame.
    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        sequence: u64,
        message: &'a EnvelopeMessage,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

/// The center-side projection use case: consumes one site report frame
/// (design §15.5, S5).
///
/// `Store` is the projection and artifact boundary on one store, `Cursor`
/// the per-stream sync-cursor boundary. Every frame is cursor-gated — the
/// cursor value is the highest processed frame sequence of the frame's
/// stream, so a re-delivered frame is skipped — and the cursor advances
/// after the attempt, whether the frame applied or was absorbed, so a
/// corrupt frame is consumed exactly once.
pub struct CenterProjection<Store, Cursor> {
    store: Store,
    cursor: Cursor,
    /// The single open artifact-file handle of the §15.5 chunk writes (see
    /// [`OpenArtifactFile`]). Only the blocking chunk-write closure touches
    /// it and never across an await, so the plain `Mutex` is safe.
    artifact_handle: std::sync::Arc<std::sync::Mutex<Option<OpenArtifactFile>>>,
}

impl<Store, Cursor> CenterContentConsumer for CenterProjection<Store, Cursor>
where
    Store: CenterProjectionRepository + ArtifactRepository,
    Cursor: CenterCursor,
{
    type Error = ProjectionErrorOf<Store, Cursor>;

    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        sequence: u64,
        message: &'a EnvelopeMessage,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { self.on_frame(site, sequence, message, now).await })
    }
}

impl<Store, Cursor> CenterProjection<Store, Cursor> {
    #[must_use]
    pub fn new(store: Store, cursor: Cursor) -> Self {
        Self {
            store,
            cursor,
            artifact_handle: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

/// A controlled failure of one projection step.
///
/// The three generic parameters are the projection repository's, the
/// artifact repository's, and the cursor boundary's error types, so every
/// persistence failure stays reachable as the source of an error chain.
/// Frame-level defects are not errors: they are logged and absorbed inside
/// the use case, so only a boundary failure surfaces here (and the engine
/// then re-delivers the frame on the next connection).
#[derive(Debug, Error)]
pub enum CenterProjectionError<ProjectionError, ArtifactError, CursorError>
where
    ProjectionError: Error + 'static,
    ArtifactError: Error + 'static,
    CursorError: Error + 'static,
{
    /// The projection repository failed; carries its own error.
    #[error("the projection repository failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The artifact store failed; carries its own error.
    #[error("the artifact store failed: {0}")]
    Artifact(#[source] ArtifactError),
    /// The artifact file could not be read or written (§7.8 blocking I/O).
    #[error("artifact {artifact_id} could not be touched: {source}")]
    ArtifactFile {
        artifact_id: ArtifactId,
        #[source]
        source: std::io::Error,
    },
    /// The sync cursor boundary failed; carries its own error.
    #[error("the sync cursor failed: {0}")]
    Cursor(#[source] CursorError),
}

/// The concrete failure type of one projection step.
type ProjectionErrorOf<Store, Cursor> = CenterProjectionError<
    <Store as CenterProjectionRepository>::Error,
    <Store as ArtifactRepository>::Error,
    <Cursor as CenterCursor>::Error,
>;

impl<Store, Cursor> CenterProjection<Store, Cursor>
where
    Store: CenterProjectionRepository + ArtifactRepository,
    Cursor: CenterCursor,
{
    /// Consumes one §15.5 content frame of a site's report.
    ///
    /// `sequence` is the frame's durable outbox sequence — the cursor
    /// watermark of the frame's stream. A frame whose sequence is already
    /// at or below the stream cursor was processed on an earlier delivery
    /// and is skipped; every other frame is applied (or absorbed with a
    /// log), and the cursor advances.
    ///
    /// # Errors
    ///
    /// Returns [`CenterProjectionError`] for a boundary failure; the frame
    /// is then not acknowledged and the connection re-delivers it.
    pub async fn on_frame(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        message: &EnvelopeMessage,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        match message {
            EnvelopeMessage::EndpointSnapshot(snapshot) => {
                self.consume_endpoint(site, sequence, snapshot, now).await
            }
            EnvelopeMessage::ResourceDelta(delta) => {
                self.consume_resource_delta(site, sequence, delta, now)
                    .await
            }
            EnvelopeMessage::EventBatch(batch) => {
                self.consume_event_batch(site, sequence, batch, now).await
            }
            EnvelopeMessage::ArtifactManifest(manifest) => {
                self.consume_artifact_manifest(site, sequence, manifest, now)
                    .await
            }
            EnvelopeMessage::ArtifactChunk(chunk) => {
                self.consume_artifact_chunk(site, sequence, chunk, now)
                    .await
            }
            // Not a content frame; the caller routes content only, so this
            // is the defensive floor.
            _ => Ok(()),
        }
    }

    /// Consumes one endpoint snapshot: the endpoint projection upsert with
    /// its active address and trust mode (§15.5 endpoint summary).
    async fn consume_endpoint(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        snapshot: &EndpointSnapshot,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if !self
            .passes_cursor(site, SyncStream::Endpoint, sequence)
            .await?
        {
            return Ok(());
        }
        let outcome = match decode_endpoint(snapshot) {
            Err(reason) => {
                return self
                    .absorb_frame(site, sequence, SyncStream::Endpoint, now, reason)
                    .await;
            }
            Ok(projection) => self
                .store
                .upsert_endpoint(&projection, site.instance_id(), now)
                .await
                .map_err(CenterProjectionError::Projection)?,
        };
        self.settle_outcome(outcome, site, sequence, SyncStream::Endpoint, now)
            .await
    }

    /// Consumes one resource delta: the upsert of the identity row and the
    /// generation snapshot, or the deletion that makes the projection
    /// converge (§21 — the site's `Delete` deltas must be consumed).
    async fn consume_resource_delta(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        delta: &ResourceDelta,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if !self
            .passes_cursor(site, SyncStream::Endpoint, sequence)
            .await?
        {
            return Ok(());
        }
        let decoded = match decode_delta(delta) {
            Err(reason) => {
                return self
                    .absorb_frame(site, sequence, SyncStream::Endpoint, now, reason)
                    .await;
            }
            Ok(decoded) => decoded,
        };
        let outcome = match decoded {
            DecodedDelta::DeleteEndpoint(endpoint_id) => self
                .store
                .delete_endpoint(endpoint_id, site.instance_id())
                .await
                .map_err(CenterProjectionError::Projection)?,
            DecodedDelta::DeleteResource {
                endpoint_id,
                odata_id,
            } => self
                .store
                .delete_resource(endpoint_id, &odata_id, site.instance_id())
                .await
                .map_err(CenterProjectionError::Projection)?,
            DecodedDelta::UpsertResource(projection) => self
                .store
                .upsert_resource(&projection, site.instance_id(), now)
                .await
                .map_err(CenterProjectionError::Projection)?,
        };
        self.settle_outcome(outcome, site, sequence, SyncStream::Endpoint, now)
            .await
    }

    /// Consumes one event batch: every record is validated, its endpoint is
    /// checked against the reporting site, and it is appended with the
    /// §14.4 dedup and the site association; a record that cannot be decoded
    /// — or that names an endpoint the site does not own — is logged and
    /// skipped without failing the batch.
    ///
    /// The batch is consumed as a unit: the §15.5 ownership preload of the
    /// batch's endpoints is one batch lookup, and the surviving records are
    /// appended as one batch write, instead of a query and a transaction per
    /// record.
    ///
    /// An ownership-absorbed record is never silently lost (V5E-3): before
    /// the cursor advances, the record is reflected as a durable dead-letter
    /// event row under [`CENTER_ABSORBED_EVENT_MESSAGE_ID`] — the record's
    /// endpoint, its original message id, and the reporting site in the
    /// message text — written through the same batch write as the owned
    /// records. The alternatives were evaluated and rejected: delaying the
    /// cursor to re-deliver the batch would wedge the site's event stream
    /// forever on the permanent anomalies the ownership check absorbs (an
    /// endpoint of another site, or an endpoint the center no longer
    /// projects — the in-order §15.4 delivery guarantees the endpoint
    /// snapshot precedes the events of one site, so the absorption never
    /// heals on a re-delivery), at the cost of every later legitimate event
    /// of the site; and the dead-letter needs no new table — the events
    /// table is the §9.3 append-only record that already outlives its
    /// sources, and the reserved message id keeps the dead-letter rows
    /// distinguishable and dedup-safe.
    async fn consume_event_batch(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        batch: &EventBatch,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if !self
            .passes_cursor(site, SyncStream::Event, sequence)
            .await?
        {
            return Ok(());
        }
        // Decode every record first, so the rest of the batch — the
        // ownership preload and the writes — runs on the decodable records
        // only.
        let mut events = Vec::new();
        for record in &batch.events {
            match decode_event(record, now) {
                Err(reason) => {
                    // The record is a data defect, not a boundary failure,
                    // exactly like every other absorbed frame: it is logged
                    // at the same warn level as the delta-stream absorbs and
                    // the batch cursor advances past it, so one bad record
                    // can never wedge the event stream behind it (the §15.4
                    // at-least-once absorption — the frame was consumed once).
                    tracing::warn!(
                        "site {}: skipping event record {}: {reason}",
                        site.instance_id(),
                        record.event_id
                    );
                }
                Ok(event) => events.push(event),
            }
        }
        // §14.4 记录事件来源 with the §15.5 site scope: each event's
        // endpoint must be a projection of the reporting site. The batch's
        // endpoint ownership is resolved in one preload; a record that names
        // an unknown endpoint, or an endpoint of another site, is refused
        // for the projection exactly like an undecodable record — one site
        // can never plant an event under another site's endpoint — and is
        // reflected as its dead-letter row instead of vanishing.
        let endpoint_ids = events
            .iter()
            .map(Event::endpoint_id)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let projections = self
            .store
            .find_endpoint_projections(&endpoint_ids)
            .await
            .map_err(CenterProjectionError::Projection)?;
        let mut records = Vec::with_capacity(events.len());
        for event in events {
            match projections.get(&event.endpoint_id()) {
                Some(projection) if projection.site_id() == Some(site.instance_id()) => {
                    records.push(event);
                }
                Some(_) => {
                    let reason = "the endpoint belongs to another site";
                    tracing::warn!(
                        "site {}: skipping event record {}: {reason}",
                        site.instance_id(),
                        event.id()
                    );
                    match absorption_dead_letter(&event, site.instance_id(), reason) {
                        Ok(dead_letter) => records.push(dead_letter),
                        Err(failure) => log_missing_dead_letter(site, &event, failure, reason),
                    }
                }
                None => {
                    let reason = "the endpoint is not projected";
                    tracing::warn!(
                        "site {}: skipping event record {}: {reason}",
                        site.instance_id(),
                        event.id()
                    );
                    match absorption_dead_letter(&event, site.instance_id(), reason) {
                        Ok(dead_letter) => records.push(dead_letter),
                        Err(failure) => log_missing_dead_letter(site, &event, failure, reason),
                    }
                }
            }
        }
        if !records.is_empty() {
            self.store
                .upsert_events(&records, site.instance_id())
                .await
                .map_err(CenterProjectionError::Projection)?;
        }
        self.advance_cursor(site, SyncStream::Event, sequence, now)
            .await
    }

    /// Consumes one artifact manifest: the declaration under the site's own
    /// artifact id (a re-declaration keeps the stored row, §15.4).
    async fn consume_artifact_manifest(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        manifest: &ArtifactManifest,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if !self
            .passes_cursor(site, SyncStream::Artifact, sequence)
            .await?
        {
            return Ok(());
        }
        let artifact = match decode_manifest(manifest, now) {
            Err(reason) => {
                return self
                    .absorb_frame(site, sequence, SyncStream::Artifact, now, reason)
                    .await;
            }
            Ok(artifact) => artifact,
        };
        self.store
            .declare_artifact(&artifact, site.instance_id())
            .await
            .map_err(CenterProjectionError::Projection)?;
        self.advance_cursor(site, SyncStream::Artifact, sequence, now)
            .await
    }

    /// Consumes one artifact chunk: the bytes are written at the exact
    /// offset the chunk's zero-based `index` positions — a re-delivered
    /// chunk lands on the same bytes instead of re-appending, and a chunk
    /// the persisted progress already covers is absorbed — and when the
    /// transfer completes the file is verified against the declared digest
    /// and marked `Ready` or `Failed`.
    // The chunk consumer spells out the site scope, the index positioning,
    // the size guards, and the three reconciliation branches (covered,
    // out-of-order, continuation), which exceeds the pedantic line budget
    // (the endpoint projection upsert allows the same lint for the same
    // reason).
    #[allow(clippy::too_many_lines)]
    async fn consume_artifact_chunk(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        chunk: &ArtifactChunk,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if !self
            .passes_cursor(site, SyncStream::Artifact, sequence)
            .await?
        {
            return Ok(());
        }
        let Ok(artifact_id) = chunk.artifact_id.parse::<ArtifactId>() else {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "unparseable artifact id",
                )
                .await;
        };
        let Some(artifact) = self
            .store
            .find_artifact(artifact_id)
            .await
            .map_err(CenterProjectionError::Artifact)?
        else {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "a chunk arrived before its manifest",
                )
                .await;
        };
        // The §15.5 site scope: the artifact row names the site that
        // declared it, and only that site may add bytes to it. A chunk a
        // different site sends is absorbed without touching the file.
        if self
            .store
            .find_artifact_site(artifact_id)
            .await
            .map_err(CenterProjectionError::Projection)?
            != Some(site.instance_id())
        {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "the artifact belongs to another site",
                )
                .await;
        }
        if artifact.state().is_terminal() {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "a chunk arrived for a finished artifact",
                )
                .await;
        }
        if chunk.data.is_empty() {
            return self
                .advance_cursor(site, SyncStream::Artifact, sequence, now)
                .await;
        }
        let received = u64::try_from(chunk.data.len()).unwrap_or(u64::MAX);
        let offset = u64::from(chunk.index) * CENTER_ARTIFACT_CHUNK_SIZE;
        let Some(end) = offset.checked_add(received) else {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "the chunk would overflow the progress",
                )
                .await;
        };
        if end > artifact.size_bytes() {
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "the chunk would exceed the declared size",
                )
                .await;
        }
        let uploaded = artifact.uploaded_bytes();
        if end <= uploaded {
            // The chunk's range is already covered by the persisted
            // progress — the §15.4 re-delivery of a chunk whose row update
            // or cursor write was lost. Absorbing it (instead of appending
            // again) is what keeps a retry from duplicating bytes, and the
            // row or cursor write the crash lost has already taken effect.
            return self
                .advance_cursor(site, SyncStream::Artifact, sequence, now)
                .await;
        }
        if offset != uploaded {
            // The chunk is out of order (a gap before it) or straddles the
            // persisted progress (a range the row partially covers).
            // Touching the file on this ambiguity could corrupt it; the
            // chunk is absorbed with the progress untouched.
            return self
                .absorb_frame(
                    site,
                    sequence,
                    SyncStream::Artifact,
                    now,
                    "the chunk is out of order or straddles the persisted progress",
                )
                .await;
        }
        // The exact continuation: the write lands at the chunk's offset and
        // the row advances only after it succeeds. The two steps are
        // idempotently redoable by index, so the §7.8 crash windows close
        // on the re-delivered chunk: a write whose row update was lost
        // overwrites the same range with the same bytes (W1 — no duplicate
        // bytes, no digest mismatch), and a row update whose cursor write
        // was lost is absorbed as already covered (W2 — the transfer is not
        // left Uploading forever).
        let path = self.store.artifact_file_path(artifact_id);
        let data = chunk.data.clone();
        let handles = std::sync::Arc::clone(&self.artifact_handle);
        tokio::task::spawn_blocking(move || {
            write_chunk_at(artifact_id, &path, offset, &data, &handles)
        })
        .await
        .map_err(|source| CenterProjectionError::ArtifactFile {
            artifact_id,
            source: std::io::Error::other(source.to_string()),
        })?
        .map_err(|source| CenterProjectionError::ArtifactFile {
            artifact_id,
            source,
        })?;
        if end < artifact.size_bytes() {
            self.store
                .update_artifact(artifact_id, end, ArtifactState::Uploading, now)
                .await
                .map_err(CenterProjectionError::Artifact)?;
        } else {
            self.finalize_artifact(artifact_id, end, now).await?;
        }
        self.advance_cursor(site, SyncStream::Artifact, sequence, now)
            .await
    }

    /// Verifies the complete artifact file against the declared digest and
    /// records the terminal state (§14.3 明确失败: a digest mismatch is a
    /// `Failed` artifact, never a silently corrupt file).
    async fn finalize_artifact(
        &self,
        artifact_id: ArtifactId,
        size_bytes: u64,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        let path = self.store.artifact_file_path(artifact_id);
        let digest = hash_artifact_file(path).await.map_err(|source| {
            CenterProjectionError::ArtifactFile {
                artifact_id,
                source,
            }
        })?;
        let artifact = self
            .store
            .find_artifact(artifact_id)
            .await
            .map_err(CenterProjectionError::Artifact)?
            .ok_or_else(|| CenterProjectionError::ArtifactFile {
                artifact_id,
                source: std::io::Error::other("the artifact vanished during the transfer"),
            })?;
        let state = if digest == artifact.sha256().into_bytes() {
            ArtifactState::Ready
        } else {
            ArtifactState::Failed
        };
        self.store
            .update_artifact(artifact_id, size_bytes, state, now)
            .await
            .map_err(CenterProjectionError::Artifact)?;
        Ok(())
    }

    /// Logs an absorbed frame and advances the cursor: the frame is
    /// consumed exactly once.
    async fn absorb_frame(
        &self,
        site: &ResolvedSite,
        sequence: u64,
        stream: SyncStream,
        now: OffsetDateTime,
        reason: &str,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        tracing::warn!(
            "site {}: skipped frame {sequence} of the {stream} stream: {reason}",
            site.instance_id()
        );
        self.advance_cursor(site, stream, sequence, now).await
    }

    /// Logs an ignored write and advances the cursor.
    async fn settle_outcome(
        &self,
        outcome: ProjectionWriteOutcome,
        site: &ResolvedSite,
        sequence: u64,
        stream: SyncStream,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        if let ProjectionWriteOutcome::Ignored { reason } = outcome {
            tracing::warn!(
                "site {}: absorbed frame {sequence} of the {stream} stream: {reason:?}",
                site.instance_id()
            );
        }
        self.advance_cursor(site, stream, sequence, now).await
    }

    /// Reports whether a frame is new for its stream: `false` when the
    /// stored cursor already covers the frame's sequence (the frame was
    /// processed on an earlier delivery).
    async fn passes_cursor(
        &self,
        site: &ResolvedSite,
        stream: SyncStream,
        sequence: u64,
    ) -> Result<bool, ProjectionErrorOf<Store, Cursor>> {
        let Some(cursor) = self
            .cursor
            .get(site.instance_id(), stream)
            .await
            .map_err(CenterProjectionError::Cursor)?
        else {
            return Ok(true);
        };
        let Ok(processed) = cursor.cursor_value().parse::<u64>() else {
            // A stored cursor a manual DB change or a partial restore left
            // unparseable must not wedge the stream: log it, process the
            // frame, and let the cursor write at the end heal the row.
            tracing::warn!(
                "site {}: resetting the {stream} stream cursor: the stored value is not a sequence",
                site.instance_id()
            );
            return Ok(true);
        };
        Ok(sequence > processed)
    }

    /// Advances the stream cursor to the processed frame's sequence.
    async fn advance_cursor(
        &self,
        site: &ResolvedSite,
        stream: SyncStream,
        sequence: u64,
        now: OffsetDateTime,
    ) -> Result<(), ProjectionErrorOf<Store, Cursor>> {
        self.cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                site.instance_id(),
                stream,
                sequence.to_string(),
                now,
            ))
            .await
            .map_err(CenterProjectionError::Cursor)
    }
}

/// Decodes one endpoint snapshot into the projection write; the wire shape
/// is validated here so the repository only ever persists decoded data.
fn decode_endpoint(snapshot: &EndpointSnapshot) -> Result<EndpointProjectionWrite, &'static str> {
    let endpoint_id = snapshot
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(|_| "unparseable endpoint id")?;
    let trust_mode = match TlsTrust::try_from(snapshot.trust) {
        Ok(TlsTrust::SystemCa) => CenterTrustMode::SystemCa,
        Ok(TlsTrust::PinnedCertificate) => CenterTrustMode::PinnedCertificate,
        _ => return Err("unspecified or unknown trust mode"),
    };
    Ok(EndpointProjectionWrite::new(
        endpoint_id,
        snapshot.display_name.clone(),
        snapshot.address.clone(),
        trust_mode,
        snapshot.refresh_generation,
        snapshot.health.clone(),
    ))
}

/// One decoded resource delta.
enum DecodedDelta {
    /// The endpoint-level delete: the whole projection goes away.
    DeleteEndpoint(EndpointId),
    /// One resource-level delete.
    DeleteResource {
        endpoint_id: EndpointId,
        odata_id: String,
    },
    /// One resource upsert.
    UpsertResource(ResourceProjectionWrite),
}

/// Decodes one resource delta into the projection operation; the wire shape
/// is validated here so the repository only ever persists decoded data.
fn decode_delta(delta: &ResourceDelta) -> Result<DecodedDelta, &'static str> {
    let endpoint_id = delta
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(|_| "unparseable endpoint id")?;
    match (ResourceDeltaOp::try_from(delta.op), delta.resource.as_ref()) {
        (Ok(ResourceDeltaOp::Delete), None) => Ok(DecodedDelta::DeleteEndpoint(endpoint_id)),
        (Ok(ResourceDeltaOp::Delete), Some(resource)) => Ok(DecodedDelta::DeleteResource {
            endpoint_id,
            odata_id: resource.odata_id.clone(),
        }),
        (Ok(ResourceDeltaOp::Upsert), Some(resource)) => Ok(DecodedDelta::UpsertResource(
            decode_resource(endpoint_id, resource, delta)?,
        )),
        (Ok(ResourceDeltaOp::Upsert), None) => Err("an upsert delta must carry its resource"),
        (Ok(ResourceDeltaOp::Unspecified), _) => Err("unspecified delta operation"),
        (Err(_), _) => Err("unknown delta operation code"),
    }
}

/// Decodes one resource summary and payload into the projection write.
fn decode_resource(
    endpoint_id: EndpointId,
    resource: &ResourceSummary,
    delta: &ResourceDelta,
) -> Result<ResourceProjectionWrite, &'static str> {
    let feature = resource
        .feature
        .parse::<ResourceFeature>()
        .map_err(|_| "unknown resource feature code")?;
    let payload = String::from_utf8(delta.payload_json.clone())
        .map_err(|_| "resource payload is not valid UTF-8")?;
    let observed_at = OffsetDateTime::from_unix_timestamp(delta.observed_at_unix)
        .map_err(|_| "unparseable observation timestamp")?;
    Ok(ResourceProjectionWrite::new(
        endpoint_id,
        resource.odata_id.clone(),
        feature,
        (!resource.odata_type.is_empty()).then(|| resource.odata_type.clone()),
        (!resource.etag.is_empty()).then(|| resource.etag.clone()),
        resource.generation,
        Some(payload),
        observed_at,
    ))
}

/// Decodes one event record into the domain event; `now` is the product
/// receive time recorded as the event's `observed_at`.
///
/// The record is truthful about the two clocks (V5C-6): `observed_at` is
/// the center's receive time — never the event's own timestamp — and the
/// BMC timestamp stays in the record's `event_timestamp`, exactly the
/// two-clock record the site side keeps. A record whose BMC timestamp runs
/// after the receive time is refused by the domain timeline invariant
/// (`event_timestamp <= observed_at`), precisely as the site side refuses
/// the same record at ingestion — a received event cannot have a future
/// timestamp, and inventing one for `observed_at` (clamping the receive
/// time to the event's clock) would record a lie in the timeline the dedup
/// key and the recent listing order by. The refusal is reported honestly
/// through the existing decode-failure classification (logged and skipped
/// once, the cursor advancing): refusing to advance would wedge the event
/// stream on a permanently mis-clocked report and block every later event.
///
/// The `Center.` message-id namespace is reserved for the center's own
/// dead-letter reflections (R6-D-7): a site reporting an event under the
/// reserved prefix would spoof an internal administrative row, and its dedup
/// key could collide with a real dead-letter's. A record under the reserved
/// prefix is refused exactly like any other undecodable report.
fn decode_event(record: &EventRecord, now: OffsetDateTime) -> Result<Event, &'static str> {
    let id = record
        .event_id
        .parse::<EventId>()
        .map_err(|_| "unparseable event id")?;
    let endpoint_id = record
        .endpoint_id
        .parse::<EndpointId>()
        .map_err(|_| "unparseable endpoint id")?;
    let message_id = MessageId::parse(&record.message_id).map_err(|_| "unusable message id")?;
    if message_id.as_str().starts_with("Center.") {
        return Err("reserved message id namespace");
    }
    let severity = match rutilus_center_protocol::EventSeverity::try_from(record.severity) {
        Ok(rutilus_center_protocol::EventSeverity::Ok) => EventSeverity::Ok,
        Ok(rutilus_center_protocol::EventSeverity::Warning) => EventSeverity::Warning,
        Ok(rutilus_center_protocol::EventSeverity::Critical) => EventSeverity::Critical,
        _ => return Err("unspecified or unknown severity"),
    };
    let event_timestamp = OffsetDateTime::from_unix_timestamp(record.occurred_at_unix)
        .map_err(|_| "unparseable occurrence timestamp")?;
    Event::new(
        id,
        endpoint_id,
        message_id,
        severity,
        None,
        event_timestamp,
        now,
    )
    .map_err(|_| "event timestamp is after the receive time")
}

/// The §15.5 absorption dead-letter row of one ownership-absorbed event
/// record (V5E-3): a durable event-row reflection under the reserved
/// [`CENTER_ABSORBED_EVENT_MESSAGE_ID`].
///
/// The row keeps every fact that identifies the absorbed record — its
/// endpoint, its original message id, its BMC timestamp, and the receive
/// time — and the absorption reason in its message text, so the event is
/// never silently lost. The dedup key of the dead-letter row is derived
/// from the reserved message id and the record's own timestamp, so it never
/// collides with the original record's dedup key: a later legitimate report
/// of the same event still stores its own row. The dead-letter is always a
/// `Warning` — an absorption is an administrative fact, whatever the
/// absorbed record's own severity said — and it is site-attributed like
/// every center event row.
///
/// # Errors
///
/// Returns `Err` when the reserved message id is unusable (a build defect —
/// the constant is fixed) or the row cannot be built (a timeline defect the
/// decoded record cannot carry); the caller then logs the absorption at
/// error level, naming the missing durable reflection ([`log_missing_dead_letter`]).
fn absorption_dead_letter(
    event: &Event,
    site: InstanceId,
    reason: &str,
) -> Result<Event, &'static str> {
    let message_id = MessageId::parse(CENTER_ABSORBED_EVENT_MESSAGE_ID)
        .map_err(|_| "the reserved absorption message id is not usable")?;
    Event::new(
        EventId::generate(),
        event.endpoint_id(),
        message_id,
        EventSeverity::Warning,
        Some(format!(
            "event absorbed: endpoint {}, message id {}, reported by site {site}: {reason}",
            event.endpoint_id(),
            event.message_id()
        )),
        event.event_timestamp(),
        event.observed_at(),
    )
    .map_err(|_| "the absorption dead-letter row cannot be built")
}

/// Logs an absorbed event record whose durable dead-letter reflection could
/// not be built (R6-D-6) — without the error the record would be lost
/// without a durable row, silently. The construction failure is a build
/// defect (the reserved message id constant is fixed; the timeline the
/// decoded record cannot carry was already refused at decode), so the log is
/// at error level and names the missing durable reflection.
fn log_missing_dead_letter(
    site: &ResolvedSite,
    event: &Event,
    failure: &'static str,
    reason: &str,
) {
    tracing::error!(
        "site {}: absorbed event record {} has no durable dead-letter reflection \
         (durable 反射缺失): {failure}; absorption reason: {reason}",
        site.instance_id(),
        event.id()
    );
}

/// Decodes one artifact manifest into the domain artifact under the site's
/// own artifact id.
fn decode_manifest(
    manifest: &ArtifactManifest,
    now: OffsetDateTime,
) -> Result<Artifact, &'static str> {
    let artifact_id = manifest
        .artifact_id
        .parse::<ArtifactId>()
        .map_err(|_| "unparseable artifact id")?;
    if manifest.total_bytes == 0 {
        return Err("a zero-byte artifact cannot be transferred");
    }
    // S1: the center enforces the same declared-total cap as the site-side
    // `create` (`ARTIFACT_MAX_SIZE_BYTES`), so a trusted site can never
    // declare a manifest that fills the center's disk past the cap. The
    // rejection flows through the same absorb-skip-warn path as every other
    // undecodable manifest — the center protocol has no HTTP status to
    // answer with, and a refused declaration leaves no row behind, so the
    // site's next delivery of the same identity re-declares and is refused
    // again (the at-least-once outbox keeps the frame until the site learns
    // of the skip) while the warning names the reason in the center log.
    // Once the declared total is capped, the chunk path's
    // `end <= artifact.size_bytes()` check bounds the accumulated bytes the
    // same way the site side's `append_chunk` does (§14.3).
    if manifest.total_bytes > ARTIFACT_MAX_SIZE_BYTES {
        return Err("the artifact exceeds the 2 GiB declared-size cap");
    }
    let name = ArtifactName::parse(&manifest.name).map_err(|_| "unusable artifact name")?;
    let sha256 = Sha256Hex::from_bytes(
        <[u8; 32]>::try_from(manifest.sha256.as_slice())
            .map_err(|_| "the digest is not 32 bytes")?,
    );
    Ok(Artifact::new(
        artifact_id,
        name,
        manifest.total_bytes,
        sha256,
        now,
    ))
}

/// Hashes one artifact file under `spawn_blocking` (§7.8) and returns the
/// digest in the raw 32-byte form for comparison with the declared value.
///
/// The file is read in 64 KiB heap-buffered passes, mirroring the site-side
/// hash path, so a large artifact never loads into memory whole: the buffer
/// must stay off the Tokio worker stack (§7.8), and a heap buffer keeps the
/// worker's stack usage independent of the chosen read size.
async fn hash_artifact_file(path: PathBuf) -> Result<[u8; 32], std::io::Error> {
    tokio::task::spawn_blocking(move || {
        use std::io::Read as _;
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().into())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// One open artifact file of the §15.5 chunk write path.
///
/// The handle is reused across the in-order chunks of one transfer instead
/// of opening the file per chunk; the slot holds at most one handle, so a
/// chunk of another artifact closes the previous transfer's file before
/// opening its own. The artifact file path is a pure function of the store
/// location and the artifact identity, so a handle opened for an id is
/// always the file that id's chunks belong to.
struct OpenArtifactFile {
    artifact_id: ArtifactId,
    file: std::fs::File,
}

/// Writes one chunk at its exact offset in the artifact file; the blocking
/// half of the §7.8 file I/O, mirroring the site-side upload flow. The
/// artifact directory is created on demand: the manifest may outlive any
/// file, and the first chunk is the moment the bytes exist. The write seeks
/// to the offset and overwrites exactly that range, so a retried chunk (the
/// §15.4 at-least-once retransmission) lands on the same bytes instead of
/// duplicating them.
///
/// The transfer's open file handle is reused across its chunks: `handles`
/// is the single-slot cache of the projection, holding the current
/// transfer's handle, so every chunk after the first skips the `open` (and
/// the directory creation), and a chunk of another artifact closes the
/// previous file before opening its own. The reuse is safe because every
/// write still seeks to the chunk's exact offset — a re-delivered chunk
/// overwrites the same range whatever handle it runs through — and the slot
/// is one handle, so the open-file count is bounded.
fn write_chunk_at(
    artifact_id: ArtifactId,
    path: &std::path::Path,
    offset: u64,
    data: &[u8],
    handles: &std::sync::Mutex<Option<OpenArtifactFile>>,
) -> Result<(), std::io::Error> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    let mut guard = handles
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Reuse the transfer's cached handle when the chunk belongs to the same
    // artifact; a chunk of another artifact replaces the slot (the taken
    // `Option` value is dropped right there, closing the previous file), so
    // the open-file count stays bounded at one. A failed open leaves the
    // slot empty and the next chunk retries.
    if guard
        .as_ref()
        .is_none_or(|open| open.artifact_id != artifact_id)
    {
        *guard = None;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        *guard = Some(OpenArtifactFile { artifact_id, file });
    }
    let open = guard
        .as_mut()
        .ok_or_else(|| std::io::Error::other("the artifact file handle is not cached"))?;
    open.file.seek(SeekFrom::Start(offset))?;
    open.file.write_all(data)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use rutilus_center_protocol::{
        ArtifactChunk, ArtifactManifest, EndpointSnapshot, EventBatch, EventRecord,
        EventSeverity as WireEventSeverity, ResourceDelta, ResourceDeltaOp, ResourceSummary,
        TlsTrust,
    };
    use rutilus_domain::{
        Artifact, ArtifactId, ArtifactState, EndpointId, Event, EventId, EventSeverity, InstanceId,
        MessageId, SyncCursor, SyncCursorId, SyncStream,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::center::session::ResolvedSite;

    /// A store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    struct MockStoreError;

    /// The shared state of the mock projection store, so the test can keep
    /// one handle while the use case owns another.
    #[derive(Clone)]
    struct MockProjectionState {
        endpoints: Arc<Mutex<Vec<EndpointProjectionWrite>>>,
        deleted_endpoints: Arc<Mutex<Vec<EndpointId>>>,
        resources: Arc<Mutex<Vec<ResourceProjectionWrite>>>,
        deleted_resources: Arc<Mutex<Vec<(EndpointId, String)>>>,
        events: Arc<Mutex<Vec<Event>>>,
        artifacts: Arc<Mutex<HashMap<ArtifactId, Artifact>>>,
        endpoint_owners: Arc<Mutex<HashMap<EndpointId, InstanceId>>>,
        artifact_sites: Arc<Mutex<HashMap<ArtifactId, InstanceId>>>,
        artifact_dir: Arc<Mutex<Option<tempfile::TempDir>>>,
        /// How many batch ownership preloads (`find_endpoint_projections`)
        /// the batch consumer issued, so a test can pin the one-preload
        /// restructure of `consume_event_batch`.
        endpoint_ownership_preloads: Arc<Mutex<usize>>,
        /// How many batch writes (`upsert_events`) the batch consumer
        /// issued, so a test can pin the one-write restructure.
        event_batch_writes: Arc<Mutex<usize>>,
    }

    impl MockProjectionState {
        fn new() -> Self {
            Self {
                endpoints: Arc::new(Mutex::new(Vec::new())),
                deleted_endpoints: Arc::new(Mutex::new(Vec::new())),
                resources: Arc::new(Mutex::new(Vec::new())),
                deleted_resources: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
                artifacts: Arc::new(Mutex::new(HashMap::new())),
                endpoint_owners: Arc::new(Mutex::new(HashMap::new())),
                artifact_sites: Arc::new(Mutex::new(HashMap::new())),
                artifact_dir: Arc::new(Mutex::new(None)),
                endpoint_ownership_preloads: Arc::new(Mutex::new(0)),
                event_batch_writes: Arc::new(Mutex::new(0)),
            }
        }

        /// How many batch ownership preloads the consumer issued.
        fn endpoint_ownership_preloads(&self) -> usize {
            self.endpoint_ownership_preloads
                .lock()
                .map(|calls| *calls)
                .unwrap_or_default()
        }

        /// How many batch event writes the consumer issued.
        fn event_batch_writes(&self) -> usize {
            self.event_batch_writes
                .lock()
                .map(|calls| *calls)
                .unwrap_or_default()
        }

        /// Registers `endpoint_id` as a projection owned by `site`, so the
        /// event attribution check sees it.
        fn claim_endpoint(&self, endpoint_id: EndpointId, site: InstanceId) {
            self.endpoint_owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(endpoint_id, site);
        }

        fn endpoints_owned(&self) -> Vec<EndpointProjectionWrite> {
            self.endpoints
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn resources_owned(&self) -> Vec<ResourceProjectionWrite> {
            self.resources
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn events_owned(&self) -> Vec<Event> {
            self.events
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn deleted_endpoints_owned(&self) -> Vec<EndpointId> {
            self.deleted_endpoints
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn deleted_resources_owned(&self) -> Vec<(EndpointId, String)> {
            self.deleted_resources
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn find_artifact_owned(&self, artifact_id: ArtifactId) -> Option<Artifact> {
            self.artifacts
                .lock()
                .map(|rows| rows.get(&artifact_id).cloned())
                .unwrap_or_default()
        }

        fn artifact_bytes(&self, artifact_id: ArtifactId) -> Vec<u8> {
            let directory = self
                .artifact_dir
                .lock()
                .map(|dir| dir.as_ref().map(|dir| dir.path().to_path_buf()))
                .unwrap_or_default();
            directory
                .map(|path| std::fs::read(path.join(artifact_id.to_string())).unwrap_or_default())
                .unwrap_or_default()
        }
    }

    #[derive(Clone)]
    struct MockProjectionStore {
        state: MockProjectionState,
    }

    impl MockProjectionStore {
        fn new() -> (Self, MockProjectionState) {
            let state = MockProjectionState::new();
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }

        fn artifact_file_path_internal(&self, artifact_id: ArtifactId) -> PathBuf {
            let mut guard = self
                .state
                .artifact_dir
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.is_none() {
                *guard = tempfile::tempdir().ok();
            }
            guard
                .as_ref()
                .map(|dir| dir.path().join(artifact_id.to_string()))
                .unwrap_or_default()
        }
    }

    impl CenterProjectionRepository for MockProjectionStore {
        type Error = MockStoreError;

        fn upsert_endpoint<'a>(
            &'a self,
            projection: &'a EndpointProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move {
                self.state
                    .endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(projection.clone());
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn delete_endpoint(
            &self,
            endpoint_id: EndpointId,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move {
                self.state
                    .deleted_endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(endpoint_id);
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn upsert_resource<'a>(
            &'a self,
            projection: &'a ResourceProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move {
                self.state
                    .resources
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(projection.clone());
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn delete_resource(
            &self,
            endpoint_id: EndpointId,
            odata_id: &str,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            let odata_id = odata_id.to_owned();
            Box::pin(async move {
                self.state
                    .deleted_resources
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push((endpoint_id, odata_id));
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn upsert_event<'a>(
            &'a self,
            event: &'a Event,
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.state
                    .events
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(event.clone());
                Ok(())
            })
        }

        fn declare_artifact<'a>(
            &'a self,
            artifact: &'a Artifact,
            site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.state
                    .artifacts
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(artifact.id(), artifact.clone());
                self.state
                    .artifact_sites
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(artifact.id(), site);
                Ok(())
            })
        }

        fn find_artifact_site(
            &self,
            artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<InstanceId>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .artifact_sites
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&artifact_id)
                    .copied())
            })
        }

        fn find_endpoint_projection(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<CenterEndpointProjection>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .endpoint_owners
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&endpoint_id)
                    .copied()
                    .map(|site| CenterEndpointProjection::new(endpoint_id, Some(site))))
            })
        }

        fn has_resource(
            &self,
            _endpoint_id: EndpointId,
            _odata_id: &str,
        ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
            Box::pin(async move { Ok(false) })
        }

        fn find_endpoint_projections<'a>(
            &'a self,
            endpoint_ids: &'a [EndpointId],
        ) -> BoundaryFuture<'a, Result<HashMap<EndpointId, CenterEndpointProjection>, Self::Error>>
        {
            let endpoint_ids = endpoint_ids.to_vec();
            Box::pin(async move {
                *self
                    .state
                    .endpoint_ownership_preloads
                    .lock()
                    .map_err(|_| MockStoreError)? += 1;
                let owners = self
                    .state
                    .endpoint_owners
                    .lock()
                    .map_err(|_| MockStoreError)?;
                Ok(endpoint_ids
                    .into_iter()
                    .filter_map(|endpoint_id| {
                        owners.get(&endpoint_id).copied().map(|site| {
                            (
                                endpoint_id,
                                CenterEndpointProjection::new(endpoint_id, Some(site)),
                            )
                        })
                    })
                    .collect())
            })
        }

        fn upsert_events<'a>(
            &'a self,
            events: &'a [Event],
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                *self
                    .state
                    .event_batch_writes
                    .lock()
                    .map_err(|_| MockStoreError)? += 1;
                let mut stored = self.state.events.lock().map_err(|_| MockStoreError)?;
                stored.extend(events.iter().cloned());
                Ok(())
            })
        }
    }

    impl ArtifactRepository for MockProjectionStore {
        type Error = MockStoreError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact(
            &self,
            artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .artifacts
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&artifact_id)
                    .cloned())
            })
        }

        fn list_artifacts_by_state(
            &self,
            _state: ArtifactState,
        ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn update_artifact(
            &self,
            artifact_id: ArtifactId,
            uploaded_bytes: u64,
            state: ArtifactState,
            occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.state.artifacts.lock().map_err(|_| MockStoreError)?;
                let stored = rows.get(&artifact_id).ok_or(MockStoreError)?.clone();
                let updated = Artifact::try_from_parts(
                    stored.id(),
                    stored.name().clone(),
                    stored.size_bytes(),
                    stored.sha256(),
                    state,
                    uploaded_bytes,
                    stored.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockStoreError)?;
                rows.insert(artifact_id, updated);
                Ok(())
            })
        }

        fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
            self.artifact_file_path_internal(artifact_id)
        }
    }

    /// An in-memory cursor store behind the projection boundary.
    #[derive(Clone)]
    struct MockCursor {
        cursors: Arc<Mutex<HashMap<SyncStream, u64>>>,
    }

    impl MockCursor {
        fn new() -> Self {
            Self {
                cursors: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl CenterCursor for MockCursor {
        type Error = MockStoreError;

        fn get(
            &self,
            _instance_id: InstanceId,
            stream: SyncStream,
        ) -> BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&stream)
                    .map(|sequence| {
                        SyncCursor::new(
                            SyncCursorId::generate(),
                            InstanceId::generate(),
                            stream,
                            sequence.to_string(),
                            OffsetDateTime::UNIX_EPOCH,
                        )
                    }))
            })
        }

        fn set<'a>(
            &'a self,
            cursor: &'a SyncCursor,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let sequence = cursor
                    .cursor_value()
                    .parse::<u64>()
                    .map_err(|_| MockStoreError)?;
                self.cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(cursor.stream(), sequence);
                Ok(())
            })
        }
    }

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn resolved_site() -> ResolvedSite {
        ResolvedSite::new(
            InstanceId::generate(),
            rutilus_domain::CenterBindingId::generate(),
            rutilus_domain::CertificateFingerprint::from_bytes([0x42; 32]),
        )
    }

    fn endpoint_snapshot(endpoint_id: &EndpointId) -> EndpointSnapshot {
        EndpointSnapshot {
            endpoint_id: endpoint_id.to_string(),
            display_name: String::from("Rack A PDU"),
            address: String::from("https://192.0.2.10"),
            trust: TlsTrust::PinnedCertificate as i32,
            refresh_generation: 3,
            resources: Vec::new(),
            health: String::from("ok"),
        }
    }

    fn resource_delta(endpoint_id: &EndpointId, generation: u64) -> ResourceDelta {
        ResourceDelta {
            endpoint_id: endpoint_id.to_string(),
            op: ResourceDeltaOp::Upsert as i32,
            resource: Some(ResourceSummary {
                feature: String::from("power"),
                odata_id: String::from("/redfish/v1/Power"),
                odata_type: String::from("#Power.v1_6_1.Power"),
                etag: String::from("\"abc\""),
                generation,
            }),
            payload_json: b"{\"power\":\"on\"}".to_vec(),
            observed_at_unix: 1_700_000_010,
        }
    }

    /// One event record of the given endpoint, observed at
    /// `occurred_at_unix`.
    fn event_record(endpoint_id: &EndpointId, occurred_at_unix: i64) -> EventRecord {
        EventRecord {
            event_id: EventId::generate().to_string(),
            message_id: String::from("ResourceEvent.1.0.ResourceUpdated"),
            severity: WireEventSeverity::Warning as i32,
            target: String::new(),
            occurred_at_unix,
            payload_json: Vec::new(),
            endpoint_id: endpoint_id.to_string(),
        }
    }

    /// One chunk frame of an artifact.
    fn chunk_frame(artifact_id: ArtifactId, index: u32, data: Vec<u8>) -> EnvelopeMessage {
        EnvelopeMessage::ArtifactChunk(ArtifactChunk {
            artifact_id: artifact_id.to_string(),
            index,
            data,
        })
    }

    /// An artifact payload in the standard wire shape: two full transfer
    /// chunks plus a short final chunk, so every chunk-index position
    /// (full, full, partial) is exercised.
    fn chunked_payload() -> Vec<u8> {
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(chunk_size * 2 + 5);
        for index in 0..(chunk_size * 2 + 5) {
            bytes.push(u8::try_from(index % 251).unwrap_or(0));
        }
        bytes
    }

    /// Declares one artifact of `bytes` under the site, returning its id.
    async fn declare_artifact(
        projection: &CenterProjection<MockProjectionStore, MockCursor>,
        site: &ResolvedSite,
        name: &str,
        bytes: &[u8],
        digest: [u8; 32],
        now: OffsetDateTime,
    ) -> Result<ArtifactId, Box<dyn Error>> {
        let artifact_id = ArtifactId::generate();
        projection
            .on_frame(
                site,
                1,
                &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: artifact_id.to_string(),
                    name: String::from(name),
                    total_bytes: bytes.len() as u64,
                    sha256: digest.to_vec(),
                }),
                now,
            )
            .await?;
        Ok(artifact_id)
    }

    #[tokio::test]
    async fn an_over_cap_manifest_is_absorbed_without_a_row() -> Result<(), Box<dyn Error>> {
        // S1: the center enforces the site-side declared-total cap at the
        // manifest decode, so a trusted site can never declare an artifact
        // that fills the center's disk past `ARTIFACT_MAX_SIZE_BYTES`. The
        // over-cap declaration follows the same absorb-skip-warn handling
        // as every other undecodable manifest (the protocol stream has no
        // HTTP status to answer with): the frame is absorbed, the cursor
        // advances, and no row — and therefore no `Uploading` file slot —
        // is ever created for the identity.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let artifact_id = ArtifactId::generate();

        projection
            .on_frame(
                &site,
                1,
                &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: artifact_id.to_string(),
                    name: String::from("firmware.bin"),
                    total_bytes: ARTIFACT_MAX_SIZE_BYTES + 1,
                    sha256: [0x5a; 32].to_vec(),
                }),
                now,
            )
            .await?;

        assert!(
            state.find_artifact_owned(artifact_id).is_none(),
            "an over-cap declaration must leave no artifact row"
        );
        assert!(
            state.artifact_bytes(artifact_id).is_empty(),
            "an over-cap declaration must never touch a file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_exactly_cap_manifest_is_accepted() -> Result<(), Box<dyn Error>> {
        // S1 boundary: a declaration at exactly `ARTIFACT_MAX_SIZE_BYTES`
        // decodes, exactly like the site-side `create` cap. The chunk path
        // then bounds the accumulated bytes by the declared size (`end <=
        // artifact.size_bytes()`), so a transfer can never accumulate past
        // the capped total — the over-declared chunk absorption is pinned
        // by `out_of_order_chunks_are_absorbed_without_touching_the_file`.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let artifact_id = ArtifactId::generate();

        projection
            .on_frame(
                &site,
                1,
                &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: artifact_id.to_string(),
                    name: String::from("firmware.bin"),
                    total_bytes: ARTIFACT_MAX_SIZE_BYTES,
                    sha256: [0x5a; 32].to_vec(),
                }),
                now,
            )
            .await?;

        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.size_bytes(), ARTIFACT_MAX_SIZE_BYTES);
        assert_eq!(stored.state(), ArtifactState::Uploading);
        assert_eq!(stored.uploaded_bytes(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_snapshots_and_resource_deltas_project_and_the_cursor_advances()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        let now = base_time();

        projection
            .on_frame(
                &site,
                1,
                &EnvelopeMessage::EndpointSnapshot(endpoint_snapshot(&endpoint_id)),
                now,
            )
            .await?;
        projection
            .on_frame(
                &site,
                2,
                &EnvelopeMessage::ResourceDelta(resource_delta(&endpoint_id, 4)),
                now,
            )
            .await?;

        let endpoints = state.endpoints_owned();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].endpoint_id(), endpoint_id);
        assert_eq!(endpoints[0].display_name(), "Rack A PDU");
        assert_eq!(endpoints[0].address(), "https://192.0.2.10");
        assert_eq!(
            endpoints[0].trust_mode(),
            CenterTrustMode::PinnedCertificate
        );
        assert_eq!(endpoints[0].refresh_generation(), 3);
        assert_eq!(endpoints[0].health(), "ok");

        let resources = state.resources_owned();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].endpoint_id(), endpoint_id);
        assert_eq!(resources[0].odata_id(), "/redfish/v1/Power");
        assert_eq!(resources[0].feature().as_str(), "power");
        assert_eq!(resources[0].generation(), 4);
        assert_eq!(resources[0].payload(), Some("{\"power\":\"on\"}"));
        assert_eq!(
            resources[0].observed_at(),
            OffsetDateTime::from_unix_timestamp(1_700_000_010)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        );

        // The endpoint stream cursor covers the second frame.
        let stored = cursor
            .get(site.instance_id(), SyncStream::Endpoint)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "2");
        Ok(())
    }

    #[tokio::test]
    async fn delete_deltas_make_the_projection_converge() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        let now = base_time();

        // The §21 endpoint-level delete: the whole projection goes away.
        projection
            .on_frame(
                &site,
                1,
                &EnvelopeMessage::ResourceDelta(ResourceDelta {
                    endpoint_id: endpoint_id.to_string(),
                    op: ResourceDeltaOp::Delete as i32,
                    resource: None,
                    payload_json: Vec::new(),
                    observed_at_unix: 0,
                }),
                now,
            )
            .await?;
        assert_eq!(state.deleted_endpoints_owned(), vec![endpoint_id]);

        // A resource-level delete removes exactly that resource.
        projection
            .on_frame(
                &site,
                2,
                &EnvelopeMessage::ResourceDelta(ResourceDelta {
                    endpoint_id: endpoint_id.to_string(),
                    op: ResourceDeltaOp::Delete as i32,
                    resource: Some(ResourceSummary {
                        feature: String::from("power"),
                        odata_id: String::from("/redfish/v1/Power"),
                        odata_type: String::new(),
                        etag: String::new(),
                        generation: 0,
                    }),
                    payload_json: Vec::new(),
                    observed_at_unix: 0,
                }),
                now,
            )
            .await?;
        assert_eq!(
            state.deleted_resources_owned(),
            vec![(endpoint_id, String::from("/redfish/v1/Power"))]
        );
        Ok(())
    }

    #[tokio::test]
    async fn re_delivered_frames_are_skipped_by_the_stream_cursor() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        let now = base_time();

        projection
            .on_frame(
                &site,
                7,
                &EnvelopeMessage::EndpointSnapshot(endpoint_snapshot(&endpoint_id)),
                now,
            )
            .await?;
        // The at-least-once re-delivery of the same frame (its ack was
        // lost) is skipped: the cursor already covers sequence 7.
        projection
            .on_frame(
                &site,
                7,
                &EnvelopeMessage::EndpointSnapshot(endpoint_snapshot(&endpoint_id)),
                now,
            )
            .await?;
        assert_eq!(state.endpoints_owned().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn event_batches_append_with_the_site_and_skip_undecodable_records()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        let now = base_time();
        state.claim_endpoint(endpoint_id, site.instance_id());

        let batch = EventBatch {
            events: vec![
                EventRecord {
                    event_id: EventId::generate().to_string(),
                    message_id: String::from("ResourceEvent.1.0.ResourceUpdated"),
                    severity: WireEventSeverity::Warning as i32,
                    target: String::new(),
                    occurred_at_unix: 1_699_999_990,
                    payload_json: Vec::new(),
                    endpoint_id: endpoint_id.to_string(),
                },
                // A record with an unparseable event id is logged and
                // skipped without failing the batch.
                EventRecord {
                    event_id: String::from("not-a-uuid"),
                    message_id: String::from("ResourceEvent.1.0.ResourceUpdated"),
                    severity: WireEventSeverity::Ok as i32,
                    target: String::new(),
                    occurred_at_unix: 1_699_999_991,
                    payload_json: Vec::new(),
                    endpoint_id: endpoint_id.to_string(),
                },
            ],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        let events = state.events_owned();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint_id(), endpoint_id);
        assert_eq!(events[0].severity(), EventSeverity::Warning);
        assert_eq!(
            events[0].message_id(),
            &MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?
        );
        assert_eq!(events[0].event_timestamp().unix_timestamp(), 1_699_999_990);
        assert_eq!(events[0].observed_at(), now);
        // The batch was consumed as a unit: one ownership preload and one
        // batch write for the whole batch.
        assert_eq!(state.endpoint_ownership_preloads(), 1);
        assert_eq!(state.event_batch_writes(), 1);
        // The event stream cursor advanced past the batch.
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }

    #[tokio::test]
    async fn artifacts_assemble_from_manifest_and_chunks_and_verify_the_digest()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let bytes = chunked_payload();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let artifact_id =
            declare_artifact(&projection, &site, "firmware.bin", &bytes, digest, now).await?;

        let declared = state
            .find_artifact_owned(artifact_id)
            .ok_or("the manifest was not declared")?;
        assert_eq!(declared.name().as_str(), "firmware.bin");
        assert_eq!(declared.state(), ArtifactState::Uploading);

        // The chunks land at the exact offsets their indexes position: the
        // site chunks at the standard transfer size, so index `i` owns the
        // `[i * chunk_size, i * chunk_size + len)` range of the file.
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE)?;
        for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
            projection
                .on_frame(
                    &site,
                    2 + index as u64,
                    &chunk_frame(
                        artifact_id,
                        u32::try_from(index).unwrap_or(u32::MAX),
                        chunk.to_vec(),
                    ),
                    now + Duration::SECOND,
                )
                .await?;
        }
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Ready);
        assert_eq!(stored.uploaded_bytes(), bytes.len() as u64);
        assert_eq!(state.artifact_bytes(artifact_id), bytes);
        Ok(())
    }

    #[tokio::test]
    async fn a_digest_mismatch_marks_the_artifact_failed() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let artifact_id = ArtifactId::generate();
        let bytes = b"firmware-bytes".to_vec();
        let wrong_digest = [0x5a; 32];

        projection
            .on_frame(
                &site,
                1,
                &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: artifact_id.to_string(),
                    name: String::from("firmware.bin"),
                    total_bytes: bytes.len() as u64,
                    sha256: wrong_digest.to_vec(),
                }),
                now,
            )
            .await?;
        projection
            .on_frame(
                &site,
                2,
                &EnvelopeMessage::ArtifactChunk(ArtifactChunk {
                    artifact_id: artifact_id.to_string(),
                    index: 0,
                    data: bytes,
                }),
                now + Duration::SECOND,
            )
            .await?;
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(
            stored.state(),
            ArtifactState::Failed,
            "a digest mismatch is a failed artifact, never a silently corrupt file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn re_delivered_chunks_land_on_the_same_bytes_and_never_duplicate()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let now = base_time();
        let bytes = chunked_payload();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let artifact_id =
            declare_artifact(&projection, &site, "firmware.bin", &bytes, digest, now).await?;

        // Each chunk is delivered, then — with the stream cursor rewound
        // below the frame's sequence, exactly as a crash between the row
        // update and the cursor write leaves it (W2) — re-delivered with
        // the same outbox sequence. The re-delivered chunk must land on the
        // same bytes (never appended a second time), and the transfer must
        // still finish Ready with the exact declared content.
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE)?;
        for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
            let sequence = 2 + index as u64;
            let frame = chunk_frame(
                artifact_id,
                u32::try_from(index).unwrap_or(u32::MAX),
                chunk.to_vec(),
            );
            projection
                .on_frame(&site, sequence, &frame, now + Duration::SECOND)
                .await?;
            cursor
                .cursors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(SyncStream::Artifact, 1);
            projection
                .on_frame(&site, sequence, &frame, now + Duration::SECOND)
                .await?;
        }

        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Ready);
        assert_eq!(stored.uploaded_bytes(), bytes.len() as u64);
        assert_eq!(
            state.artifact_bytes(artifact_id),
            bytes,
            "a re-delivered chunk must land on the same bytes, never a duplicate"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_chunk_write_without_its_row_update_is_healed_by_the_redelivery()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let now = base_time();
        let bytes = chunked_payload();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let artifact_id =
            declare_artifact(&projection, &site, "firmware.bin", &bytes, digest, now).await?;

        // Chunk 0 lands on the file, but the row update is lost — the W1
        // crash state, where the file runs ahead of the persisted progress.
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE)?;
        let first = chunk_frame(artifact_id, 0, bytes[..chunk_size].to_vec());
        projection
            .on_frame(&site, 2, &first, now + Duration::SECOND)
            .await?;
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        let rolled_back = Artifact::try_from_parts(
            stored.id(),
            stored.name().clone(),
            stored.size_bytes(),
            stored.sha256(),
            ArtifactState::Uploading,
            0,
            stored.created_at(),
            stored.updated_at(),
        )
        .map_err(|_| std::io::Error::other("the row cannot be rolled back"))?;
        state
            .artifacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(artifact_id, rolled_back);
        // The W1 crash that lost the row update lost the cursor write too —
        // both follow the file write — so the stream cursor is rolled back
        // with the row, and the re-delivered chunk is new again for the
        // projection (§15.4 at-least-once: the site re-sends from its last
        // acknowledged sequence).
        cursor
            .cursors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(SyncStream::Artifact, 1);

        // The re-delivered chunk overwrites exactly its own range: the file
        // must not grow a second copy of the chunk.
        projection
            .on_frame(&site, 2, &first, now + Duration::SECOND)
            .await?;
        assert_eq!(
            state.artifact_bytes(artifact_id),
            bytes[..chunk_size],
            "the redelivery must rewrite the same range, not append a duplicate"
        );

        // The rest of the transfer completes normally and verifies.
        for (index, chunk) in bytes.chunks(chunk_size).enumerate().skip(1) {
            projection
                .on_frame(
                    &site,
                    3 + index as u64,
                    &chunk_frame(
                        artifact_id,
                        u32::try_from(index).unwrap_or(u32::MAX),
                        chunk.to_vec(),
                    ),
                    now + Duration::SECOND,
                )
                .await?;
        }
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Ready);
        assert_eq!(state.artifact_bytes(artifact_id), bytes);
        Ok(())
    }

    #[tokio::test]
    async fn out_of_order_chunks_are_absorbed_without_touching_the_file()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let bytes = chunked_payload();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let artifact_id =
            declare_artifact(&projection, &site, "firmware.bin", &bytes, digest, now).await?;
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE)?;

        // Chunk 1 before chunk 0: its range lies beyond the persisted
        // progress, so it is absorbed with a log and the cursor advances;
        // the file is never touched.
        projection
            .on_frame(
                &site,
                2,
                &chunk_frame(artifact_id, 1, bytes[chunk_size..chunk_size * 2].to_vec()),
                now + Duration::SECOND,
            )
            .await?;
        assert!(
            state.artifact_bytes(artifact_id).is_empty(),
            "an out-of-order chunk must not create the file"
        );
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.uploaded_bytes(), 0);

        // A chunk whose range exceeds the declared size is absorbed by the
        // declared size check, whatever its index.
        projection
            .on_frame(
                &site,
                3,
                &chunk_frame(artifact_id, 0, vec![0x5a; bytes.len() + 1]),
                now + Duration::SECOND,
            )
            .await?;
        assert!(state.artifact_bytes(artifact_id).is_empty());

        // The in-order transfer still completes.
        for (index, chunk) in bytes.chunks(chunk_size).enumerate() {
            projection
                .on_frame(
                    &site,
                    4 + index as u64,
                    &chunk_frame(
                        artifact_id,
                        u32::try_from(index).unwrap_or(u32::MAX),
                        chunk.to_vec(),
                    ),
                    now + Duration::SECOND,
                )
                .await?;
        }
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Ready);
        assert_eq!(state.artifact_bytes(artifact_id), bytes);
        Ok(())
    }

    #[tokio::test]
    async fn chunks_for_an_artifact_of_another_site_are_absorbed() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let other_site = resolved_site();
        let now = base_time();
        let bytes = b"firmware-bytes".to_vec();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let artifact_id =
            declare_artifact(&projection, &site, "firmware.bin", &bytes, digest, now).await?;

        // A different site's chunk for the artifact is absorbed: the row
        // names the declaring site, and only that site may add bytes to it.
        projection
            .on_frame(
                &other_site,
                2,
                &chunk_frame(artifact_id, 0, bytes.clone()),
                now + Duration::SECOND,
            )
            .await?;
        assert!(
            state.artifact_bytes(artifact_id).is_empty(),
            "a cross-site chunk must not touch the file"
        );
        let stored = state
            .find_artifact_owned(artifact_id)
            .ok_or("the artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Uploading);
        assert_eq!(stored.uploaded_bytes(), 0);

        // The owning site's chunk still lands.
        projection
            .on_frame(
                &site,
                3,
                &chunk_frame(artifact_id, 0, bytes),
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(state.artifact_bytes(artifact_id), b"firmware-bytes");
        Ok(())
    }

    #[tokio::test]
    async fn interleaved_artifact_transfers_never_mix_their_bytes() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let now = base_time();
        let bytes = chunked_payload();
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        let mut second_bytes = chunked_payload();
        second_bytes[0] ^= 0xFF;
        let second_digest: [u8; 32] = sha2::Sha256::digest(&second_bytes).into();

        // Two manifests on their own sequences — a shared sequence would be
        // skipped as already processed. The first transfer reuses the
        // declare helper's sequence 1; the second is declared on sequence 2.
        let first_id =
            declare_artifact(&projection, &site, "first.bin", &bytes, digest, now).await?;
        let second_id = ArtifactId::generate();
        projection
            .on_frame(
                &site,
                2,
                &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: second_id.to_string(),
                    name: String::from("second.bin"),
                    total_bytes: second_bytes.len() as u64,
                    sha256: second_digest.to_vec(),
                }),
                now,
            )
            .await?;

        // The two transfers' chunks alternate, exactly as two artifacts
        // interleave on the wire. The single-slot file handle is evicted
        // and re-opened per transfer; each file must still end with exactly
        // its own bytes and its own digest verification.
        let chunk_size = usize::try_from(CENTER_ARTIFACT_CHUNK_SIZE)?;
        let mut sequence = 3;
        for (index, (first_chunk, second_chunk)) in bytes
            .chunks(chunk_size)
            .zip(second_bytes.chunks(chunk_size))
            .enumerate()
        {
            for (artifact_id, payload) in [(first_id, first_chunk), (second_id, second_chunk)] {
                projection
                    .on_frame(
                        &site,
                        sequence,
                        &chunk_frame(
                            artifact_id,
                            u32::try_from(index).unwrap_or(u32::MAX),
                            payload.to_vec(),
                        ),
                        now + Duration::SECOND,
                    )
                    .await?;
                sequence += 1;
            }
        }

        for artifact_id in [first_id, second_id] {
            let stored = state
                .find_artifact_owned(artifact_id)
                .ok_or("the artifact is missing")?;
            assert_eq!(stored.state(), ArtifactState::Ready);
            assert_eq!(stored.uploaded_bytes(), bytes.len() as u64);
        }
        assert_eq!(
            state.artifact_bytes(first_id),
            bytes,
            "the first transfer must land on its own file"
        );
        assert_eq!(
            state.artifact_bytes(second_id),
            second_bytes,
            "the second transfer must land on its own file"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_future_event_timestamp_is_refused_and_never_clamped() -> Result<(), Box<dyn Error>> {
        // V5C-6: the center records the two clocks truthfully — `observed_at`
        // is the receive time, the BMC timestamp stays in `event_timestamp` —
        // so a record whose BMC timestamp runs after the receive time is
        // refused by the domain timeline invariant, exactly as the site side
        // refuses the same record at ingestion. The center must never clamp
        // the receive time up to the event's clock: that would record a lie
        // in the timeline the dedup key and the recent listing order by.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        state.claim_endpoint(endpoint_id, site.instance_id());
        let now = base_time();

        // The record's BMC timestamp runs 30 seconds after the receive time.
        let batch = EventBatch {
            events: vec![event_record(&endpoint_id, now.unix_timestamp() + 30)],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        // The record is refused and logged honestly; the batch cursor
        // advances, so the mis-clocked record cannot wedge the stream.
        assert_eq!(state.events_owned().len(), 0);
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }

    #[tokio::test]
    async fn observed_at_is_the_receive_time_never_the_event_time() -> Result<(), Box<dyn Error>> {
        // V5C-6: the persisted record keeps the two clocks separate — the
        // BMC's own timestamp in `event_timestamp` and the center's receive
        // time in `observed_at` — so a viewer compares them directly, like
        // the site side's records.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor);
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        state.claim_endpoint(endpoint_id, site.instance_id());
        let now = base_time();

        // The BMC clock runs 90 seconds behind the center's clock; the
        // record arrives at `now`.
        let batch = EventBatch {
            events: vec![event_record(&endpoint_id, now.unix_timestamp() - 90)],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        let events = state.events_owned();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint_id(), endpoint_id);
        assert_eq!(
            events[0].event_timestamp().unix_timestamp(),
            now.unix_timestamp() - 90,
            "the BMC's own timestamp stays in event_timestamp"
        );
        assert_eq!(
            events[0].observed_at().unix_timestamp(),
            now.unix_timestamp(),
            "observed_at is the receive time, never the event time"
        );
        Ok(())
    }

    #[tokio::test]
    async fn event_timestamps_beyond_the_clock_tolerance_are_skipped() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        state.claim_endpoint(endpoint_id, site.instance_id());
        let now = base_time();

        // A timestamp five minutes ahead of the center's clock is beyond
        // the tolerance: the record is rejected and logged honestly, and —
        // per the existing decode-failure classification — the batch cursor
        // still advances, so a permanently mis-clocked site cannot wedge
        // the event stream behind it.
        let batch = EventBatch {
            events: vec![event_record(&endpoint_id, now.unix_timestamp() + 300)],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        assert_eq!(state.events_owned().len(), 0);
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }

    #[tokio::test]
    async fn event_batches_reject_endpoints_the_site_does_not_own() -> Result<(), Box<dyn Error>> {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let other_site = resolved_site();
        let now = base_time();
        let owned = EndpointId::generate();
        let foreign = EndpointId::generate();
        let unknown = EndpointId::generate();
        state.claim_endpoint(owned, site.instance_id());
        state.claim_endpoint(foreign, other_site.instance_id());

        let batch = EventBatch {
            events: vec![
                event_record(&owned, now.unix_timestamp() - 10),
                event_record(&foreign, now.unix_timestamp() - 10),
                event_record(&unknown, now.unix_timestamp() - 10),
            ],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        // Only the endpoint the reporting site owns is stored as a real
        // event; the foreign and unknown records are refused for the
        // projection — one site can never plant an event under another
        // site's endpoint — and reflected as durable dead-letter rows
        // (V5E-3) instead of vanishing. The whole batch was one ownership
        // preload (the three distinct endpoints) and one batch write.
        let events = state.events_owned();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].endpoint_id(), owned);
        let dead_letters = events
            .iter()
            .filter(|event| event.message_id().as_str() == CENTER_ABSORBED_EVENT_MESSAGE_ID)
            .collect::<Vec<_>>();
        assert_eq!(dead_letters.len(), 2);
        assert_eq!(
            dead_letters[0].endpoint_id(),
            foreign,
            "the dead-letter names the absorbed record's endpoint"
        );
        assert_eq!(
            dead_letters[1].endpoint_id(),
            unknown,
            "the dead-letter names the absorbed record's endpoint"
        );
        assert_eq!(state.endpoint_ownership_preloads(), 1);
        assert_eq!(state.event_batch_writes(), 1);
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }

    #[tokio::test]
    async fn ownership_absorbed_records_land_durable_dead_letter_rows() -> Result<(), Box<dyn Error>>
    {
        // V5E-3: an absorption is never silently lost. Before the cursor
        // advances, each ownership-absorbed record is reflected as a
        // dead-letter event row under the reserved message id that keeps
        // every identifying fact — the endpoint, the original message id,
        // the BMC timestamp, and the receive time — plus the absorption
        // reason. The alternative of delaying the cursor to re-deliver the
        // batch is rejected: the absorption is permanent (the endpoint
        // belongs to another site, or the center no longer projects it), so
        // the re-delivery would wedge the site's event stream forever at
        // the cost of every later legitimate event.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let other_site = resolved_site();
        let now = base_time();
        let foreign = EndpointId::generate();
        let unknown = EndpointId::generate();
        state.claim_endpoint(foreign, other_site.instance_id());
        let foreign_timestamp = now.unix_timestamp() - 20;
        let unknown_timestamp = now.unix_timestamp() - 40;

        let batch = EventBatch {
            events: vec![
                event_record(&foreign, foreign_timestamp),
                event_record(&unknown, unknown_timestamp),
            ],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        let events = state.events_owned();
        assert_eq!(
            events.len(),
            2,
            "both absorbed records land as dead-letters"
        );
        let foreign_letter = events
            .iter()
            .find(|event| event.endpoint_id() == foreign)
            .ok_or("the foreign record's dead-letter is missing")?;
        assert_eq!(
            foreign_letter.message_id().as_str(),
            CENTER_ABSORBED_EVENT_MESSAGE_ID
        );
        assert_eq!(foreign_letter.severity(), EventSeverity::Warning);
        assert_eq!(
            foreign_letter.event_timestamp().unix_timestamp(),
            foreign_timestamp,
            "the dead-letter keeps the absorbed record's BMC timestamp"
        );
        assert_eq!(
            foreign_letter.observed_at().unix_timestamp(),
            now.unix_timestamp(),
            "the dead-letter keeps the receive time"
        );
        let message = foreign_letter
            .message()
            .ok_or("the dead-letter message is missing")?;
        assert!(
            message.contains("endpoint") && message.contains(&foreign.to_string()),
            "the dead-letter names the absorbed record's endpoint: {message}"
        );
        assert!(
            message.contains("ResourceEvent.1.0.ResourceUpdated"),
            "the dead-letter names the absorbed record's message id: {message}"
        );
        assert!(
            message.contains("the endpoint belongs to another site"),
            "the dead-letter names the absorption reason: {message}"
        );
        let unknown_letter = events
            .iter()
            .find(|event| event.endpoint_id() == unknown)
            .ok_or("the unknown record's dead-letter is missing")?;
        assert!(
            unknown_letter
                .message()
                .is_some_and(|message| message.contains("the endpoint is not projected")),
            "the dead-letter names the absorption reason"
        );
        // The absorbed records' original message ids never appear: the
        // events table holds the dead-letter reflections, not planted
        // events.
        assert!(
            events
                .iter()
                .all(|event| event.message_id().as_str() != "ResourceEvent.1.0.ResourceUpdated"),
            "the absorbed records' original message ids must not appear"
        );
        // The batch cursor still advances past the absorbed records.
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }

    #[tokio::test]
    async fn a_dead_letter_row_never_collides_with_the_original_records_dedup_key()
    -> Result<(), Box<dyn Error>> {
        // V5E-3: the dead-letter's dedup key is derived from the reserved
        // message id and the record's own timestamp, so it can never
        // suppress the original record: when the same BMC event is later
        // reported by its legitimate owner, it stores its own row beside
        // the dead-letter instead of being absorbed as a duplicate.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let other_site = resolved_site();
        let now = base_time();
        let foreign = EndpointId::generate();
        let occurred_at_unix = now.unix_timestamp() - 10;
        state.claim_endpoint(foreign, other_site.instance_id());

        // Site B's report of the foreign endpoint's event is absorbed as a
        // dead-letter row.
        projection
            .on_frame(
                &site,
                3,
                &EnvelopeMessage::EventBatch(EventBatch {
                    events: vec![event_record(&foreign, occurred_at_unix)],
                }),
                now,
            )
            .await?;
        // The endpoint's legitimate owner later reports the same event: the
        // row must land, not be suppressed by the dead-letter's dedup key.
        projection
            .on_frame(
                &other_site,
                4,
                &EnvelopeMessage::EventBatch(EventBatch {
                    events: vec![event_record(&foreign, occurred_at_unix)],
                }),
                now + Duration::SECOND,
            )
            .await?;

        let events = state.events_owned();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .any(|event| event.message_id().as_str() == CENTER_ABSORBED_EVENT_MESSAGE_ID),
            "the dead-letter row is stored"
        );
        assert!(
            events
                .iter()
                .any(|event| event.message_id().as_str() == "ResourceEvent.1.0.ResourceUpdated"),
            "the legitimate owner's report is stored beside the dead-letter"
        );
        Ok(())
    }

    #[tokio::test]
    async fn events_reporting_the_reserved_center_namespace_are_refused()
    -> Result<(), Box<dyn Error>> {
        // R6-D-7: the `Center.` message-id namespace is reserved for the
        // center's own dead-letter reflections — a site reporting an event
        // under the reserved prefix would spoof an internal administrative
        // row, and its dedup key could collide with a real dead-letter's.
        // The decode refuses the record like any other undecodable report:
        // logged and skipped once, the cursor advancing past it.
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let now = base_time();
        let owned = EndpointId::generate();
        state.claim_endpoint(owned, site.instance_id());

        let mut record = event_record(&owned, now.unix_timestamp() - 10);
        record.message_id = String::from("Center.1.0.EventAbsorbed");
        projection
            .on_frame(
                &site,
                3,
                &EnvelopeMessage::EventBatch(EventBatch {
                    events: vec![record],
                }),
                now,
            )
            .await?;

        assert!(
            state.events_owned().is_empty(),
            "a record under the reserved `Center.` namespace must not be stored"
        );
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }
}
