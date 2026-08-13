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
//! A site-reported event whose BMC timestamp runs ahead of the center's
//! clock by at most [`EVENT_TIMESTAMP_TOLERANCE`] is still accepted (the
//! recorded receive time is clamped to the event's own timestamp so the
//! persisted timeline never inverts); beyond that skew the record is
//! rejected and logged like any other undecodable record.
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

use std::error::Error;

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

use crate::{ArtifactRepository, BoundaryFuture, CenterCursor, center::session::ResolvedSite};

/// The clock skew a site-reported event may carry.
///
/// The site's clock (and the BMC clocks behind it) is not the center's
/// clock: a site whose clock runs ahead reports events whose BMC
/// timestamps lie in the center's near future. Without a tolerance those
/// events are rejected as undecodable and the batch cursor advances past
/// them — permanent loss. Sixty seconds is far beyond the skew of two
/// NTP-synced clocks (milliseconds) while still catching a genuinely
/// misconfigured clock.
const EVENT_TIMESTAMP_TOLERANCE: time::Duration = time::Duration::seconds(60);

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
    pub const fn new(store: Store, cursor: Cursor) -> Self {
        Self { store, cursor }
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
        for record in &batch.events {
            let event = match decode_event(record, now) {
                Err(reason) => {
                    tracing::error!(
                        "site {}: skipping event record {}: {reason}",
                        site.instance_id(),
                        record.event_id
                    );
                    continue;
                }
                Ok(event) => event,
            };
            // §14.4 记录事件来源 with the §15.5 site scope: the event's
            // endpoint must be a projection of the reporting site. A record
            // that names an unknown endpoint, or an endpoint of another
            // site, is logged and skipped exactly like an undecodable
            // record — one site can never plant an event under another
            // site's endpoint.
            match self
                .store
                .find_endpoint_projection(event.endpoint_id())
                .await
                .map_err(CenterProjectionError::Projection)?
            {
                Some(projection) if projection.site_id() == Some(site.instance_id()) => {
                    self.store
                        .upsert_event(&event, site.instance_id())
                        .await
                        .map_err(CenterProjectionError::Projection)?;
                }
                Some(_) => {
                    tracing::error!(
                        "site {}: skipping event record {}: the endpoint belongs to another site",
                        site.instance_id(),
                        record.event_id
                    );
                }
                None => {
                    tracing::error!(
                        "site {}: skipping event record {}: the endpoint is not projected",
                        site.instance_id(),
                        record.event_id
                    );
                }
            }
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
        tokio::task::spawn_blocking(move || write_chunk_at(&path, offset, &data))
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
        let bytes = tokio::task::spawn_blocking(move || std::fs::read(path))
            .await
            .map_err(|source| CenterProjectionError::ArtifactFile {
                artifact_id,
                source: std::io::Error::other(source.to_string()),
            })?
            .map_err(|source| CenterProjectionError::ArtifactFile {
                artifact_id,
                source,
            })?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
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
/// receive time the timeline judgment compares against.
///
/// A record whose BMC timestamp runs ahead of the receive time by at most
/// [`EVENT_TIMESTAMP_TOLERANCE`] is accepted with the recorded receive time
/// clamped to the event's own timestamp: the domain invariant
/// (`event_timestamp <= observed_at`) and persistence read-back both refuse
/// an inverted timeline, so clamping is the only way to keep the event —
/// recording the real receive time would make the row unreadable. The
/// alternative, rejecting the event, is exactly the clock-skew loss this
/// tolerance fixes. Beyond the tolerance the record is refused and reported
/// honestly through the existing decode-failure classification (logged and
/// skipped once, the cursor advancing): refusing to advance would wedge the
/// event stream on a permanently mis-clocked site and block every later
/// event.
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
    let severity = match rutilus_center_protocol::EventSeverity::try_from(record.severity) {
        Ok(rutilus_center_protocol::EventSeverity::Ok) => EventSeverity::Ok,
        Ok(rutilus_center_protocol::EventSeverity::Warning) => EventSeverity::Warning,
        Ok(rutilus_center_protocol::EventSeverity::Critical) => EventSeverity::Critical,
        _ => return Err("unspecified or unknown severity"),
    };
    let event_timestamp = OffsetDateTime::from_unix_timestamp(record.occurred_at_unix)
        .map_err(|_| "unparseable occurrence timestamp")?;
    if event_timestamp > now + EVENT_TIMESTAMP_TOLERANCE {
        return Err("event timestamp is beyond the tolerated clock skew");
    }
    let observed_at = if event_timestamp > now {
        event_timestamp
    } else {
        now
    };
    Event::new(
        id,
        endpoint_id,
        message_id,
        severity,
        None,
        event_timestamp,
        observed_at,
    )
    .map_err(|_| "event timestamp is after the receive time")
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

/// Writes one chunk at its exact offset in the artifact file; the blocking
/// half of the §7.8 file I/O, mirroring the site-side upload flow. The
/// artifact directory is created on demand: the manifest may outlive any
/// file, and the first chunk is the moment the bytes exist. The write seeks
/// to the offset and overwrites exactly that range, so a retried chunk (the
/// §15.4 at-least-once retransmission) lands on the same bytes instead of
/// duplicating them.
fn write_chunk_at(path: &std::path::Path, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)
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
            }
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
    async fn event_timestamps_within_the_clock_tolerance_are_accepted() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockProjectionStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store, cursor.clone());
        let site = resolved_site();
        let endpoint_id = EndpointId::generate();
        state.claim_endpoint(endpoint_id, site.instance_id());
        let now = base_time();

        // The site's clock runs 30 seconds ahead of the center's — within
        // the tolerance, the event is accepted instead of lost. The
        // recorded receive time is clamped to the event's own timestamp so
        // the persisted row keeps the domain timeline invariant.
        let batch = EventBatch {
            events: vec![event_record(&endpoint_id, now.unix_timestamp() + 30)],
        };
        projection
            .on_frame(&site, 3, &EnvelopeMessage::EventBatch(batch), now)
            .await?;

        let events = state.events_owned();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint_id(), endpoint_id);
        assert_eq!(
            events[0].event_timestamp().unix_timestamp(),
            now.unix_timestamp() + 30
        );
        assert_eq!(
            events[0].observed_at().unix_timestamp(),
            now.unix_timestamp() + 30
        );
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
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

        // Only the endpoint the reporting site owns is stored; the foreign
        // and unknown records are logged and skipped without failing the
        // batch, and the cursor advances past all three.
        let events = state.events_owned();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].endpoint_id(), owned);
        let stored = cursor
            .get(site.instance_id(), SyncStream::Event)
            .await?
            .ok_or("the cursor was not stored")?;
        assert_eq!(stored.cursor_value(), "3");
        Ok(())
    }
}
