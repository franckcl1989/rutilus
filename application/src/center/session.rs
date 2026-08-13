//! The inbound session layer of the center (design §15.1, 0.7.0 S5).
//!
//! Two services make up the admission path of one inbound connection:
//!
//! - [`CenterSessionAdmission`] resolves the certificate identity of an
//!   accepted mTLS connection to its bound site. Only a `Bound` binding
//!   admits a connection (§15.1 — only bound sites may connect), and the
//!   S3b audit item 1 cross-validation ([`crate::center::binding::validate_bound_identity`])
//!   is the admission's gate: the certificate's private-arc extension and
//!   subject must agree with the binding record, never the other way
//!   around.
//! - [`CenterSessionRegistry`] tracks which bound sites currently hold an
//!   online connection, with one connection per site. The engine touches
//!   the registry on every received frame and removes the site on every
//!   exit; the runtime's connection task additionally arms a
//!   [`DisconnectOnDrop`] guard, so the cleanup is guaranteed even when
//!   the task ends abnormally — a crashed task can never leave a zombie
//!   online entry, and the site's next reconnect succeeds instead of a
//!   stale [`CenterSessionRegistryError::AlreadyConnected`] refusal.

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    future::Future,
    sync::Mutex,
};

use rutilus_center_protocol::{Ack, Envelope, EnvelopeMessage};
use rutilus_domain::{CenterBindingId, CertificateFingerprint, InstanceId, OutboxEntryId};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    BoundaryFuture, CenterOutbox, Clock,
    center::binding::{
        CenterBindingRepository, IdentityValidationError, SiteIdentity, validate_bound_identity,
    },
};

/// One bound site admitted onto an inbound connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSite {
    instance_id: InstanceId,
    binding_id: CenterBindingId,
    site_fingerprint: CertificateFingerprint,
}

impl ResolvedSite {
    #[must_use]
    pub const fn new(
        instance_id: InstanceId,
        binding_id: CenterBindingId,
        site_fingerprint: CertificateFingerprint,
    ) -> Self {
        Self {
            instance_id,
            binding_id,
            site_fingerprint,
        }
    }

    /// The bound site's instance identity.
    #[must_use]
    pub const fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    /// The bound binding's identity.
    #[must_use]
    pub const fn binding_id(&self) -> CenterBindingId {
        self.binding_id
    }

    /// The site identity fingerprint the binding recorded (§15.1).
    #[must_use]
    pub const fn site_fingerprint(&self) -> CertificateFingerprint {
        self.site_fingerprint
    }
}

/// Why one inbound connection is refused admission (§15.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionRejection {
    /// The presented certificate matches no bound binding: it was never
    /// issued, or its binding was revoked or re-bound.
    UnknownSite,
    /// The certificate identity disagrees with its binding record (S3b
    /// audit item 1): missing extension, mismatched fingerprint, or
    /// mismatched subject, or the binding is not in force.
    Identity(IdentityValidationError),
    /// The `Hello`'s declared instance id disagrees with the binding
    /// record the presented certificate resolves to (C5-10): the wire
    /// identity is not the site the certificate was issued for. The
    /// site's binding is in force, so it must not converge it — it
    /// receives its own honest reason code.
    HelloIdentityMismatch {
        /// The instance id the `Hello` declared on the wire.
        declared: String,
        /// The bound site the certificate was issued for.
        bound: InstanceId,
    },
}

impl std::fmt::Display for AdmissionRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSite => formatter.write_str("the certificate matches no bound site"),
            Self::Identity(reason) => reason.fmt(formatter),
            Self::HelloIdentityMismatch { declared, bound } => write!(
                formatter,
                "the Hello declares instance {declared} but the certificate is bound to instance {bound}"
            ),
        }
    }
}

impl Error for AdmissionRejection {}

/// The admission decision for one inbound connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionVerdict {
    /// The connection is admitted and carries the resolved site.
    Admitted(ResolvedSite),
    /// The connection is refused with the stable reason.
    Rejected { reason: AdmissionRejection },
}

/// Resolves one accepted inbound connection to its bound site (§15.1,
/// S3b audit item 1).
///
/// `Store` is the binding boundary; the app crate hands this service the
/// [`SiteIdentity`] it parsed from the presented client certificate and
/// acts on the verdict.
pub struct CenterSessionAdmission<Store> {
    store: Store,
}

impl<Store> CenterSessionAdmission<Store> {
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }
}

/// A controlled failure of one admission step.
#[derive(Debug, Error)]
pub enum CenterSessionAdmissionError<BindingError>
where
    BindingError: Error + 'static,
{
    /// The binding repository failed; carries its own error.
    #[error("the binding repository failed: {0}")]
    Binding(#[source] BindingError),
}

impl<Store> CenterSessionAdmission<Store>
where
    Store: CenterBindingRepository,
{
    /// Resolves one presented certificate identity to its bound site,
    /// under the `Hello`'s declared instance id (C5-10).
    ///
    /// The binding lookup keys on the certificate's private-arc site
    /// fingerprint; a certificate without the extension, or whose extension
    /// matches no `Bound` binding, is refused. A found binding must then
    /// pass the S3b cross-validation — the binding record is the source of
    /// truth, and a certificate that disagrees with it (stale issuance,
    /// re-bound or revoked registration) is refused even though its CA
    /// signature verifies.
    ///
    /// The certificate identity is not the whole identity: the `Hello`
    /// carries a self-declared `instance_id`, and admission refuses a
    /// `Hello` that declares any instance other than the binding record's
    /// bound site. The certificate and the binding together are the source
    /// of truth for who this connection is; the wire declaration must agree
    /// with them, never the other way around. `site_name` is a display
    /// label without a certificate counterpart, so it never participates in
    /// the decision.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSessionAdmissionError::Binding`] when the binding
    /// repository fails.
    pub async fn resolve(
        &self,
        identity: &SiteIdentity,
        declared_instance_id: &str,
    ) -> Result<AdmissionVerdict, CenterSessionAdmissionError<Store::Error>> {
        let Some(site_fingerprint) = identity.bound_site_fingerprint() else {
            return Ok(AdmissionVerdict::Rejected {
                reason: AdmissionRejection::Identity(IdentityValidationError::ExtensionMissing),
            });
        };
        let Some(binding) = self
            .store
            .find_binding_by_site_fingerprint(site_fingerprint)
            .await
            .map_err(CenterSessionAdmissionError::Binding)?
        else {
            return Ok(AdmissionVerdict::Rejected {
                reason: AdmissionRejection::UnknownSite,
            });
        };
        if let Err(reason) = validate_bound_identity(&binding, identity) {
            return Ok(AdmissionVerdict::Rejected {
                reason: AdmissionRejection::Identity(reason),
            });
        }
        let bound_site = binding.site_instance_id();
        // C5-10: the certificate resolved the connection to the binding
        // record; the `Hello`'s self-declared instance id must name that
        // same bound site. A `Hello` that claims a different identity is
        // refused honestly — the binding is in force, so this is an
        // identity lie, not a convergence signal for the site's local
        // binding.
        if declared_instance_id != bound_site.to_string() {
            return Ok(AdmissionVerdict::Rejected {
                reason: AdmissionRejection::HelloIdentityMismatch {
                    declared: declared_instance_id.to_owned(),
                    bound: bound_site,
                },
            });
        }
        Ok(AdmissionVerdict::Admitted(ResolvedSite::new(
            bound_site,
            binding.id(),
            site_fingerprint,
        )))
    }
}

/// Why a registry write is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CenterSessionRegistryError {
    /// The site already holds an online connection; one connection per site
    /// is the §15.1 session rule.
    AlreadyConnected { site: InstanceId },
    /// The registry lock is poisoned; the registry cannot be used.
    Poisoned,
}

impl std::fmt::Display for CenterSessionRegistryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyConnected { site } => {
                write!(formatter, "site {site} already has an online connection")
            }
            Self::Poisoned => formatter.write_str("the session registry lock is poisoned"),
        }
    }
}

impl Error for CenterSessionRegistryError {}

/// One registered online connection.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OnlineSession {
    site: ResolvedSite,
    last_seen: OffsetDateTime,
}

/// Tracks which bound sites currently hold an online connection (§15.1).
///
/// One connection per site: [`Self::mark_connected`] refuses a second
/// concurrent connection for a site that is already online. [`Self::touch`]
/// advances the liveness stamp on every received frame, and the engine
/// removes the site on every connection exit. The runtime's connection task
/// arms a [`DisconnectOnDrop`] guard around the engine, so the cleanup is
/// guaranteed even on a crashed task — a panic unwind runs the guard's
/// `Drop` — and the site's next reconnect succeeds instead of a stale
/// [`CenterSessionRegistryError::AlreadyConnected`] refusal.
#[derive(Debug)]
pub struct CenterSessionRegistry {
    online: Mutex<HashMap<InstanceId, OnlineSession>>,
}

impl CenterSessionRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            online: Mutex::new(HashMap::new()),
        }
    }

    /// Registers one online connection for the resolved site.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSessionRegistryError::AlreadyConnected`] when the
    /// site already holds an online connection, and
    /// [`CenterSessionRegistryError::Poisoned`] when the registry lock is
    /// poisoned.
    pub fn mark_connected(
        &self,
        site: ResolvedSite,
        now: OffsetDateTime,
    ) -> Result<(), CenterSessionRegistryError> {
        let mut online = self
            .online
            .lock()
            .map_err(|_| CenterSessionRegistryError::Poisoned)?;
        if online.contains_key(&site.instance_id()) {
            return Err(CenterSessionRegistryError::AlreadyConnected {
                site: site.instance_id(),
            });
        }
        online.insert(
            site.instance_id(),
            OnlineSession {
                site,
                last_seen: now,
            },
        );
        Ok(())
    }

    /// Advances the liveness stamp of one online site.
    ///
    /// A site that is not online is a no-op: the touch is only ever a
    /// liveness fact, never an admission.
    pub fn touch(&self, site: InstanceId, now: OffsetDateTime) {
        let Ok(mut online) = self.online.lock() else {
            return;
        };
        if let Some(session) = online.get_mut(&site) {
            session.last_seen = now;
        }
    }

    /// Removes one site from the online set; a site that is not online is a
    /// no-op (the disconnect is idempotent).
    pub fn mark_disconnected(&self, site: InstanceId) {
        let Ok(mut online) = self.online.lock() else {
            return;
        };
        online.remove(&site);
    }

    /// Reports whether one site currently holds an online connection.
    #[must_use]
    pub fn is_online(&self, site: InstanceId) -> bool {
        self.online
            .lock()
            .is_ok_and(|online| online.contains_key(&site))
    }

    /// Lists every site with an online connection, most recently seen
    /// first.
    #[must_use]
    pub fn list_online(&self) -> Vec<ResolvedSite> {
        let mut sessions = self
            .online
            .lock()
            .map_or_else(|_| Vec::new(), |online| online.values().cloned().collect());
        sessions.sort_by_key(|session| std::cmp::Reverse(session.last_seen));
        sessions.into_iter().map(|session| session.site).collect()
    }
}

/// Guarantees one site leaves the online registry when the connection task
/// ends, whatever the ending is (§15.1): the normal engine cleanup and the
/// panic unwind alike.
///
/// The engine removes the site on every orderly exit, but a connection task
/// that crashes — a panic inside the handler or the transport, or a task
/// aborted by the runtime — would leave a zombie online entry without this
/// guard, and the site's reconnects would be refused as
/// [`CenterSessionRegistryError::AlreadyConnected`] forever, silently. The
/// guard is the crash backstop: its `Drop` runs during the unwind and
/// removes the site, so the one-connection-per-site rule self-heals on the
/// next reconnect. The cleanup is idempotent — [`CenterPresence::mark_disconnected`]
/// is a no-op for a site that is not online — so the guard and the engine's
/// own cleanup never conflict.
#[must_use]
pub struct DisconnectOnDrop<Presence: CenterPresence> {
    presence: Presence,
    site: InstanceId,
}

impl<Presence: CenterPresence> DisconnectOnDrop<Presence> {
    pub const fn new(presence: Presence, site: InstanceId) -> Self {
        Self { presence, site }
    }
}

impl<Presence: CenterPresence> Drop for DisconnectOnDrop<Presence> {
    fn drop(&mut self) {
        self.presence.mark_disconnected(self.site);
    }
}

impl Default for CenterSessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The transport boundary of one established inbound connection (§15.1).
///
/// The app crate implements this over its `CenterConnection`; the engine
/// drives it exactly like the site-side [`crate::CenterTransport`] boundary,
/// sending one [`Envelope`] per frame — the envelope's `sequence` and
/// `acked_sequence` are the engine's, since the center's durable outbox
/// owns them — and receiving raw envelopes.
pub trait CenterInboundSession: Send {
    /// The boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Sends one envelope exactly as given.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the transport cannot deliver the frame.
    fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Waits for the next inbound frame.
    ///
    /// `Ok(None)` reports a clean close of the connection. An `Err` reports
    /// a transport or protocol failure, including the idle timeout — the
    /// engine treats every end alike: the site leaves the online registry
    /// and the runtime logs the reason.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] for transport and protocol failures.
    fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>>;
}

/// The frame-consumption boundary of the inbound engine: everything a
/// received content frame does with the center's durable state.
///
/// The engine owns the reliable-transport mechanics (the §15.4
/// acknowledgements and the outbox flush) and delegates every content
/// message to the consumer; the [`crate::center::projection`] and
/// [`crate::center::dispatch`] use cases implement it.
pub trait CenterFrameConsumer: Send + Sync {
    /// The consumer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Handles one received content frame.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] for a boundary failure; the engine then ends
    /// the connection without acknowledging the frame, so the site
    /// re-delivers it on the next connection (§15.4 at-least-once).
    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

impl<Consumer> CenterFrameConsumer for &Consumer
where
    Consumer: CenterFrameConsumer + ?Sized,
{
    type Error = Consumer::Error;

    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Consumer::on_frame(*self, site, envelope, now)
    }
}

/// The presence boundary the inbound engine drives: the online registry.
///
/// The engine touches the site on every received frame and removes it on
/// every connection exit; the concrete [`CenterSessionRegistry`]
/// implements the boundary, and the runtime shares one registry across the
/// center's connections.
pub trait CenterPresence: Send + Sync {
    /// Advances the liveness stamp of one online site.
    fn touch(&self, site: InstanceId, now: OffsetDateTime);

    /// Removes one site from the online set.
    fn mark_disconnected(&self, site: InstanceId);
}

impl<Presence> CenterPresence for &Presence
where
    Presence: CenterPresence + ?Sized,
{
    fn touch(&self, site: InstanceId, now: OffsetDateTime) {
        Presence::touch(*self, site, now);
    }

    fn mark_disconnected(&self, site: InstanceId) {
        Presence::mark_disconnected(*self, site);
    }
}

impl<Presence> CenterPresence for std::sync::Arc<Presence>
where
    Presence: CenterPresence,
{
    fn touch(&self, site: InstanceId, now: OffsetDateTime) {
        Presence::touch(self, site, now);
    }

    fn mark_disconnected(&self, site: InstanceId) {
        Presence::mark_disconnected(self, site);
    }
}

impl CenterPresence for CenterSessionRegistry {
    fn touch(&self, site: InstanceId, now: OffsetDateTime) {
        CenterSessionRegistry::touch(self, site, now);
    }

    fn mark_disconnected(&self, site: InstanceId) {
        CenterSessionRegistry::mark_disconnected(self, site);
    }
}

/// The timing bounds of one inbound center connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterInboundOptions {
    /// How many pending outbox entries one flush sends before the next
    /// acknowledgement is needed; bounds one burst on the wire.
    pub flush_limit: u64,
}

impl Default for CenterInboundOptions {
    fn default() -> Self {
        Self { flush_limit: 64 }
    }
}

/// The center's inbound connection engine (design §15, 0.7.0 S5).
///
/// The engine is the receiving mirror of the site-side [`crate::CenterSync`]
/// connection loop: it flushes the center's durable outbox for the site
/// (the §15.6 operation offers), receives the site's frames, applies the
/// §15.4 acknowledgements in both directions, and dispatches every content
/// frame to the [`CenterFrameConsumer`]. The loop ends on a clean close, a
/// transport failure (including the idle timeout), or the stop signal; in
/// every case the site is removed from the online registry.
///
/// # The acknowledgement discipline
///
/// Every received content frame is acknowledged with an [`Ack`] after it
/// was processed — never before, so a frame whose processing failed is
/// re-delivered by the site on its next connection. The site's
/// acknowledgements travel both as explicit `Ack` frames and as the
/// `acked_sequence` watermark piggybacked on every site frame; both retire
/// the center's outbox entries up to the acknowledged sequence.
pub struct CenterInboundEngine<Session, Outbox, Consumer, Registry, Time> {
    session: Session,
    outbox: Outbox,
    consumer: Consumer,
    registry: Registry,
    clock: Time,
    site: ResolvedSite,
    options: CenterInboundOptions,
}

impl<Session, Outbox, Consumer, Registry, Time>
    CenterInboundEngine<Session, Outbox, Consumer, Registry, Time>
where
    Session: CenterInboundSession,
    Outbox: CenterOutbox,
    Consumer: CenterFrameConsumer,
    Registry: CenterPresence,
    Time: Clock,
{
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        session: Session,
        outbox: Outbox,
        consumer: Consumer,
        registry: Registry,
        clock: Time,
        site: ResolvedSite,
        options: CenterInboundOptions,
    ) -> Self {
        Self {
            session,
            outbox,
            consumer,
            registry,
            clock,
            site,
            options,
        }
    }

    /// Runs the connection loop until `stop` resolves or the connection
    /// ends, then removes the site from the online registry.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboundEngineError::Transport`] for a session
    /// failure (including the idle timeout), [`CenterInboundEngineError::Outbox`]
    /// for an outbox boundary failure, and
    /// [`CenterInboundEngineError::Consumer`] when a content frame could
    /// not be processed.
    pub async fn run<Stop>(
        mut self,
        stop: Stop,
    ) -> Result<(), CenterInboundEngineErrorOf<Session, Outbox, Consumer>>
    where
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        // The durable entries sent on this connection, in send order; the
        // site's acknowledgements pop the head. The list resets on every
        // connection; unacknowledged entries stay pending and the next
        // connection re-sends them from the last acknowledgement (§15.4).
        let mut sent: VecDeque<(OutboxEntryId, i64)> = VecDeque::new();
        // The highest site sequence accepted on this connection; every
        // outbound frame piggybacks it (§15.4).
        let peer_acked: u64 = 0;
        let result = self
            .connected_loop(&mut sent, peer_acked, stop.as_mut())
            .await;
        self.registry.mark_disconnected(self.site.instance_id());
        result
    }

    async fn connected_loop<Stop>(
        &mut self,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
        mut peer_acked: u64,
        stop: Stop,
    ) -> Result<(), CenterInboundEngineErrorOf<Session, Outbox, Consumer>>
    where
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        self.flush_outbox(sent, peer_acked).await?;
        loop {
            tokio::select! {
                () = stop.as_mut() => return Ok(()),
                frame = self.session.receive() => {
                    let Some(envelope) = frame.map_err(CenterInboundEngineError::Transport)? else {
                        return Ok(());
                    };
                    peer_acked = peer_acked.max(envelope.sequence);
                    let now = self.clock.now();
                    self.registry.touch(self.site.instance_id(), now);
                    let delivery_ack = match envelope.message.as_ref() {
                        Some(EnvelopeMessage::Ack(ack)) => {
                            self.ack_outbox(ack.sequence, sent).await?;
                            false
                        }
                        Some(EnvelopeMessage::Heartbeat(_)) => false,
                        Some(_) => {
                            self.consumer
                                .on_frame(&self.site, &envelope, now)
                                .await
                                .map_err(CenterInboundEngineError::Consumer)?;
                            true
                        }
                        None => {
                            tracing::warn!(
                                "site {}: center frame {} carries no message",
                                self.site.instance_id(),
                                envelope.sequence
                            );
                            false
                        }
                    };
                    // The site's own acknowledgement watermark rides on
                    // every frame; it retires the center's outbox entries.
                    // The retirement precedes the delivery confirmation, so
                    // the site's flush observes the retired queue.
                    self.ack_outbox(envelope.acked_sequence, sent).await?;
                    if delivery_ack {
                        // The delivery confirmation follows the processing:
                        // a failed frame is never acknowledged, so the site
                        // re-delivers it (§15.4). The ack is a delivery
                        // frame, not an outbox message, so it carries
                        // sequence 0 like the site-side heartbeat
                        // convention.
                        self.session
                            .send(Envelope {
                                sequence: 0,
                                acked_sequence: peer_acked,
                                message: Some(EnvelopeMessage::Ack(Ack {
                                    sequence: envelope.sequence,
                                })),
                            })
                            .await
                            .map_err(CenterInboundEngineError::Transport)?;
                    }
                    self.flush_outbox(sent, peer_acked).await?;
                }
            }
        }
    }

    /// Sends the oldest pending outbox entries in sequence order, up to the
    /// flush limit, and records them as sent on this connection.
    ///
    /// Every frame carries its durable sequence and the highest site
    /// sequence accepted so far. A transport failure mid-flush abandons
    /// only the wire position: the unacknowledged entries stay pending and
    /// the next connection re-sends them (at-least-once delivery; the site
    /// deduplicates by operation id, §15.4). An offer past its §15.6 TTL is
    /// retired instead of sent — the site would only refuse it, so the
    /// queue must not re-send it forever.
    async fn flush_outbox(
        &mut self,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
        peer_acked: u64,
    ) -> Result<(), CenterInboundEngineErrorOf<Session, Outbox, Consumer>> {
        let pending = self
            .outbox
            .list_pending(self.site.instance_id(), self.options.flush_limit)
            .await
            .map_err(CenterInboundEngineError::Outbox)?;
        let now = self.clock.now();
        for entry in pending {
            // An entry already delivered on this connection is not sent
            // again: the acknowledgement retires it, and a dropped
            // connection re-sends it from the pending scan (§15.4).
            if sent.iter().any(|(sent_id, _)| *sent_id == entry.id()) {
                continue;
            }
            let mut envelope: Envelope = match serde_json::from_str(entry.payload_json()) {
                Ok(envelope) => envelope,
                Err(source) => {
                    // Ciphertext rows are authenticated by the list scan:
                    // a tampered payload fails the whole `list_pending`
                    // read as Corrupt before this loop runs, so a flush
                    // never sends on top of a tampered queue (fail closed,
                    // deliberate). The per-row skip here survives only for
                    // legacy plaintext rows whose JSON no longer parses:
                    // log it, skip it, and deliver the rest of the queue.
                    tracing::error!(
                        "site {}: skipping outbox entry {} with a corrupt payload: {source}",
                        self.site.instance_id(),
                        entry.id()
                    );
                    continue;
                }
            };
            let Ok(wire_sequence) = u64::try_from(entry.sequence()) else {
                tracing::error!(
                    "site {}: skipping outbox entry {} with an unwireable sequence {}",
                    self.site.instance_id(),
                    entry.id(),
                    entry.sequence()
                );
                continue;
            };
            let Some(message) = envelope.message else {
                // An outbox row without a message cannot be delivered; like
                // a malformed legacy plaintext payload, it is logged and
                // skipped so one row never wedges the whole flush.
                tracing::error!(
                    "site {}: skipping outbox entry {} with an empty envelope",
                    self.site.instance_id(),
                    entry.id()
                );
                continue;
            };
            // The §15.6 offer TTL: an offer past its expiry can no longer
            // be accepted by the site, so the flush retires the row instead
            // of re-sending it forever — a site that was offline past the
            // TTL would only refuse it. The domain outbox has no expired
            // state, so the retirement is the queue-level termination.
            if let Some(expires_at) = offer_expiry(&message)
                && now > expires_at
            {
                tracing::warn!(
                    "site {}: retiring outbox entry {}: the offer expired at {expires_at}",
                    self.site.instance_id(),
                    entry.id()
                );
                self.outbox
                    .acknowledge(entry.id(), now)
                    .await
                    .map_err(CenterInboundEngineError::Outbox)?;
                continue;
            }
            envelope.sequence = wire_sequence;
            envelope.acked_sequence = peer_acked;
            envelope.message = Some(message);
            self.session
                .send(envelope)
                .await
                .map_err(CenterInboundEngineError::Transport)?;
            sent.push_back((entry.id(), entry.sequence()));
        }
        Ok(())
    }

    /// Retires every outbox entry whose sequence is at most the
    /// acknowledged sequence. Frames on one connection are ordered, so the
    /// acknowledgements are monotonic and the head of the sent list is the
    /// only candidate.
    async fn ack_outbox(
        &mut self,
        acked_sequence: u64,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
    ) -> Result<(), CenterInboundEngineErrorOf<Session, Outbox, Consumer>> {
        let now = self.clock.now();
        while let Some(&(entry_id, sequence)) = sent.front() {
            let Ok(wire_sequence) = u64::try_from(sequence) else {
                sent.pop_front();
                continue;
            };
            if wire_sequence > acked_sequence {
                break;
            }
            sent.pop_front();
            self.outbox
                .acknowledge(entry_id, now)
                .await
                .map_err(CenterInboundEngineError::Outbox)?;
        }
        Ok(())
    }
}

/// The §15.6 offer expiry of one pending message: `Some(expires_at)` for
/// an [`EnvelopeMessage::OperationOffer`], `None` for every other envelope.
/// An offer whose expiry cannot be parsed reports the epoch — an unreadable
/// TTL is treated as past (fail closed, the mirror of the site's §15.6
/// recheck).
fn offer_expiry(message: &EnvelopeMessage) -> Option<OffsetDateTime> {
    match message {
        EnvelopeMessage::OperationOffer(offer) => Some(
            OffsetDateTime::from_unix_timestamp(offer.expires_at_unix)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        ),
        _ => None,
    }
}

/// A controlled failure of one inbound connection step.
#[derive(Debug, Error)]
pub enum CenterInboundEngineError<SessionError, OutboxError, ConsumerError>
where
    SessionError: Error + 'static,
    OutboxError: Error + 'static,
    ConsumerError: Error + 'static,
{
    /// The session boundary failed; carries its own error.
    #[error("the inbound session failed: {0}")]
    Transport(#[source] SessionError),
    /// The durable outbox boundary failed; carries its own error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The frame consumer failed; carries its own error.
    #[error("the frame consumer failed: {0}")]
    Consumer(#[source] ConsumerError),
}

/// The concrete failure type of one inbound connection step.
type CenterInboundEngineErrorOf<Session, Outbox, Consumer> = CenterInboundEngineError<
    <Session as CenterInboundSession>::Error,
    <Outbox as CenterOutbox>::Error,
    <Consumer as CenterFrameConsumer>::Error,
>;

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use rutilus_domain::{BINDING_CODE_TTL, BindingCode, CenterBinding};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::center::binding::test_support::MockBindingStore;

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn site_fingerprint() -> CertificateFingerprint {
        CertificateFingerprint::from_bytes([0x42; 32])
    }

    fn bound_binding(site: InstanceId) -> Result<CenterBinding, Box<dyn Error>> {
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            String::from("https://center.example"),
            site,
            &"23456789ABCDEFGHJKLM".parse::<BindingCode>()?,
            base_time() + BINDING_CODE_TTL,
            base_time(),
        );
        binding.bind(Some(site_fingerprint()), base_time() + Duration::MINUTE)?;
        Ok(binding)
    }

    fn matching_identity(site: InstanceId) -> SiteIdentity {
        SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.to_string()),
            Some(site_fingerprint()),
        )
    }

    #[tokio::test]
    async fn a_bound_certificate_admits_its_site() -> Result<(), Box<dyn Error>> {
        let site = InstanceId::generate();
        let store = MockBindingStore::new();
        store.seed_bound(bound_binding(site)?);
        let admission = CenterSessionAdmission::new(&store);

        // The Hello declares the bound instance: the admission admits it.
        let verdict = admission
            .resolve(&matching_identity(site), &site.to_string())
            .await?;
        assert_eq!(
            verdict,
            AdmissionVerdict::Admitted(ResolvedSite::new(
                site,
                store.seeded_binding_id(),
                site_fingerprint()
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn admission_refuses_unknown_unbound_and_mismatched_certificates()
    -> Result<(), Box<dyn Error>> {
        let site = InstanceId::generate();
        let store = MockBindingStore::new();
        store.seed_bound(bound_binding(site)?);
        let admission = CenterSessionAdmission::new(&store);

        // A certificate without the site-identity extension is refused.
        let no_extension = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.to_string()),
            None,
        );
        assert_eq!(
            admission.resolve(&no_extension, &site.to_string()).await?,
            AdmissionVerdict::Rejected {
                reason: AdmissionRejection::Identity(IdentityValidationError::ExtensionMissing)
            }
        );
        // A certificate whose extension matches no bound binding is refused
        // (§15.1 — only bound sites may connect).
        let unknown = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(site.to_string()),
            Some(CertificateFingerprint::from_bytes([0x43; 32])),
        );
        assert_eq!(
            admission.resolve(&unknown, &site.to_string()).await?,
            AdmissionVerdict::Rejected {
                reason: AdmissionRejection::UnknownSite
            }
        );
        // A certificate whose subject names a different instance disagrees
        // with the binding record (S3b audit item 1).
        let wrong_subject = SiteIdentity::from_parts(
            CertificateFingerprint::from_bytes([0x99; 32]),
            Some(InstanceId::generate().to_string()),
            Some(site_fingerprint()),
        );
        assert_eq!(
            admission.resolve(&wrong_subject, &site.to_string()).await?,
            AdmissionVerdict::Rejected {
                reason: AdmissionRejection::Identity(IdentityValidationError::SubjectMismatch)
            }
        );
        // A certificate for a revoked binding is refused.
        let other_site = InstanceId::generate();
        let mut revoked = bound_binding(other_site)?;
        revoked.revoke()?;
        let store_with_revoked = MockBindingStore::new();
        store_with_revoked.seed_bound(revoked);
        let admission_with_revoked = CenterSessionAdmission::new(&store_with_revoked);
        assert_eq!(
            admission_with_revoked
                .resolve(&matching_identity(other_site), &other_site.to_string())
                .await?,
            AdmissionVerdict::Rejected {
                reason: AdmissionRejection::Identity(IdentityValidationError::NotBound)
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn admission_refuses_a_hello_declaring_a_different_instance_id()
    -> Result<(), Box<dyn Error>> {
        // C5-10: the certificate and its binding resolve the connection to
        // one bound site; a `Hello` that declares any other instance id is
        // refused honestly, with both identities in the reason.
        let site = InstanceId::generate();
        let store = MockBindingStore::new();
        store.seed_bound(bound_binding(site)?);
        let admission = CenterSessionAdmission::new(&store);
        let liar = InstanceId::generate();

        assert_eq!(
            admission
                .resolve(&matching_identity(site), &liar.to_string())
                .await?,
            AdmissionVerdict::Rejected {
                reason: AdmissionRejection::HelloIdentityMismatch {
                    declared: liar.to_string(),
                    bound: site,
                }
            }
        );
        // The declared identity does not override the certificate: the
        // same certificate is still admitted when its Hello is honest.
        assert_eq!(
            admission
                .resolve(&matching_identity(site), &site.to_string())
                .await?,
            AdmissionVerdict::Admitted(ResolvedSite::new(
                site,
                store.seeded_binding_id(),
                site_fingerprint()
            ))
        );
        Ok(())
    }

    #[test]
    fn the_registry_tracks_online_sites_with_one_connection_per_site() -> Result<(), Box<dyn Error>>
    {
        let registry = CenterSessionRegistry::new();
        let base = base_time();
        let site = ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            site_fingerprint(),
        );
        let other = ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            site_fingerprint(),
        );

        registry.mark_connected(site.clone(), base)?;
        assert!(registry.is_online(site.instance_id()));
        assert!(!registry.is_online(other.instance_id()));

        // A second concurrent connection for the same site is refused.
        assert_eq!(
            registry.mark_connected(site.clone(), base + Duration::SECOND),
            Err(CenterSessionRegistryError::AlreadyConnected {
                site: site.instance_id()
            })
        );

        registry.mark_connected(other.clone(), base + Duration::SECOND)?;
        // The list is newest-seen first; the touch gives the site the
        // later stamp so the order is deterministic.
        registry.touch(site.instance_id(), base + Duration::seconds(2));
        assert_eq!(registry.list_online(), vec![site.clone(), other.clone()]);

        registry.mark_disconnected(site.instance_id());
        assert!(!registry.is_online(site.instance_id()));
        // The disconnect is idempotent.
        registry.mark_disconnected(site.instance_id());
        assert_eq!(registry.list_online(), vec![other]);
        Ok(())
    }

    #[test]
    fn a_crashed_connection_task_removes_the_site_from_the_registry() -> Result<(), Box<dyn Error>>
    {
        let registry = Arc::new(CenterSessionRegistry::new());
        let base = base_time();
        let site = ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            site_fingerprint(),
        );
        let site_id = site.instance_id();
        registry.mark_connected(site.clone(), base)?;

        // The connection task crashes after the site was registered (an
        // index out of bounds, standing in for a handler panic). The
        // disconnect guard is armed inside the task, so its `Drop` runs
        // during the unwind and removes the site — the engine's own
        // cleanup never runs on this path.
        let crashed = std::thread::spawn({
            let registry = Arc::clone(&registry);
            move || {
                let _guard = DisconnectOnDrop::new(registry, site_id);
                let values = Vec::from([0_u8]);
                let _ = values[1];
            }
        });
        assert!(
            crashed.join().is_err(),
            "the task must have crashed with a panic"
        );
        assert!(!registry.is_online(site_id));

        // The registry healed: the site's next reconnect registers instead
        // of the stale `AlreadyConnected` refusal of a zombie entry.
        registry.mark_connected(site, base)?;
        assert!(registry.is_online(site_id));
        Ok(())
    }

    /// A fixed clock for the engine tests.
    #[derive(Clone, Copy)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    /// The wire error of the test session and mocks.
    use crate::center_transport::test_support::MockCenterError;

    /// A channel-backed inbound session: the sent envelopes land in one
    /// channel and the inbound queue feeds [`CenterInboundSession::receive`].
    struct ChannelInboundSession {
        outbound: tokio::sync::mpsc::UnboundedSender<Envelope>,
        inbound: tokio::sync::mpsc::UnboundedReceiver<Envelope>,
    }

    impl ChannelInboundSession {
        fn channel() -> (
            Self,
            tokio::sync::mpsc::UnboundedReceiver<Envelope>,
            tokio::sync::mpsc::UnboundedSender<Envelope>,
        ) {
            let (outbound, outbound_rx) = tokio::sync::mpsc::unbounded_channel();
            let (inbound, inbound_rx) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    outbound,
                    inbound: inbound_rx,
                },
                outbound_rx,
                inbound,
            )
        }
    }

    impl CenterInboundSession for ChannelInboundSession {
        type Error = MockCenterError;

        fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.outbound.send(envelope).map_err(|_| MockCenterError)?;
                Ok(())
            })
        }

        fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>> {
            Box::pin(async move { Ok(self.inbound.recv().await) })
        }
    }

    /// The shared state of one test outbox: the engine owns the mock, the
    /// test keeps the clone to seed and inspect.
    #[derive(Clone)]
    struct MockOutbox {
        entries: Arc<Mutex<Vec<rutilus_domain::OutboxEntry>>>,
    }

    impl MockOutbox {
        fn new() -> Self {
            Self {
                entries: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Seeds one pending offer entry carrying the given wire sequence
        /// and §15.6 expiry.
        fn seed_offer(
            &self,
            sequence: u64,
            site: InstanceId,
            now: OffsetDateTime,
            expires_at_unix: i64,
        ) {
            let envelope = Envelope {
                sequence,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::OperationOffer(
                    rutilus_center_protocol::OperationOffer {
                        operation_id: String::from("operation-1"),
                        endpoint_id: String::from("endpoint-1"),
                        site_id: site.to_string(),
                        command_json: b"{}".to_vec(),
                        target: String::from("/redfish/v1/Systems/1"),
                        expires_at_unix,
                        actor_context: String::from("principal-1"),
                    },
                )),
            };
            let entry = rutilus_domain::OutboxEntry::new(
                rutilus_domain::OutboxEntryId::generate(),
                site,
                i64::try_from(sequence).unwrap_or(i64::MAX),
                serde_json::to_string(&envelope).unwrap_or_default(),
                now,
            );
            self.entries.lock().map(|mut rows| rows.push(entry)).ok();
        }

        /// The pending entry sequences of one site, in sequence order — the
        /// observable delivery queue.
        fn pending_sequences(&self, site: InstanceId) -> Vec<u64> {
            let mut pending = self
                .entries
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default();
            pending.retain(|entry| {
                entry.instance_id() == site
                    && entry.state() == rutilus_domain::OutboxEntryState::Pending
            });
            pending
                .iter()
                .map(|entry| u64::try_from(entry.sequence()).unwrap_or_default())
                .collect()
        }
    }

    impl crate::CenterOutbox for MockOutbox {
        type Error = MockCenterError;

        fn enqueue<'a>(
            &'a self,
            instance_id: InstanceId,
            message: &'a EnvelopeMessage,
            created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<rutilus_domain::OutboxEntry, Self::Error>> {
            Box::pin(async move {
                let sequence =
                    i64::try_from(self.entries.lock().map_err(|_| MockCenterError)?.len())
                        .unwrap_or(i64::MAX)
                        .saturating_add(1);
                let envelope = Envelope {
                    sequence: u64::try_from(sequence).unwrap_or(u64::MAX),
                    acked_sequence: 0,
                    message: Some(message.clone()),
                };
                let entry = rutilus_domain::OutboxEntry::new(
                    rutilus_domain::OutboxEntryId::generate(),
                    instance_id,
                    sequence,
                    serde_json::to_string(&envelope).map_err(|_| MockCenterError)?,
                    created_at,
                );
                self.entries
                    .lock()
                    .map_err(|_| MockCenterError)?
                    .push(entry.clone());
                Ok(entry)
            })
        }

        fn list_pending(
            &self,
            instance_id: InstanceId,
            limit: u64,
        ) -> BoundaryFuture<'_, Result<Vec<rutilus_domain::OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut pending = self
                    .entries
                    .lock()
                    .map_err(|_| MockCenterError)?
                    .iter()
                    .filter(|entry| {
                        entry.instance_id() == instance_id
                            && entry.state() == rutilus_domain::OutboxEntryState::Pending
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                pending.sort_by_key(rutilus_domain::OutboxEntry::sequence);
                pending.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                Ok(pending)
            })
        }

        fn list_offers(
            &self,
            instance_id: InstanceId,
        ) -> BoundaryFuture<'_, Result<Vec<rutilus_domain::OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .entries
                    .lock()
                    .map_err(|_| MockCenterError)?
                    .iter()
                    .filter(|entry| entry.instance_id() == instance_id)
                    .cloned()
                    .collect::<Vec<_>>();
                rows.sort_by_key(rutilus_domain::OutboxEntry::sequence);
                Ok(rows)
            })
        }

        fn acknowledge(
            &self,
            entry_id: rutilus_domain::OutboxEntryId,
            acked_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.entries.lock().map_err(|_| MockCenterError)?;
                let entry = rows
                    .iter_mut()
                    .find(|entry| entry.id() == entry_id)
                    .ok_or(MockCenterError)?;
                entry.ack(acked_at).map_err(|_| MockCenterError)?;
                Ok(())
            })
        }
    }

    /// A consumer that records every delivered frame; the engine owns one
    /// clone, the test keeps the other.
    #[derive(Clone)]
    struct RecorderConsumer {
        frames: Arc<Mutex<Vec<(ResolvedSite, Envelope)>>>,
    }

    impl RecorderConsumer {
        fn new() -> Self {
            Self {
                frames: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn frames_owned(&self) -> Vec<Envelope> {
            self.frames
                .lock()
                .map(|frames| {
                    frames
                        .iter()
                        .map(|(_, envelope)| envelope.clone())
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    impl CenterFrameConsumer for RecorderConsumer {
        type Error = MockCenterError;

        fn on_frame<'a>(
            &'a self,
            site: &'a ResolvedSite,
            envelope: &'a Envelope,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.frames
                    .lock()
                    .map_err(|_| MockCenterError)?
                    .push((site.clone(), envelope.clone()));
                Ok(())
            })
        }
    }

    fn resolved_site() -> ResolvedSite {
        ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            site_fingerprint(),
        )
    }

    #[tokio::test]
    async fn the_engine_flushes_offers_processes_frames_and_acks_them() -> Result<(), Box<dyn Error>>
    {
        let site = resolved_site();
        let (session, mut outbound_rx, inbound_tx) = ChannelInboundSession::channel();
        let outbox = MockOutbox::new();
        let base = base_time();
        outbox.seed_offer(
            1,
            site.instance_id(),
            base,
            (base + Duration::minutes(15)).unix_timestamp(),
        );
        let consumer = RecorderConsumer::new();
        let registry = Arc::new(CenterSessionRegistry::new());
        registry.mark_connected(site.clone(), base)?;
        let engine = CenterInboundEngine::new(
            session,
            outbox.clone(),
            consumer.clone(),
            Arc::clone(&registry),
            FixedClock(base + Duration::SECOND),
            site.clone(),
            CenterInboundOptions::default(),
        );
        let task = tokio::spawn(engine.run(std::future::pending::<()>()));

        // The engine's first outbound frame is the initial offer flush.
        let first = outbound_rx.recv().await.ok_or("no offer frame")?;
        assert_eq!(first.sequence, 1);
        assert!(matches!(
            first.message,
            Some(EnvelopeMessage::OperationOffer(_))
        ));

        // The site sends one event batch; the engine processes it and acks
        // the delivery (sequence 0, like the site-side heartbeat frames).
        let batch = Envelope {
            sequence: 5,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::EventBatch(
                rutilus_center_protocol::EventBatch { events: Vec::new() },
            )),
        };
        inbound_tx.send(batch.clone())?;
        let ack = outbound_rx.recv().await.ok_or("no ack frame")?;
        assert_eq!(ack.sequence, 0, "delivery frames carry sequence 0");
        assert!(matches!(
            ack.message,
            Some(EnvelopeMessage::Ack(rutilus_center_protocol::Ack {
                sequence: 5
            }))
        ));

        // A second content frame carries the site's acknowledgement
        // watermark; once its ack arrives, the offer was retired.
        let second_batch = Envelope {
            sequence: 6,
            acked_sequence: 1,
            message: Some(EnvelopeMessage::EventBatch(
                rutilus_center_protocol::EventBatch { events: Vec::new() },
            )),
        };
        inbound_tx.send(second_batch.clone())?;
        let ack = outbound_rx.recv().await.ok_or("no second ack frame")?;
        assert!(matches!(
            ack.message,
            Some(EnvelopeMessage::Ack(rutilus_center_protocol::Ack {
                sequence: 6
            }))
        ));

        // The consumer saw exactly the two event batches, in order.
        let frames = consumer.frames_owned();
        assert_eq!(frames, vec![batch, second_batch]);

        // The site's piggybacked acknowledgement retired the offer.
        assert!(outbox.pending_sequences(site.instance_id()).is_empty());
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn the_sites_acknowledgement_retires_the_center_outbox() -> Result<(), Box<dyn Error>> {
        let site = resolved_site();
        let (session, mut outbound_rx, inbound_tx) = ChannelInboundSession::channel();
        let outbox = MockOutbox::new();
        let base = base_time();
        outbox.seed_offer(
            1,
            site.instance_id(),
            base,
            (base + Duration::minutes(15)).unix_timestamp(),
        );
        outbox.seed_offer(
            2,
            site.instance_id(),
            base,
            (base + Duration::minutes(15)).unix_timestamp(),
        );
        let consumer = RecorderConsumer::new();
        let registry = Arc::new(CenterSessionRegistry::new());
        registry.mark_connected(site.clone(), base)?;
        let engine = CenterInboundEngine::new(
            session,
            outbox.clone(),
            consumer.clone(),
            Arc::clone(&registry),
            FixedClock(base + Duration::SECOND),
            site.clone(),
            CenterInboundOptions::default(),
        );
        let task = tokio::spawn(engine.run(std::future::pending::<()>()));

        // Both offers travel on the connection.
        let first = outbound_rx.recv().await.ok_or("no first offer")?;
        assert_eq!(first.sequence, 1);
        let second = outbound_rx.recv().await.ok_or("no second offer")?;
        assert_eq!(second.sequence, 2);

        // A content frame carrying the site's acknowledgement watermark
        // retires both entries once its delivery ack confirms the frame was
        // processed.
        inbound_tx.send(Envelope {
            sequence: 10,
            acked_sequence: 2,
            message: Some(EnvelopeMessage::EventBatch(
                rutilus_center_protocol::EventBatch { events: Vec::new() },
            )),
        })?;
        let ack = outbound_rx.recv().await.ok_or("no ack")?;
        assert!(matches!(
            ack.message,
            Some(EnvelopeMessage::Ack(rutilus_center_protocol::Ack {
                sequence: 10
            }))
        ));
        assert!(outbox.pending_sequences(site.instance_id()).is_empty());

        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn a_clean_close_removes_the_site_from_the_registry() -> Result<(), Box<dyn Error>> {
        let site = resolved_site();
        let (session, _outbound_rx, inbound_tx) = ChannelInboundSession::channel();
        let outbox = MockOutbox::new();
        let consumer = RecorderConsumer::new();
        let registry = Arc::new(CenterSessionRegistry::new());
        registry.mark_connected(site.clone(), base_time())?;
        let engine = CenterInboundEngine::new(
            session,
            outbox,
            consumer,
            Arc::clone(&registry),
            FixedClock(base_time() + Duration::SECOND),
            site.clone(),
            CenterInboundOptions::default(),
        );

        let task = tokio::spawn(engine.run(std::future::pending::<()>()));
        // The site's side of the connection ends; the engine observes the
        // clean close and removes the site from the registry.
        drop(inbound_tx);
        task.await.map_err(std::io::Error::other)??;
        assert!(!registry.is_online(site.instance_id()));
        Ok(())
    }

    #[tokio::test]
    async fn expired_offers_are_retired_and_live_offers_are_still_sent()
    -> Result<(), Box<dyn Error>> {
        let site = resolved_site();
        let (session, mut outbound_rx, inbound_tx) = ChannelInboundSession::channel();
        let outbox = MockOutbox::new();
        let base = base_time();
        // The first offer expired a minute ago (§15.6 TTL); the second is
        // still actionable when the connection opens.
        outbox.seed_offer(1, site.instance_id(), base, base.unix_timestamp() - 60);
        outbox.seed_offer(
            2,
            site.instance_id(),
            base,
            (base + Duration::minutes(15)).unix_timestamp(),
        );
        let consumer = RecorderConsumer::new();
        let registry = Arc::new(CenterSessionRegistry::new());
        registry.mark_connected(site.clone(), base)?;
        let engine = CenterInboundEngine::new(
            session,
            outbox.clone(),
            consumer.clone(),
            Arc::clone(&registry),
            FixedClock(base + Duration::SECOND),
            site.clone(),
            CenterInboundOptions::default(),
        );
        let task = tokio::spawn(engine.run(std::future::pending::<()>()));

        // Only the live offer travels on the connection; the expired one
        // was retired by the flush, so it is never re-sent.
        let first = outbound_rx.recv().await.ok_or("no offer frame")?;
        assert_eq!(first.sequence, 2);
        assert!(matches!(
            first.message,
            Some(EnvelopeMessage::OperationOffer(_))
        ));
        assert_eq!(outbox.pending_sequences(site.instance_id()), vec![2]);

        // The site's piggybacked acknowledgement retires the live offer.
        inbound_tx.send(Envelope {
            sequence: 5,
            acked_sequence: 2,
            message: Some(EnvelopeMessage::EventBatch(
                rutilus_center_protocol::EventBatch { events: Vec::new() },
            )),
        })?;
        let ack = outbound_rx.recv().await.ok_or("no ack frame")?;
        assert!(matches!(
            ack.message,
            Some(EnvelopeMessage::Ack(rutilus_center_protocol::Ack {
                sequence: 5
            }))
        ));
        assert!(outbox.pending_sequences(site.instance_id()).is_empty());
        task.abort();
        Ok(())
    }
}
