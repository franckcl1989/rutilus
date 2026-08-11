//! The §14.2 homepage aggregation use case: one server-derived, read-only
//! dashboard summary of the whole managed fleet.
//!
//! The design's homepage display list (§14.2 多服务器首页) — endpoint counts,
//! vendor distribution, unified health distribution, firmware inventory
//! summary, capability coverage, running operations, recent events, and data
//! staleness — is served as one aggregate instead of one request per block.
//! The use case composes only existing query boundaries (the endpoint
//! inventory and per-endpoint resource inventories, the capability query,
//! the operation store, and the event repository), so no new persistence
//! surface exists and the aggregate can never disagree with the individual
//! views: it derives from the same persisted facts.
//!
//! Honest derivations (see the api contract for the wire semantics):
//! - The product does not model online/offline/auth-failed reachability, so
//!   the endpoint split is by snapshot state: an endpoint with a complete
//!   resource Generation last refreshed successfully, one awaiting its first
//!   refresh has never completed one (§9.5).
//! - The unified §12.3 health level is the worst `Health` of the endpoint's
//!   System, Chassis, and Manager statuses, classified case-insensitively
//!   over the Redfish vocabulary; an endpoint without any observed health is
//!   `Unknown`, never "healthy".
//! - Capability coverage counts only observed ledger entries: an entry whose
//!   endpoint never completed a probe has no state and is not counted as
//!   supported or unsupported.
//! - Data staleness is derived at serving time from each endpoint's last
//!   successful refresh against the `now` the caller supplies (the Web
//!   handler passes its injected clock).
//!
//! The use case is read-only by construction: it never writes, so the §16.1
//! Viewer role may call it.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    num::NonZeroU64,
};

use rutilus_domain::{CapabilityState, EndpointId, Event};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::{
    CapabilityQueryRepository, CoreResourceDetails, CoreResourceSummary, EndpointInventoryQuery,
    EndpointInventoryQueryError, EndpointInventoryRepository, EndpointResourceInventoryQuery,
    EndpointResourceInventoryQueryError, EventRepository, OperationStore, StoredCapability,
};

/// The maximum size of the §14.2 homepage recent-event tail. The wire
/// contract mirrors this bound as `rutilus_api::OVERVIEW_RECENT_EVENTS`.
pub const OVERVIEW_RECENT_EVENTS: u64 = 5;

/// The unified §12.3 health level of one endpoint as the homepage aggregate
/// derives it.
///
/// `Unknown` ranks lowest because it means "no health observed yet", not
/// "healthy" (§12.3), and the ordering drives the worst-of aggregation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OverviewHealthLevel {
    Unknown,
    Ok,
    Warning,
    Critical,
}

/// The §14.2 homepage data-staleness age class of one endpoint's last
/// successful refresh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverviewFreshnessBucket {
    /// No complete refresh has ever succeeded (§9.5).
    NeverRefreshed,
    /// The last successful refresh is less than one hour old.
    WithinOneHour,
    /// The last successful refresh is at least one hour and less than one
    /// day old.
    WithinOneDay,
    /// The last successful refresh is at least one day and less than seven
    /// days old.
    WithinSevenDays,
    /// The last successful refresh is at least seven days old.
    OlderThanSevenDays,
}

/// One §14.2 homepage vendor-distribution bucket; `None` is the honest
/// "no Service Root `Vendor` published yet" bucket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverviewVendorCount {
    vendor: Option<String>,
    count: u64,
}

impl OverviewVendorCount {
    #[must_use]
    pub const fn new(vendor: Option<String>, count: u64) -> Self {
        Self { vendor, count }
    }

    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// One §14.2 homepage health-distribution bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewHealthCount {
    level: OverviewHealthLevel,
    count: u64,
}

impl OverviewHealthCount {
    #[must_use]
    pub const fn new(level: OverviewHealthLevel, count: u64) -> Self {
        Self { level, count }
    }

    #[must_use]
    pub const fn level(&self) -> OverviewHealthLevel {
        self.level
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// The §14.2 homepage firmware-inventory summary over the §2.1
/// `update-service` `SoftwareInventory` family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewFirmwareSummary {
    endpoints_with_inventory: u64,
    entries: u64,
    distinct_versions: u64,
}

impl OverviewFirmwareSummary {
    #[must_use]
    pub const fn new(endpoints_with_inventory: u64, entries: u64, distinct_versions: u64) -> Self {
        Self {
            endpoints_with_inventory,
            entries,
            distinct_versions,
        }
    }

    #[must_use]
    pub const fn endpoints_with_inventory(&self) -> u64 {
        self.endpoints_with_inventory
    }

    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    #[must_use]
    pub const fn distinct_versions(&self) -> u64 {
        self.distinct_versions
    }
}

/// The §14.2 homepage capability coverage across every endpoint's §2.4
/// capability ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewCapabilityCoverage {
    observed_entries: u64,
    supported_entries: u64,
}

impl OverviewCapabilityCoverage {
    #[must_use]
    pub const fn new(observed_entries: u64, supported_entries: u64) -> Self {
        Self {
            observed_entries,
            supported_entries,
        }
    }

    #[must_use]
    pub const fn observed_entries(&self) -> u64 {
        self.observed_entries
    }

    #[must_use]
    pub const fn supported_entries(&self) -> u64 {
        self.supported_entries
    }
}

/// One §14.2 homepage staleness bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewFreshnessCount {
    bucket: OverviewFreshnessBucket,
    count: u64,
}

impl OverviewFreshnessCount {
    #[must_use]
    pub const fn new(bucket: OverviewFreshnessBucket, count: u64) -> Self {
        Self { bucket, count }
    }

    #[must_use]
    pub const fn bucket(&self) -> OverviewFreshnessBucket {
        self.bucket
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// The §14.2 homepage endpoint-count block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverviewEndpointCounts {
    total: u64,
    with_current_snapshot: u64,
    awaiting_first_refresh: u64,
}

impl OverviewEndpointCounts {
    #[must_use]
    pub const fn new(total: u64, with_current_snapshot: u64, awaiting_first_refresh: u64) -> Self {
        Self {
            total,
            with_current_snapshot,
            awaiting_first_refresh,
        }
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    #[must_use]
    pub const fn with_current_snapshot(&self) -> u64 {
        self.with_current_snapshot
    }

    #[must_use]
    pub const fn awaiting_first_refresh(&self) -> u64 {
        self.awaiting_first_refresh
    }
}

/// One server-derived §14.2 homepage dashboard summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverviewAggregate {
    endpoints: OverviewEndpointCounts,
    vendors: Vec<OverviewVendorCount>,
    health: Vec<OverviewHealthCount>,
    firmware: OverviewFirmwareSummary,
    capabilities: OverviewCapabilityCoverage,
    running_operations: u64,
    recent_events: Vec<Event>,
    freshness: Vec<OverviewFreshnessCount>,
}

impl OverviewAggregate {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        endpoints: OverviewEndpointCounts,
        vendors: Vec<OverviewVendorCount>,
        health: Vec<OverviewHealthCount>,
        firmware: OverviewFirmwareSummary,
        capabilities: OverviewCapabilityCoverage,
        running_operations: u64,
        recent_events: Vec<Event>,
        freshness: Vec<OverviewFreshnessCount>,
    ) -> Self {
        Self {
            endpoints,
            vendors,
            health,
            firmware,
            capabilities,
            running_operations,
            recent_events,
            freshness,
        }
    }

    #[must_use]
    pub const fn endpoints(&self) -> &OverviewEndpointCounts {
        &self.endpoints
    }

    #[must_use]
    pub fn vendors(&self) -> &[OverviewVendorCount] {
        &self.vendors
    }

    #[must_use]
    pub fn health(&self) -> &[OverviewHealthCount] {
        &self.health
    }

    #[must_use]
    pub const fn firmware(&self) -> &OverviewFirmwareSummary {
        &self.firmware
    }

    #[must_use]
    pub const fn capabilities(&self) -> &OverviewCapabilityCoverage {
        &self.capabilities
    }

    #[must_use]
    pub const fn running_operations(&self) -> u64 {
        self.running_operations
    }

    #[must_use]
    pub fn recent_events(&self) -> &[Event] {
        &self.recent_events
    }

    #[must_use]
    pub fn freshness(&self) -> &[OverviewFreshnessCount] {
        &self.freshness
    }
}

/// Loads the §14.2 homepage aggregate over the four read-only boundaries the
/// blocks derive from.
///
/// The inventory boundary also backs the per-endpoint resource-inventory
/// reads (the §12.3 vendor/health and the §2.1 `SoftwareInventory` facts live
/// in the typed resource payloads), so the same repository reference feeds
/// both the inventory query and the per-endpoint fan-out.
pub struct OverviewQuery<Inventory, Capabilities, Operations, Events> {
    inventory: Inventory,
    capabilities: Capabilities,
    operations: Operations,
    events: Events,
}

impl<Inventory, Capabilities, Operations, Events>
    OverviewQuery<Inventory, Capabilities, Operations, Events>
where
    Inventory: EndpointInventoryRepository,
    Capabilities: CapabilityQueryRepository,
    Operations: OperationStore,
    Events: EventRepository,
{
    #[must_use]
    pub const fn new(
        inventory: Inventory,
        capabilities: Capabilities,
        operations: Operations,
        events: Events,
    ) -> Self {
        Self {
            inventory,
            capabilities,
            operations,
            events,
        }
    }

    /// Derives the whole §14.2 dashboard summary at the given serving time.
    ///
    /// # Errors
    ///
    /// Returns [`OverviewQueryError`] when any composed boundary fails. The
    /// aggregate is a fleet-wide summary, so a failing block never degrades
    /// into a partial dashboard: the caller reports the whole query
    /// unavailable exactly like the single-block handlers do.
    pub async fn execute(
        &self,
        now: OffsetDateTime,
        recent_events_limit: NonZeroU64,
    ) -> Result<
        OverviewAggregate,
        OverviewQueryError<Inventory::Error, Capabilities::Error, Operations::Error, Events::Error>,
    > {
        let items = EndpointInventoryQuery::new(&self.inventory)
            .execute()
            .await
            .map_err(OverviewQueryError::Inventory)?;

        let mut fleet = FleetAccumulator::new();
        for item in &items {
            let endpoint_id = item.endpoint().id();
            fleet.count_endpoint(item, now);

            // The §12.3 vendor/health and the §2.1 `SoftwareInventory` facts
            // live in the typed resource payloads, so the block derivation
            // reuses the per-endpoint resource-inventory projection — the
            // same typed read the §12.2 Endpoint page serves. `Ok(None)`
            // cannot occur for an inventory-listed endpoint and is treated as
            // an empty resource set.
            let resources = EndpointResourceInventoryQuery::new(&self.inventory, endpoint_id)
                .execute()
                .await
                .map_err(|source| OverviewQueryError::Resources {
                    endpoint_id,
                    source,
                })?
                .map(|inventory| inventory.resources().to_vec())
                .unwrap_or_default();
            fleet.count_resources(&resources);

            let observations = match self
                .capabilities
                .find_endpoint_capabilities(endpoint_id)
                .await
            {
                Ok(Some(observations)) => observations,
                Ok(None) => Vec::new(),
                Err(source) => return Err(OverviewQueryError::Capabilities(source)),
            };
            fleet.count_capabilities(observations);
        }

        let operations = self
            .operations
            .list_operations(None)
            .await
            .map_err(OverviewQueryError::Operations)?;
        let running_operations = operations.iter().fold(0_u64, |count, operation| {
            count + u64::from(operation.state().is_active())
        });

        let events = self
            .events
            .list_recent_events(recent_events_limit)
            .await
            .map_err(OverviewQueryError::Events)?;

        Ok(fleet.finish(running_operations, events))
    }
}

/// The per-endpoint accumulation state of one §14.2 dashboard derivation.
///
/// The block counters stay together so [`OverviewQuery::execute`] reads as a
/// fan-out loop and every compaction rule (deterministic ordering, zero
/// buckets omitted) lives in one place.
struct FleetAccumulator {
    endpoints: OverviewEndpointCounts,
    vendor_counts: BTreeMap<Option<String>, u64>,
    health_counts: [u64; 4],
    firmware: OverviewFirmwareSummary,
    distinct_versions: u64,
    version_set: BTreeSet<String>,
    freshness_counts: [u64; 5],
    observed_entries: u64,
    supported_entries: u64,
}

impl FleetAccumulator {
    fn new() -> Self {
        Self {
            endpoints: OverviewEndpointCounts::new(0, 0, 0),
            vendor_counts: BTreeMap::new(),
            health_counts: [0_u64; 4],
            firmware: OverviewFirmwareSummary::new(0, 0, 0),
            distinct_versions: 0,
            version_set: BTreeSet::new(),
            freshness_counts: [0_u64; 5],
            observed_entries: 0,
            supported_entries: 0,
        }
    }

    /// Counts one managed endpoint into the snapshot-split, staleness, and
    /// vendor blocks. The vendor needs the typed resources, so
    /// [`Self::count_resources`] adds it right after.
    fn count_endpoint(&mut self, item: &crate::EndpointInventoryItem, now: OffsetDateTime) {
        self.endpoints = OverviewEndpointCounts::new(
            self.endpoints.total() + 1,
            self.endpoints.with_current_snapshot() + u64::from(item.generation().is_some()),
            self.endpoints.awaiting_first_refresh() + u64::from(item.generation().is_none()),
        );
        self.freshness_counts
            [usize::from(freshness_bucket(now, item.last_successful_refresh_at()))] += 1;
    }

    /// Counts one endpoint's typed resources into the §12.3 vendor/health
    /// and the §2.1 `SoftwareInventory` blocks.
    fn count_resources(&mut self, resources: &[CoreResourceSummary]) {
        let vendor = endpoint_vendor(resources);
        self.vendor_counts
            .entry(vendor)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        self.health_counts[usize::from(aggregate_health(resources))] += 1;
        let mut endpoint_has_inventory = false;
        for resource in resources {
            let CoreResourceDetails::SoftwareInventory { version, .. } = resource.details() else {
                continue;
            };
            endpoint_has_inventory = true;
            self.firmware = OverviewFirmwareSummary::new(
                self.firmware.endpoints_with_inventory(),
                self.firmware.entries() + 1,
                self.distinct_versions,
            );
            if let Some(version) = version.as_ref()
                && self.version_set.insert(version.clone())
            {
                self.distinct_versions += 1;
            }
        }
        if endpoint_has_inventory {
            self.firmware = OverviewFirmwareSummary::new(
                self.firmware.endpoints_with_inventory() + 1,
                self.firmware.entries(),
                self.distinct_versions,
            );
        }
    }

    /// Counts one endpoint's observed capability ledger into the coverage
    /// block.
    fn count_capabilities(&mut self, observations: Vec<StoredCapability>) {
        for stored in observations {
            self.observed_entries += 1;
            if stored.observation().state() == CapabilityState::Supported {
                self.supported_entries += 1;
            }
        }
    }

    /// Compacts the counters into the final aggregate with the deterministic
    /// orderings of the wire contract.
    fn finish(self, running_operations: u64, recent_events: Vec<Event>) -> OverviewAggregate {
        OverviewAggregate::new(
            self.endpoints,
            non_zero_vendor_counts(self.vendor_counts),
            non_zero_health_counts(self.health_counts),
            self.firmware,
            OverviewCapabilityCoverage::new(self.observed_entries, self.supported_entries),
            running_operations,
            recent_events,
            non_zero_freshness_counts(self.freshness_counts),
        )
    }
}

/// The §12.3 unified vendor of one endpoint's resource set, from its Service
/// Root resource.
fn endpoint_vendor(resources: &[CoreResourceSummary]) -> Option<String> {
    resources
        .iter()
        .find_map(|resource| match resource.details() {
            CoreResourceDetails::ServiceRoot { vendor, .. } => vendor.clone(),
            _ => None,
        })
}

/// A controlled failure while loading the §14.2 homepage aggregate.
///
/// The four generic parameters are the error types of the four composed
/// boundaries, so every persistence failure stays reachable as the source of
/// an error chain.
#[derive(Debug, Error)]
pub enum OverviewQueryError<InventoryError, CapabilityError, OperationError, EventError>
where
    InventoryError: Error + 'static,
    CapabilityError: Error + 'static,
    OperationError: Error + 'static,
    EventError: Error + 'static,
{
    /// The managed-endpoint inventory could not be loaded.
    #[error("failed to load endpoint inventory: {0}")]
    Inventory(#[source] EndpointInventoryQueryError<InventoryError>),
    /// One endpoint's typed resource inventory could not be loaded or
    /// projected.
    #[error("failed to load the resource inventory of endpoint {endpoint_id}: {source}")]
    Resources {
        endpoint_id: EndpointId,
        #[source]
        source: EndpointResourceInventoryQueryError<InventoryError>,
    },
    /// One endpoint's capability observations could not be loaded.
    #[error("failed to load capability observations: {0}")]
    Capabilities(#[source] CapabilityError),
    /// The operation listing could not be loaded.
    #[error("failed to load operations: {0}")]
    Operations(#[source] OperationError),
    /// The recent-event tail could not be loaded.
    #[error("failed to load recent events: {0}")]
    Events(#[source] EventError),
}

/// The unified §12.3 health level of one endpoint's resource set: the worst
/// `Health` of its System, Chassis, and Manager statuses, with `Unknown`
/// when no resource published a health yet.
fn aggregate_health(resources: &[CoreResourceSummary]) -> OverviewHealthLevel {
    resources
        .iter()
        .filter_map(|resource| match resource.details() {
            CoreResourceDetails::System { status, .. }
            | CoreResourceDetails::Chassis { status, .. }
            | CoreResourceDetails::Manager { status, .. } => status.as_ref(),
            _ => None,
        })
        .filter_map(|status| status.health().and_then(health_level_of))
        .max()
        .unwrap_or(OverviewHealthLevel::Unknown)
}

/// Maps one raw Redfish status-health text (§12.3 original value) to the
/// unified §12.3 level; an unknown spelling contributes no health.
fn health_level_of(health: &str) -> Option<OverviewHealthLevel> {
    if health.eq_ignore_ascii_case("ok") {
        Some(OverviewHealthLevel::Ok)
    } else if health.eq_ignore_ascii_case("warning") {
        Some(OverviewHealthLevel::Warning)
    } else if health.eq_ignore_ascii_case("critical") {
        Some(OverviewHealthLevel::Critical)
    } else {
        None
    }
}

/// The §14.2 staleness bucket of one endpoint's last successful refresh.
fn freshness_bucket(
    now: OffsetDateTime,
    last_successful_refresh_at: Option<OffsetDateTime>,
) -> OverviewFreshnessBucket {
    let Some(last_refresh) = last_successful_refresh_at else {
        return OverviewFreshnessBucket::NeverRefreshed;
    };
    let age = now - last_refresh;
    if age < Duration::HOUR {
        OverviewFreshnessBucket::WithinOneHour
    } else if age < Duration::DAY {
        OverviewFreshnessBucket::WithinOneDay
    } else if age < Duration::days(7) {
        OverviewFreshnessBucket::WithinSevenDays
    } else {
        OverviewFreshnessBucket::OlderThanSevenDays
    }
}

/// The bucket index into the [`OverviewAggregate`] health-count array:
/// worst-first order (critical, warning, ok, unknown).
impl From<OverviewHealthLevel> for usize {
    fn from(level: OverviewHealthLevel) -> usize {
        match level {
            OverviewHealthLevel::Critical => 0,
            OverviewHealthLevel::Warning => 1,
            OverviewHealthLevel::Ok => 2,
            OverviewHealthLevel::Unknown => 3,
        }
    }
}

/// The bucket index into the [`OverviewAggregate`] freshness-count array:
/// never refreshed, then newest-first age buckets.
impl From<OverviewFreshnessBucket> for usize {
    fn from(bucket: OverviewFreshnessBucket) -> usize {
        match bucket {
            OverviewFreshnessBucket::NeverRefreshed => 0,
            OverviewFreshnessBucket::WithinOneHour => 1,
            OverviewFreshnessBucket::WithinOneDay => 2,
            OverviewFreshnessBucket::WithinSevenDays => 3,
            OverviewFreshnessBucket::OlderThanSevenDays => 4,
        }
    }
}

/// Compacts the vendor distribution to the present buckets in deterministic
/// order: the unobserved bucket first, then alphabetical.
fn non_zero_vendor_counts(counts: BTreeMap<Option<String>, u64>) -> Vec<OverviewVendorCount> {
    counts
        .into_iter()
        .map(|(vendor, count)| OverviewVendorCount::new(vendor, count))
        .collect()
}

/// Compacts the health distribution to the present buckets in deterministic
/// worst-first order (critical, warning, ok, unknown).
fn non_zero_health_counts(counts: [u64; 4]) -> Vec<OverviewHealthCount> {
    [
        (OverviewHealthLevel::Critical, counts[0]),
        (OverviewHealthLevel::Warning, counts[1]),
        (OverviewHealthLevel::Ok, counts[2]),
        (OverviewHealthLevel::Unknown, counts[3]),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(level, count)| OverviewHealthCount::new(level, count))
    .collect()
}

/// Compacts the staleness distribution to the present buckets in
/// deterministic order: never refreshed, then newest-first age buckets.
fn non_zero_freshness_counts(counts: [u64; 5]) -> Vec<OverviewFreshnessCount> {
    [
        (OverviewFreshnessBucket::NeverRefreshed, counts[0]),
        (OverviewFreshnessBucket::WithinOneHour, counts[1]),
        (OverviewFreshnessBucket::WithinOneDay, counts[2]),
        (OverviewFreshnessBucket::WithinSevenDays, counts[3]),
        (OverviewFreshnessBucket::OlderThanSevenDays, counts[4]),
    ]
    .into_iter()
    .filter(|(_, count)| *count > 0)
    .map(|(bucket, count)| OverviewFreshnessCount::new(bucket, count))
    .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, fmt};

    use rutilus_domain::{
        CapabilityState, CredentialId, Endpoint, EndpointAddress, EndpointCapability,
        EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event, EventId,
        EventSeverity, MessageId, Operation, OperationId, OperationSource, OperationState,
        OperationTarget, RedfishCommand, RefreshGeneration, ResetType, ResourceFeature, ResourceId,
        ResourceODataId, ResourceSnapshot, ResourceSnapshotPayload, SystemCommand, TargetId,
        TlsCertificate, TlsTrust,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::{BoundaryFuture, EndpointInventoryItem, StoredCapability};

    const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn limit() -> Result<NonZeroU64, Box<dyn Error>> {
        Ok(NonZeroU64::new(OVERVIEW_RECENT_EVENTS)
            .ok_or("the recent-events limit constant must be positive")?)
    }

    /// Which mock boundary fails on the next query.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockFailure {
        Inventory,
        Capabilities,
        Operations,
        Events,
    }

    fn endpoint(name: &str, index: u8) -> Result<Endpoint, Box<dyn Error>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse(name)?,
            EndpointAddress::parse(&format!("https://192.0.2.{index}"))?,
            TlsTrust::SystemCa {
                certificate: TlsCertificate::from_der(format!("certificate {index}").into_bytes())?,
                verified_at: NOW,
            },
            CredentialId::generate(),
            NOW,
            NOW,
        )?)
    }

    fn snapshot(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            RefreshGeneration::new(1)?,
        ))
    }

    fn service_root(vendor: Option<&str>) -> String {
        match vendor {
            Some(vendor) => format!(r#"{{"Id":"Root","Name":"Root","Vendor":"{vendor}"}}"#),
            None => r#"{"Id":"Root","Name":"Root"}"#.to_owned(),
        }
    }

    fn system(health: Option<&str>) -> String {
        match health {
            Some(health) => {
                format!(r#"{{"Id":"1","Name":"System","Status":{{"Health":"{health}"}}}}"#)
            }
            None => r#"{"Id":"1","Name":"System"}"#.to_owned(),
        }
    }

    fn software_inventory(version: Option<&str>) -> String {
        // `ReleaseDate` is a required wire property of the typed payload
        // (the `Edm.DateTimeOffset` projection), so the fixture pins it as
        // null.
        match version {
            Some(version) => {
                format!(r#"{{"Id":"BIOS","Name":"BIOS","Version":"{version}","ReleaseDate":null}}"#)
            }
            None => r#"{"Id":"BIOS","Name":"BIOS","ReleaseDate":null}"#.to_owned(),
        }
    }

    fn inventory_item(
        endpoint: Endpoint,
        resources: Vec<ResourceSnapshot>,
    ) -> Result<EndpointInventoryItem, Box<dyn Error>> {
        Ok(EndpointInventoryItem::try_new(endpoint, resources)?)
    }

    fn operation(
        state: OperationState,
        created_at: OffsetDateTime,
    ) -> Result<Operation, Box<dyn Error>> {
        Ok(Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            state,
            created_at,
            created_at,
        )?)
    }

    fn event(
        endpoint_id: EndpointId,
        observed_at: OffsetDateTime,
    ) -> Result<Event, Box<dyn Error>> {
        Ok(Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse("Alert.1.0.PowerSupplyFailure")?,
            EventSeverity::Critical,
            None,
            observed_at,
            observed_at,
        )?)
    }

    #[derive(Clone)]
    struct MockBoundaries {
        inventory: Vec<EndpointInventoryItem>,
        capabilities: HashMap<EndpointId, Vec<StoredCapability>>,
        operations: Vec<Operation>,
        events: Vec<Event>,
        fail: Option<MockFailure>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl Error for MockError {}
    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock overview boundary failed")
        }
    }

    impl EndpointInventoryRepository for MockBoundaries {
        type Error = MockError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            let items = self.inventory.clone();
            let fail = self.fail == Some(MockFailure::Inventory);
            Box::pin(async move {
                if fail {
                    return Err(MockError);
                }
                Ok(items)
            })
        }
    }

    impl CapabilityQueryRepository for MockBoundaries {
        type Error = MockError;

        fn find_endpoint_capabilities(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            let capabilities = self.capabilities.get(&endpoint_id).cloned();
            let fail = self.fail == Some(MockFailure::Capabilities);
            Box::pin(async move {
                if fail {
                    return Err(MockError);
                }
                Ok(capabilities)
            })
        }
    }

    impl OperationStore for MockBoundaries {
        type Error = MockError;

        fn create_operation<'a>(
            &'a self,
            _operation: &'a Operation,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn find_operation(
            &self,
            _operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn apply_transition(
            &self,
            _operation_id: OperationId,
            _new_state: OperationState,
            _occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            let operations = self.operations.clone();
            let fail = self.fail == Some(MockFailure::Operations);
            Box::pin(async move {
                if fail {
                    return Err(MockError);
                }
                Ok(operations)
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a rutilus_domain::BatchOperation,
            _children: &'a [Operation],
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: rutilus_domain::FailureKind,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn find_batch(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>>
        {
            Box::pin(async { Err(MockError) })
        }

        fn list_batches(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn list_batch_children(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Vec<crate::ClassifiedBatchChild>, Self::Error>> {
            Box::pin(async { Err(MockError) })
        }
    }

    impl EventRepository for MockBoundaries {
        type Error = MockError;

        fn append_event<'a>(
            &'a self,
            _event: &'a Event,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockError) })
        }

        fn list_recent_events(
            &self,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
            let events = self.events.clone();
            let fail = self.fail == Some(MockFailure::Events);
            Box::pin(async move {
                if fail {
                    return Err(MockError);
                }
                Ok(events)
            })
        }
    }

    fn stored(capability: EndpointCapability, state: CapabilityState) -> StoredCapability {
        StoredCapability::new(EndpointCapabilityObservation::new(capability, state), NOW)
    }

    fn query(
        boundaries: &MockBoundaries,
    ) -> OverviewQuery<&MockBoundaries, &MockBoundaries, &MockBoundaries, &MockBoundaries> {
        OverviewQuery::new(boundaries, boundaries, boundaries, boundaries)
    }

    /// Builds one refreshed endpoint: a Service Root with the given vendor, a
    /// System with the given health, and one `SoftwareInventory` member per
    /// given version — the §12.2 typed resource surface the aggregate reads.
    fn refreshed_item(
        name: &str,
        index: u8,
        vendor: Option<&str>,
        health: Option<&str>,
        firmware_versions: &[Option<&str>],
        refreshed_at: OffsetDateTime,
    ) -> Result<(Endpoint, EndpointInventoryItem), Box<dyn Error>> {
        let endpoint = endpoint(name, index)?;
        let endpoint_id = endpoint.id();
        let mut snapshots = vec![
            snapshot(
                endpoint_id,
                ResourceFeature::ServiceRoot,
                "/redfish/v1",
                &service_root(vendor),
                refreshed_at,
            )?,
            snapshot(
                endpoint_id,
                ResourceFeature::Systems,
                "/redfish/v1/Systems/1",
                &system(health),
                refreshed_at,
            )?,
        ];
        for (offset, version) in firmware_versions.iter().enumerate() {
            snapshots.push(snapshot(
                endpoint_id,
                ResourceFeature::SoftwareInventory,
                &format!("/redfish/v1/UpdateService/SoftwareInventory/{offset}"),
                &software_inventory(*version),
                refreshed_at,
            )?);
        }
        Ok((endpoint.clone(), inventory_item(endpoint, snapshots)?))
    }

    #[tokio::test]
    async fn aggregates_every_dashboard_block_from_the_boundaries() -> Result<(), Box<dyn Error>> {
        let (current, current_item) = refreshed_item(
            "Rack A BMC",
            10,
            Some("ACME"),
            Some("OK"),
            &[Some("1.2.3"), Some("1.2.3")],
            NOW - Duration::MINUTE,
        )?;
        let current_id = current.id();
        let (stale, stale_item) = refreshed_item(
            "Rack B BMC",
            11,
            Some("ACME"),
            Some("Critical"),
            &[Some("2.0.0")],
            NOW - Duration::days(9),
        )?;
        let stale_id = stale.id();
        let waiting = endpoint("Rack C BMC", 12)?;

        let boundaries = MockBoundaries {
            inventory: vec![
                current_item,
                stale_item,
                inventory_item(waiting, Vec::new())?,
            ],
            capabilities: HashMap::from([
                (
                    current_id,
                    vec![
                        stored(EndpointCapability::Systems, CapabilityState::Supported),
                        stored(
                            EndpointCapability::SessionService,
                            CapabilityState::NotAdvertised,
                        ),
                    ],
                ),
                (
                    stale_id,
                    vec![stored(
                        EndpointCapability::Managers,
                        CapabilityState::Supported,
                    )],
                ),
            ]),
            operations: vec![
                operation(OperationState::Running, NOW)?,
                operation(OperationState::Queued, NOW)?,
                operation(OperationState::Succeeded, NOW)?,
            ],
            events: vec![
                event(current_id, NOW)?,
                event(stale_id, NOW - Duration::MINUTE)?,
            ],
            fail: None,
        };

        let aggregate = query(&boundaries)
            .execute(NOW, limit()?)
            .await
            .map_err(|error| format!("overview query failed: {error}"))?;

        assert_eq!(aggregate.endpoints(), &OverviewEndpointCounts::new(3, 2, 1));
        assert_eq!(
            aggregate.vendors(),
            &[
                OverviewVendorCount::new(None, 1),
                OverviewVendorCount::new(Some("ACME".to_owned()), 2),
            ]
        );
        assert_eq!(
            aggregate.health(),
            &[
                OverviewHealthCount::new(OverviewHealthLevel::Critical, 1),
                OverviewHealthCount::new(OverviewHealthLevel::Ok, 1),
                OverviewHealthCount::new(OverviewHealthLevel::Unknown, 1),
            ]
        );
        assert_eq!(aggregate.firmware(), &OverviewFirmwareSummary::new(2, 3, 2));
        assert_eq!(
            aggregate.capabilities(),
            &OverviewCapabilityCoverage::new(3, 2)
        );
        assert_eq!(aggregate.running_operations(), 2);
        assert_eq!(aggregate.recent_events().len(), 2);
        assert_eq!(
            aggregate.freshness(),
            &[
                OverviewFreshnessCount::new(OverviewFreshnessBucket::NeverRefreshed, 1),
                OverviewFreshnessCount::new(OverviewFreshnessBucket::WithinOneHour, 1),
                OverviewFreshnessCount::new(OverviewFreshnessBucket::OlderThanSevenDays, 1),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn boundary_failures_map_to_the_matching_verdict() -> Result<(), Box<dyn Error>> {
        let current = endpoint("Rack A BMC", 20)?;
        let item = inventory_item(current, Vec::new())?;
        for (failure, verdict) in [
            (MockFailure::Inventory, "inventory"),
            (MockFailure::Capabilities, "capabilities"),
            (MockFailure::Operations, "operations"),
            (MockFailure::Events, "events"),
        ] {
            let boundaries = MockBoundaries {
                inventory: vec![item.clone()],
                capabilities: HashMap::new(),
                operations: Vec::new(),
                events: Vec::new(),
                fail: Some(failure),
            };
            let result = query(&boundaries).execute(NOW, limit()?).await;
            let Err(error) = result else {
                return Err(format!("the {verdict} failure must reject the query").into());
            };
            let kind = match error {
                OverviewQueryError::Inventory(_) => "inventory",
                OverviewQueryError::Capabilities(_) => "capabilities",
                OverviewQueryError::Operations(_) => "operations",
                OverviewQueryError::Events(_) => "events",
                OverviewQueryError::Resources { .. } => "resources",
            };
            assert_eq!(kind, verdict);
        }
        Ok(())
    }

    #[tokio::test]
    async fn empty_fleet_produces_an_empty_but_consistent_aggregate() -> Result<(), Box<dyn Error>>
    {
        let boundaries = MockBoundaries {
            inventory: Vec::new(),
            capabilities: HashMap::new(),
            operations: Vec::new(),
            events: Vec::new(),
            fail: None,
        };
        let aggregate = query(&boundaries).execute(NOW, limit()?).await?;
        assert_eq!(aggregate.endpoints(), &OverviewEndpointCounts::new(0, 0, 0));
        assert!(aggregate.vendors().is_empty());
        assert!(aggregate.health().is_empty());
        assert_eq!(aggregate.firmware(), &OverviewFirmwareSummary::new(0, 0, 0));
        assert_eq!(
            aggregate.capabilities(),
            &OverviewCapabilityCoverage::new(0, 0)
        );
        assert_eq!(aggregate.running_operations(), 0);
        assert!(aggregate.recent_events().is_empty());
        assert!(aggregate.freshness().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn freshness_buckets_follow_the_documented_age_classes() -> Result<(), Box<dyn Error>> {
        let (_, item) = refreshed_item(
            "Rack A BMC",
            30,
            Some("ACME"),
            None,
            &[None],
            NOW - Duration::HOUR,
        )?;
        let boundaries = MockBoundaries {
            inventory: vec![item],
            capabilities: HashMap::new(),
            operations: Vec::new(),
            events: Vec::new(),
            fail: None,
        };
        let aggregate = query(&boundaries)
            .execute(NOW + Duration::HOUR, limit()?)
            .await?;
        assert_eq!(
            aggregate.freshness(),
            &[OverviewFreshnessCount::new(
                OverviewFreshnessBucket::WithinOneDay,
                1
            )]
        );
        // A version-less inventory member still counts as an entry and as an
        // endpoint with inventory, but never as a distinct version.
        assert_eq!(aggregate.firmware(), &OverviewFirmwareSummary::new(1, 1, 0));
        // A System without a Status contributes no health: Unknown.
        assert_eq!(
            aggregate.health(),
            &[OverviewHealthCount::new(OverviewHealthLevel::Unknown, 1)]
        );
        Ok(())
    }
}
