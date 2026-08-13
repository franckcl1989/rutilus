use std::str::FromStr;

use rutilus_domain::{
    AuditAction, AuditActor, AuditCodeParseError, AuditEvent, AuditEventError, AuditEventId,
    AuditFailure, AuditFailureVerification, AuditOperationContext, AuditOperationContextError,
    AuditOperationId, AuditOutcome, AuditOutcomeKind, AuditParameterSummary,
    AuditParameterSummaryError, AuditProgress, AuditRedfishOperation, AuditSequence,
    AuditSequenceError, AuditTarget, AuditTlsTrust, AuditVerification, CredentialId,
    DeploymentPosture, DeploymentPostureParseError, EndpointAddress, EndpointAddressError,
    EndpointId, ProductPermission,
};
use rutilus_entity::audit_event;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Appends one event after validating the complete operation-local
    /// transition against the current tail in a coordinated transaction.
    ///
    /// No update or delete counterpart is exposed. Audit facts remain even if
    /// their referenced Endpoint or Credential is later removed.
    ///
    /// # Errors
    ///
    /// Returns [`AuditRepositoryError`] when the operation has no start, the
    /// sequence is not contiguous, immutable context changes, time moves
    /// backwards, an event follows a terminal outcome, stored history is
    /// corrupt, write coordination fails, or `SQLite` rejects the append.
    pub async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditRepositoryError> {
        let operation_id = event.context().operation_id();
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(AuditRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(AuditRepositoryError::Database)?;
        let models = audit_event::Entity::find()
            .filter(audit_event::Column::OperationId.eq(operation_id.into_uuid()))
            .order_by_asc(audit_event::Column::EventSequence)
            .all(&transaction)
            .await
            .map_err(AuditRepositoryError::Database)?;
        let existing = models
            .iter()
            .map(map_stored_event)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| corrupt(operation_id, source))?;
        validate_stored_trail(&existing).map_err(|source| corrupt(operation_id, source))?;

        validate_append(operation_id, existing.last(), event)?;
        project_event(event)
            .insert(&transaction)
            .await
            .map_err(AuditRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(AuditRepositoryError::Database)
    }

    /// Loads and revalidates one operation's complete append-only event trail
    /// in sequence order.
    ///
    /// An unknown operation returns an empty vector.
    ///
    /// # Errors
    ///
    /// Returns [`AuditRepositoryError`] when a query fails or any stored row,
    /// transition, timeline, or immutable context violates domain invariants.
    pub async fn find_audit_operation(
        &self,
        operation_id: AuditOperationId,
    ) -> Result<Vec<AuditEvent>, AuditRepositoryError> {
        let models = audit_event::Entity::find()
            .filter(audit_event::Column::OperationId.eq(operation_id.into_uuid()))
            .order_by_asc(audit_event::Column::EventSequence)
            .all(&self.database)
            .await
            .map_err(AuditRepositoryError::Database)?;
        let events = models
            .iter()
            .map(map_stored_event)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| corrupt(operation_id, source))?;
        validate_stored_trail(&events).map_err(|source| corrupt(operation_id, source))?;
        Ok(events)
    }
}

fn validate_append(
    operation_id: AuditOperationId,
    previous: Option<&AuditEvent>,
    event: &AuditEvent,
) -> Result<(), AuditRepositoryError> {
    let Some(previous) = previous else {
        if event.sequence() == AuditSequence::FIRST
            && event.outcome().kind() == AuditOutcomeKind::Started
        {
            return Ok(());
        }
        return Err(AuditRepositoryError::MissingStart {
            operation_id,
            actual: event.sequence(),
        });
    };
    if previous.outcome().is_terminal() {
        return Err(AuditRepositoryError::OperationTerminal {
            operation_id,
            terminal: previous.sequence(),
        });
    }
    let expected = previous
        .sequence()
        .next()
        .map_err(|source| AuditRepositoryError::Sequence {
            operation_id,
            source,
        })?;
    if event.sequence() != expected {
        return Err(AuditRepositoryError::NonContiguous {
            operation_id,
            expected,
            actual: event.sequence(),
        });
    }
    if event.context() != previous.context() {
        return Err(AuditRepositoryError::ContextChanged {
            operation_id,
            sequence: event.sequence(),
        });
    }
    if event.occurred_at() < previous.occurred_at() {
        return Err(AuditRepositoryError::EventPredatesPrevious {
            operation_id,
            sequence: event.sequence(),
        });
    }
    Ok(())
}

fn validate_stored_trail(events: &[AuditEvent]) -> Result<(), StoredAuditEventError> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    if first.sequence() != AuditSequence::FIRST
        || first.outcome().kind() != AuditOutcomeKind::Started
    {
        return Err(StoredAuditEventError::MissingStart);
    }
    let mut previous = first;
    for event in &events[1..] {
        if previous.outcome().is_terminal() {
            return Err(StoredAuditEventError::EventAfterTerminal {
                sequence: event.sequence(),
            });
        }
        let expected = previous
            .sequence()
            .next()
            .map_err(StoredAuditEventError::InvalidSequence)?;
        if event.sequence() != expected {
            return Err(StoredAuditEventError::NonContiguous {
                expected,
                actual: event.sequence(),
            });
        }
        if event.context() != previous.context() {
            return Err(StoredAuditEventError::ContextChanged {
                sequence: event.sequence(),
            });
        }
        if event.occurred_at() < previous.occurred_at() {
            return Err(StoredAuditEventError::EventPredatesPrevious {
                sequence: event.sequence(),
            });
        }
        previous = event;
    }
    Ok(())
}

fn project_event(event: &AuditEvent) -> audit_event::ActiveModel {
    let context = event.context();
    let (target_kind, target_endpoint_id, target_endpoint_address) = match context.target() {
        AuditTarget::Product => ("product", None, None),
        AuditTarget::EndpointAddress(address) => {
            ("endpoint-address", None, Some(address.to_string()))
        }
        AuditTarget::Endpoint(endpoint_id) => ("endpoint", Some(endpoint_id.into_uuid()), None),
    };
    let (parameter_kind, credential_id, trust_mode, row_count) = match context.parameters() {
        AuditParameterSummary::EndpointEnrollment {
            credential_id,
            trust,
        } => (
            "endpoint-enrollment",
            Some(credential_id.into_uuid()),
            Some(trust.as_str().to_owned()),
            None,
        ),
        AuditParameterSummary::EndpointRefresh => ("endpoint-refresh", None, None, None),
        AuditParameterSummary::CsvEndpointImport { row_count } => (
            "csv-endpoint-import",
            None,
            None,
            Some(i64::from(row_count)),
        ),
    };
    let outcome = event.outcome();
    audit_event::ActiveModel {
        id: Set(event.id().into_uuid()),
        operation_id: Set(context.operation_id().into_uuid()),
        event_sequence: Set(i64::from(event.sequence().get())),
        actor: Set(context.actor().as_str().to_owned()),
        actor_principal_id: Set(context
            .actor_principal_id()
            .map(rutilus_domain::PrincipalId::into_uuid)),
        target_principal_id: Set(context
            .target_principal_id()
            .map(rutilus_domain::PrincipalId::into_uuid)),
        origin: Set(context.origin().as_str().to_owned()),
        target_kind: Set(target_kind.to_owned()),
        target_endpoint_id: Set(target_endpoint_id),
        target_endpoint_address: Set(target_endpoint_address),
        parameter_kind: Set(parameter_kind.to_owned()),
        credential_id: Set(credential_id),
        trust_mode: Set(trust_mode),
        row_count: Set(row_count),
        permission: Set(context.permission().as_str().to_owned()),
        action: Set(context.action().as_str().to_owned()),
        redfish_operation: Set(context.redfish_operation().as_str().to_owned()),
        outcome: Set(outcome.kind().as_str().to_owned()),
        progress: Set(outcome
            .progress()
            .map(|progress| progress.as_str().to_owned())),
        failure: Set(outcome.failure().map(|failure| failure.as_str().to_owned())),
        verification: Set(outcome
            .verification()
            .map(|verification| verification.as_str().to_owned())),
        occurred_at: Set(event.occurred_at()),
    }
}

fn map_stored_event(model: &audit_event::Model) -> Result<AuditEvent, StoredAuditEventError> {
    let context = map_context(model)?;
    let sequence_value = u32::try_from(model.event_sequence)
        .map_err(|_| StoredAuditEventError::InvalidSequenceValue)?;
    let sequence =
        AuditSequence::try_new(sequence_value).map_err(StoredAuditEventError::InvalidSequence)?;
    let outcome = map_outcome(model)?;
    AuditEvent::try_from_parts(
        AuditEventId::from_uuid(model.id),
        context,
        sequence,
        outcome,
        model.occurred_at,
    )
    .map_err(StoredAuditEventError::InvalidEvent)
}

fn map_context(model: &audit_event::Model) -> Result<AuditOperationContext, StoredAuditEventError> {
    let actor = AuditActor::from_str(&model.actor).map_err(StoredAuditEventError::UnknownActor)?;
    let origin =
        DeploymentPosture::from_str(&model.origin).map_err(StoredAuditEventError::UnknownOrigin)?;
    let target = map_target(model)?;
    let parameters = map_parameters(model)?;
    let permission = ProductPermission::from_str(&model.permission)
        .map_err(StoredAuditEventError::UnknownPermission)?;
    let action =
        AuditAction::from_str(&model.action).map_err(StoredAuditEventError::UnknownAction)?;
    let redfish_operation = AuditRedfishOperation::from_str(&model.redfish_operation)
        .map_err(StoredAuditEventError::UnknownRedfishOperation)?;
    let context = AuditOperationContext::try_new_with_actor_principal(
        AuditOperationId::from_uuid(model.operation_id),
        actor,
        origin,
        target,
        parameters,
        permission,
        action,
        redfish_operation,
        model
            .actor_principal_id
            .map(rutilus_domain::PrincipalId::from_uuid),
    )
    .map_err(StoredAuditEventError::InvalidContext)?;
    match model.target_principal_id {
        Some(target_principal_id) => {
            // A target principal may only be recorded under an action that
            // names a subject distinct from its actor (S3-4); the schema
            // CHECK pins the same rule, so a stored row that violates it was
            // written by a build with a different contract and is corrupt.
            if !action.names_distinct_target_principal() {
                return Err(StoredAuditEventError::InvalidTargetPrincipalShape);
            }
            Ok(context
                .with_target_principal(rutilus_domain::PrincipalId::from_uuid(target_principal_id)))
        }
        None => Ok(context),
    }
}

fn map_target(model: &audit_event::Model) -> Result<AuditTarget, StoredAuditEventError> {
    match (
        model.target_kind.as_str(),
        model.target_endpoint_id,
        model.target_endpoint_address.as_deref(),
    ) {
        ("product", None, None) => Ok(AuditTarget::Product),
        ("endpoint-address", None, Some(address)) => EndpointAddress::parse(address)
            .map(AuditTarget::EndpointAddress)
            .map_err(StoredAuditEventError::InvalidEndpointAddress),
        ("endpoint", Some(endpoint_id), None) => {
            Ok(AuditTarget::Endpoint(EndpointId::from_uuid(endpoint_id)))
        }
        ("product" | "endpoint-address" | "endpoint", _, _) => {
            Err(StoredAuditEventError::InvalidTargetShape)
        }
        _ => Err(StoredAuditEventError::UnknownTargetKind),
    }
}

fn map_parameters(
    model: &audit_event::Model,
) -> Result<AuditParameterSummary, StoredAuditEventError> {
    match (
        model.parameter_kind.as_str(),
        model.credential_id,
        model.trust_mode.as_deref(),
        model.row_count,
    ) {
        ("endpoint-enrollment", Some(credential_id), Some(trust), None) => {
            let trust =
                AuditTlsTrust::from_str(trust).map_err(StoredAuditEventError::UnknownTrustMode)?;
            Ok(AuditParameterSummary::EndpointEnrollment {
                credential_id: CredentialId::from_uuid(credential_id),
                trust,
            })
        }
        ("endpoint-refresh", None, None, None) => Ok(AuditParameterSummary::EndpointRefresh),
        ("csv-endpoint-import", None, None, Some(row_count)) => {
            let row_count =
                u32::try_from(row_count).map_err(|_| StoredAuditEventError::InvalidRowCount)?;
            AuditParameterSummary::csv_endpoint_import(row_count)
                .map_err(StoredAuditEventError::InvalidParameterSummary)
        }
        ("endpoint-enrollment" | "endpoint-refresh" | "csv-endpoint-import", _, _, _) => {
            Err(StoredAuditEventError::InvalidParameterShape)
        }
        _ => Err(StoredAuditEventError::UnknownParameterKind),
    }
}

fn map_outcome(model: &audit_event::Model) -> Result<AuditOutcome, StoredAuditEventError> {
    let kind = AuditOutcomeKind::from_str(&model.outcome)
        .map_err(StoredAuditEventError::UnknownOutcome)?;
    match (
        kind,
        model.progress.as_deref(),
        model.failure.as_deref(),
        model.verification.as_deref(),
    ) {
        (AuditOutcomeKind::Started, None, None, None) => Ok(AuditOutcome::Started),
        (AuditOutcomeKind::Progress, Some(progress), None, None) => {
            AuditProgress::from_str(progress)
                .map(AuditOutcome::Progress)
                .map_err(StoredAuditEventError::UnknownProgress)
        }
        (AuditOutcomeKind::Succeeded, None, None, Some(verification)) => {
            let verification = AuditVerification::from_str(verification)
                .map_err(StoredAuditEventError::UnknownVerification)?;
            if verification == AuditVerification::Confirmed {
                Ok(AuditOutcome::Succeeded)
            } else {
                Err(StoredAuditEventError::InvalidOutcomeShape)
            }
        }
        (AuditOutcomeKind::Failed, None, Some(failure), Some(verification)) => {
            let failure =
                AuditFailure::from_str(failure).map_err(StoredAuditEventError::UnknownFailure)?;
            let verification = AuditFailureVerification::from_str(verification)
                .map_err(StoredAuditEventError::UnknownFailureVerification)?;
            Ok(AuditOutcome::Failed {
                failure,
                verification,
            })
        }
        _ => Err(StoredAuditEventError::InvalidOutcomeShape),
    }
}

fn corrupt(operation_id: AuditOperationId, source: StoredAuditEventError) -> AuditRepositoryError {
    AuditRepositoryError::Corrupt {
        operation_id,
        source,
    }
}

/// A controlled failure while appending or reading immutable audit facts.
#[derive(Debug, Error)]
pub enum AuditRepositoryError {
    #[error("audit event write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("audit operation {operation_id} must begin at sequence 1, not {actual}")]
    MissingStart {
        operation_id: AuditOperationId,
        actual: AuditSequence,
    },
    #[error("audit operation {operation_id} expected sequence {expected}, but received {actual}")]
    NonContiguous {
        operation_id: AuditOperationId,
        expected: AuditSequence,
        actual: AuditSequence,
    },
    #[error("audit operation {operation_id} sequence cannot advance: {source}")]
    Sequence {
        operation_id: AuditOperationId,
        #[source]
        source: AuditSequenceError,
    },
    #[error("audit operation {operation_id} immutable context changed at sequence {sequence}")]
    ContextChanged {
        operation_id: AuditOperationId,
        sequence: AuditSequence,
    },
    #[error("audit operation {operation_id} time moved backwards at sequence {sequence}")]
    EventPredatesPrevious {
        operation_id: AuditOperationId,
        sequence: AuditSequence,
    },
    #[error("audit operation {operation_id} already ended at sequence {terminal}")]
    OperationTerminal {
        operation_id: AuditOperationId,
        terminal: AuditSequence,
    },
    #[error("audit operation {operation_id} contains corrupt persisted history: {source}")]
    Corrupt {
        operation_id: AuditOperationId,
        #[source]
        source: StoredAuditEventError,
    },
    #[error("audit event database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// A persisted audit row or operation trail violates the typed audit model.
#[derive(Debug, Error)]
pub enum StoredAuditEventError {
    #[error("stored audit actor is unknown: {0}")]
    UnknownActor(#[source] AuditCodeParseError),
    #[error("stored audit origin is unknown: {0}")]
    UnknownOrigin(#[source] DeploymentPostureParseError),
    #[error("stored audit target kind is unknown")]
    UnknownTargetKind,
    #[error("stored audit target fields have an invalid shape")]
    InvalidTargetShape,
    #[error("stored audit Endpoint address is invalid: {0}")]
    InvalidEndpointAddress(#[source] EndpointAddressError),
    #[error("stored audit parameter kind is unknown")]
    UnknownParameterKind,
    #[error("stored audit parameter fields have an invalid shape")]
    InvalidParameterShape,
    #[error("stored audit TLS trust mode is unknown: {0}")]
    UnknownTrustMode(#[source] AuditCodeParseError),
    #[error("stored audit CSV row count is outside the supported range")]
    InvalidRowCount,
    #[error("stored audit parameter summary is invalid: {0}")]
    InvalidParameterSummary(#[source] AuditParameterSummaryError),
    #[error("stored audit permission is unknown: {0}")]
    UnknownPermission(#[source] AuditCodeParseError),
    #[error("stored audit action is unknown: {0}")]
    UnknownAction(#[source] AuditCodeParseError),
    #[error("stored audit Redfish operation is unknown: {0}")]
    UnknownRedfishOperation(#[source] AuditCodeParseError),
    #[error("stored audit context is inconsistent: {0}")]
    InvalidContext(#[source] AuditOperationContextError),
    #[error(
        "stored audit target principal is recorded under an action that names no distinct subject"
    )]
    InvalidTargetPrincipalShape,
    #[error("stored audit sequence is outside the supported range")]
    InvalidSequenceValue,
    #[error("stored audit sequence is invalid: {0}")]
    InvalidSequence(#[source] AuditSequenceError),
    #[error("stored audit outcome is unknown: {0}")]
    UnknownOutcome(#[source] AuditCodeParseError),
    #[error("stored audit progress is unknown: {0}")]
    UnknownProgress(#[source] AuditCodeParseError),
    #[error("stored audit failure is unknown: {0}")]
    UnknownFailure(#[source] AuditCodeParseError),
    #[error("stored audit verification is unknown: {0}")]
    UnknownVerification(#[source] AuditCodeParseError),
    #[error("stored failed-audit verification is unknown: {0}")]
    UnknownFailureVerification(#[source] AuditCodeParseError),
    #[error("stored audit outcome fields have an invalid shape")]
    InvalidOutcomeShape,
    #[error("stored audit event is invalid: {0}")]
    InvalidEvent(#[source] AuditEventError),
    #[error("stored audit operation does not start at sequence 1")]
    MissingStart,
    #[error("stored audit trail expected sequence {expected}, but found {actual}")]
    NonContiguous {
        expected: AuditSequence,
        actual: AuditSequence,
    },
    #[error("stored audit context changed at sequence {sequence}")]
    ContextChanged { sequence: AuditSequence },
    #[error("stored audit time moved backwards at sequence {sequence}")]
    EventPredatesPrevious { sequence: AuditSequence },
    #[error("stored audit event {sequence} follows a terminal outcome")]
    EventAfterTerminal { sequence: AuditSequence },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{AuditTlsTrust, DeploymentPosture, PrincipalId};
    use sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, EntityTrait, IntoActiveModel,
        Set,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;

    #[tokio::test]
    async fn appends_and_loads_one_complete_immutable_operation() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let context = enrollment_context(AuditOperationId::generate(), CredentialId::generate())?;
        let started = AuditEvent::started(context.clone(), now);
        let second = AuditSequence::FIRST.next()?;
        let progress = AuditEvent::progress(
            context.clone(),
            second,
            AuditProgress::EndpointCreated,
            now + Duration::SECOND,
        )?;
        let succeeded = AuditEvent::succeeded(context, second.next()?, now + Duration::seconds(2))?;

        store.append_audit_event(&started).await?;
        store.append_audit_event(&progress).await?;
        store.append_audit_event(&succeeded).await?;

        assert_eq!(
            store
                .find_audit_operation(started.context().operation_id())
                .await?,
            [started, progress, succeeded]
        );
        assert!(
            store
                .find_audit_operation(AuditOperationId::generate())
                .await?
                .is_empty()
        );
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_missing_gapped_changed_reversed_and_post_terminal_events()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let operation_id = AuditOperationId::generate();
        let context = enrollment_context(operation_id, CredentialId::generate())?;
        let second = AuditSequence::FIRST.next()?;
        let missing_start = AuditEvent::succeeded(context.clone(), second, now)?;
        assert!(matches!(
            store.append_audit_event(&missing_start).await,
            Err(AuditRepositoryError::MissingStart { .. })
        ));

        let started = AuditEvent::started(context.clone(), now);
        store.append_audit_event(&started).await?;
        let gap = AuditEvent::succeeded(context.clone(), second.next()?, now)?;
        assert!(matches!(
            store.append_audit_event(&gap).await,
            Err(AuditRepositoryError::NonContiguous { .. })
        ));

        let changed = AuditEvent::progress(
            enrollment_context(operation_id, CredentialId::generate())?,
            second,
            AuditProgress::EndpointCreated,
            now,
        )?;
        assert!(matches!(
            store.append_audit_event(&changed).await,
            Err(AuditRepositoryError::ContextChanged { .. })
        ));

        let reversed = AuditEvent::progress(
            context.clone(),
            second,
            AuditProgress::EndpointCreated,
            now - Duration::SECOND,
        )?;
        assert!(matches!(
            store.append_audit_event(&reversed).await,
            Err(AuditRepositoryError::EventPredatesPrevious { .. })
        ));

        let succeeded = AuditEvent::succeeded(context.clone(), second, now)?;
        store.append_audit_event(&succeeded).await?;
        let after_terminal =
            AuditEvent::progress(context, second.next()?, AuditProgress::EndpointCreated, now)?;
        assert!(matches!(
            store.append_audit_event(&after_terminal).await,
            Err(AuditRepositoryError::OperationTerminal { .. })
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn detects_a_row_valid_but_noncontiguous_persisted_trail() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let context = enrollment_context(AuditOperationId::generate(), CredentialId::generate())?;
        let started = AuditEvent::started(context.clone(), now);
        store.append_audit_event(&started).await?;
        let gap =
            AuditEvent::succeeded(context, AuditSequence::try_new(3)?, now + Duration::SECOND)?;
        project_event(&gap).insert(&store.database).await?;

        assert!(matches!(
            store
                .find_audit_operation(started.context().operation_id())
                .await,
            Err(AuditRepositoryError::Corrupt {
                source: StoredAuditEventError::NonContiguous { .. },
                ..
            })
        ));
        let fourth = AuditEvent::progress(
            started.context().clone(),
            AuditSequence::try_new(4)?,
            AuditProgress::EndpointCreated,
            now + Duration::seconds(2),
        )?;
        assert!(matches!(
            store.append_audit_event(&fourth).await,
            Err(AuditRepositoryError::Corrupt {
                source: StoredAuditEventError::NonContiguous { .. },
                ..
            })
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn serializes_competing_terminal_appends_without_branching_history()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let context = enrollment_context(AuditOperationId::generate(), CredentialId::generate())?;
        store
            .append_audit_event(&AuditEvent::started(context.clone(), now))
            .await?;
        let second = AuditSequence::FIRST.next()?;
        let succeeded = AuditEvent::succeeded(context.clone(), second, now)?;
        let failed = AuditEvent::failed(
            context,
            second,
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailureVerification::Inconclusive,
            now,
        )?;

        let (first, second_result) = tokio::join!(
            store.append_audit_event(&succeeded),
            store.append_audit_event(&failed),
        );

        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second_result.is_ok()),
            1
        );
        for result in [first, second_result] {
            if let Err(error) = result {
                assert!(matches!(
                    error,
                    AuditRepositoryError::OperationTerminal { .. }
                ));
            }
        }
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_corrupt_secret_bearing_target_without_echoing_it() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let context = enrollment_context(AuditOperationId::generate(), CredentialId::generate())?;
        let started = AuditEvent::started(context, OffsetDateTime::now_utc());
        store.append_audit_event(&started).await?;
        let mut stored = audit_event::Entity::find_by_id(started.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("inserted audit event is missing")?
            .into_active_model();
        stored.target_endpoint_address =
            Set(Some(String::from("https://operator:password@192.0.2.90")));
        stored.update(&store.database).await?;

        let result = store
            .find_audit_operation(started.context().operation_id())
            .await;
        assert!(matches!(
            &result,
            Err(AuditRepositoryError::Corrupt {
                source: StoredAuditEventError::InvalidEndpointAddress(_),
                ..
            })
        ));
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("operator"));
        assert!(!rendered.contains("password"));
        store.close().await?;
        drop(directory);
        Ok(())
    }

    fn enrollment_context(
        operation_id: AuditOperationId,
        credential_id: CredentialId,
    ) -> Result<AuditOperationContext, AuditOperationContextError> {
        AuditOperationContext::try_new(
            operation_id,
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            AuditTarget::EndpointAddress(
                EndpointAddress::parse("https://192.0.2.90")
                    .map_err(|_| AuditOperationContextError)?,
            ),
            AuditParameterSummary::EndpointEnrollment {
                credential_id,
                trust: AuditTlsTrust::PinnedCertificate,
            },
            ProductPermission::ManageEndpoints,
            AuditAction::EnrollEndpoint,
            AuditRedfishOperation::ProbeCoreCapabilities,
        )
    }

    #[tokio::test]
    async fn center_console_events_persist_through_the_real_schema() -> Result<(), Box<dyn Error>> {
        // The three 0.7.0 center-console shapes the web handlers record (the
        // `audit` recorder assertions in `web/src/lib.rs`) now persist
        // through the real schema: binding registration and revocation under
        // the product target and the `manage-center-bindings` permission,
        // and the §15.6 dispatch under the endpoint target and the
        // `dispatch-center-operations` permission. The 000013 migration
        // widened the `audit_events` CHECKs to these exact shapes, so a
        // failed append here would mean the web-visible actions still cannot
        // be persisted.
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let principal_id = PrincipalId::generate();
        let second = AuditSequence::FIRST.next()?;
        for (action, permission, target) in [
            (
                AuditAction::RegisterSiteBinding,
                ProductPermission::ManageCenterBindings,
                AuditTarget::Product,
            ),
            (
                AuditAction::RevokeSiteBinding,
                ProductPermission::ManageCenterBindings,
                AuditTarget::Product,
            ),
            (
                AuditAction::DispatchCenterOperation,
                ProductPermission::DispatchCenterOperations,
                AuditTarget::Endpoint(EndpointId::generate()),
            ),
        ] {
            let context = AuditOperationContext::try_new_with_actor_principal(
                AuditOperationId::generate(),
                AuditActor::User,
                DeploymentPosture::Center,
                target,
                AuditParameterSummary::EndpointRefresh,
                permission,
                action,
                AuditRedfishOperation::None,
                Some(principal_id),
            )?;
            let started = AuditEvent::started(context.clone(), now);
            let succeeded = AuditEvent::succeeded(context.clone(), second, now)?;
            store.append_audit_event(&started).await?;
            store.append_audit_event(&succeeded).await?;
            assert_eq!(
                store
                    .find_audit_operation(started.context().operation_id())
                    .await?,
                [started, succeeded]
            );
        }

        // The refused-dispatch failure code persists through the same path:
        // a §15.6 dispatch refused by the center records
        // `center-request-refused` as its terminal event.
        let refused_context = AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            AuditActor::User,
            DeploymentPosture::Center,
            AuditTarget::Endpoint(EndpointId::generate()),
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::DispatchCenterOperations,
            AuditAction::DispatchCenterOperation,
            AuditRedfishOperation::None,
            Some(principal_id),
        )?;
        let started = AuditEvent::started(refused_context.clone(), now);
        let failed = AuditEvent::failed(
            refused_context.clone(),
            second,
            AuditFailure::CenterRequestRefused,
            AuditFailureVerification::Rejected,
            now,
        )?;
        store.append_audit_event(&started).await?;
        store.append_audit_event(&failed).await?;
        assert_eq!(
            store
                .find_audit_operation(started.context().operation_id())
                .await?,
            [started, failed]
        );
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn target_principal_round_trips_and_foreign_action_shapes_are_corrupt()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let now = OffsetDateTime::now_utc();
        let actor_principal_id = PrincipalId::generate();
        let target_principal_id = PrincipalId::generate();
        // S3-4: the administrator-issued password set records the acting
        // administrator as actor and the user whose credential was replaced
        // as the target, and the target rides every event of the operation.
        let context = AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            AuditActor::User,
            DeploymentPosture::Site,
            AuditTarget::Product,
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::Authenticate,
            AuditAction::ChangePassword,
            AuditRedfishOperation::None,
            Some(actor_principal_id),
        )?
        .with_target_principal(target_principal_id);
        let started = AuditEvent::started(context.clone(), now);
        let succeeded = AuditEvent::succeeded(context, AuditSequence::FIRST.next()?, now)?;
        let operation_id = started.context().operation_id();
        let succeeded_id = succeeded.id();
        store.append_audit_event(&started).await?;
        store.append_audit_event(&succeeded).await?;
        assert_eq!(
            store.find_audit_operation(operation_id).await?,
            [started, succeeded]
        );

        // A stored target under an action that names no distinct subject is
        // corrupt. The schema CHECK refuses such a row, so it is written on
        // a dedicated single-connection writer with check constraints
        // ignored — exactly what a build with a different contract's row
        // looks like, the upgrade-order discipline of the event-repository
        // test. One connection executes both the pragma and the update, so
        // the bypass is deterministic.
        //
        // Test-scope exception to the §7.3 bare-SQL ban: the PRAGMA only
        // simulates the foreign-build write above; no production path runs
        // raw SQL (the `tests/bare_sql_gate.rs` gate in the migration crate
        // pins persistence/src to PRAGMA-only).
        let database_path = store.database_path();
        let normalized_path = database_path.to_string_lossy().replace('\\', "/");
        let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
        options.max_connections(1);
        options.sqlx_logging(false);
        let writer = Database::connect(options).await?;
        writer
            .execute_unprepared("PRAGMA ignore_check_constraints = ON")
            .await?;
        let mut stored = audit_event::Entity::find_by_id(succeeded_id.into_uuid())
            .one(&writer)
            .await?
            .ok_or("inserted audit event is missing")?
            .into_active_model();
        stored.action = Set(String::from("login"));
        stored.update(&writer).await?;
        writer.close().await?;

        assert!(matches!(
            store.find_audit_operation(operation_id).await,
            Err(AuditRepositoryError::Corrupt {
                source: StoredAuditEventError::InvalidTargetPrincipalShape,
                ..
            })
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }
}
