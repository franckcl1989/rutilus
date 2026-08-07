use std::{error::Error, fmt};

use rutilus_domain::{
    AuditAction, AuditActor, AuditEvent, AuditFailure, AuditFailureVerification,
    AuditOperationContext, AuditOperationId, AuditParameterSummary, AuditProgress,
    AuditRedfishOperation, AuditSequence, AuditTarget, DeploymentPosture, EndpointAddress,
    EndpointId, PrincipalId, ProductPermission,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AuditEventWriter, AuditRecordError, Clock, EndpointCsvImport, EndpointEnroller,
    EndpointTrustEstablishment, EndpointTrustExpectationError, OnboardEndpointRequest,
    TlsIdentityProbe,
};

/// Executes a validated CSV import sequentially with independent row results.
///
/// Sequential execution is an intentional initial concurrency bound of one.
/// A failed row never rolls back or suppresses another row's result.
pub struct EndpointCsvImportExecutor<Probe, Enroller, Audit, Time> {
    probe: Probe,
    enroller: Enroller,
    audit: Audit,
    clock: Time,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    origin: DeploymentPosture,
}

impl<Probe, Enroller, Audit, Time> EndpointCsvImportExecutor<Probe, Enroller, Audit, Time>
where
    Probe: TlsIdentityProbe,
    Enroller: EndpointEnroller,
    Audit: AuditEventWriter,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        probe: Probe,
        enroller: Enroller,
        audit: Audit,
        clock: Time,
        actor: AuditActor,
        actor_principal_id: Option<PrincipalId>,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            probe,
            enroller,
            audit,
            clock,
            actor,
            actor_principal_id,
            origin,
        }
    }

    /// Verifies TLS without credentials, then enrolls and initially refreshes
    /// every validated row while retaining each independent result.
    ///
    /// The batch audit starts before any TLS probe. Every row-validation fact
    /// is durable before that row reaches the network. A partial batch is
    /// terminally recorded as failed rather than being presented as success.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointCsvImportExecutionError`] only when the mandatory
    /// batch audit cannot be prepared or appended. The error retains all row
    /// results completed before audit integrity prevented further work.
    pub async fn execute(
        &self,
        import: EndpointCsvImport,
    ) -> Result<
        EndpointCsvImportReport<Probe::Error, Enroller::Error>,
        EndpointCsvImportExecutionError<Audit::Error, Probe::Error, Enroller::Error>,
    > {
        let total_rows = import.rows().len();
        let report = EndpointCsvImportReport::new(total_rows);
        let (mut audit, mut report) = self.start_audit(import.row_count(), report).await?;
        let trust = EndpointTrustEstablishment::new(&self.probe, &self.clock);
        for row in import.into_rows() {
            report = self
                .record_row_validated(&mut audit, row.record_number(), report)
                .await?;
            report.push(self.execute_row(&trust, row).await);
        }
        self.complete_audit(audit, report).await
    }

    async fn start_audit(
        &self,
        row_count: u32,
        report: EndpointCsvImportReport<Probe::Error, Enroller::Error>,
    ) -> Result<
        (
            CsvImportAuditState,
            EndpointCsvImportReport<Probe::Error, Enroller::Error>,
        ),
        EndpointCsvImportExecutionError<Audit::Error, Probe::Error, Enroller::Error>,
    > {
        let parameters = match AuditParameterSummary::csv_endpoint_import(row_count) {
            Ok(parameters) => parameters,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    EndpointCsvImportAuditStage::Start,
                    report,
                    AuditRecordError::Parameters(source),
                ));
            }
        };
        let context = match AuditOperationContext::try_new_with_actor_principal(
            AuditOperationId::generate(),
            self.actor,
            self.origin,
            AuditTarget::Product,
            parameters,
            ProductPermission::ManageEndpoints,
            AuditAction::ImportEndpoints,
            AuditRedfishOperation::None,
            self.actor_principal_id,
        ) {
            Ok(context) => context,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    EndpointCsvImportAuditStage::Start,
                    report,
                    AuditRecordError::Context(source),
                ));
            }
        };
        let started_at = self.clock.now();
        let started = AuditEvent::started(context.clone(), started_at);
        if let Err(source) = self.audit.append_audit_event(&started).await {
            return Err(EndpointCsvImportExecutionError::new(
                EndpointCsvImportAuditStage::Start,
                report,
                AuditRecordError::Write(source),
            ));
        }
        Ok((
            CsvImportAuditState {
                context,
                sequence: AuditSequence::FIRST,
                previous_at: started_at,
            },
            report,
        ))
    }

    async fn record_row_validated(
        &self,
        audit: &mut CsvImportAuditState,
        record_number: usize,
        report: EndpointCsvImportReport<Probe::Error, Enroller::Error>,
    ) -> Result<
        EndpointCsvImportReport<Probe::Error, Enroller::Error>,
        EndpointCsvImportExecutionError<Audit::Error, Probe::Error, Enroller::Error>,
    > {
        let stage = EndpointCsvImportAuditStage::RowValidated {
            record: record_number,
        };
        audit.sequence = match audit.sequence.next() {
            Ok(sequence) => sequence,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    stage,
                    report,
                    AuditRecordError::Sequence(source),
                ));
            }
        };
        let progress_at = at_or_after(audit.previous_at, self.clock.now());
        let progress = match AuditEvent::progress(
            audit.context.clone(),
            audit.sequence,
            AuditProgress::RowValidated,
            progress_at,
        ) {
            Ok(progress) => progress,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    stage,
                    report,
                    AuditRecordError::Event(source),
                ));
            }
        };
        if let Err(source) = self.audit.append_audit_event(&progress).await {
            return Err(EndpointCsvImportExecutionError::new(
                stage,
                report,
                AuditRecordError::Write(source),
            ));
        }
        audit.previous_at = progress_at;
        Ok(report)
    }

    async fn execute_row(
        &self,
        trust: &EndpointTrustEstablishment<&Probe, &Time>,
        row: crate::EndpointCsvRow,
    ) -> EndpointCsvRowResult<Probe::Error, Enroller::Error> {
        let record_number = row.record_number();
        let address = row.address().clone();
        let outcome = match trust.begin(address.clone()).await {
            Err(source) => EndpointCsvRowOutcome::TlsProbeFailed(source),
            Ok(challenge) => match trust.complete_with_expectation(challenge, row.trust()) {
                Err(source) => EndpointCsvRowOutcome::TrustRejected(source),
                Ok(target) => {
                    let request = OnboardEndpointRequest::new(
                        row.display_name().clone(),
                        target,
                        row.credential_id(),
                    );
                    match self.enroller.enroll(request).await {
                        Ok(endpoint_id) => EndpointCsvRowOutcome::Enrolled(endpoint_id),
                        Err(source) => EndpointCsvRowOutcome::EnrollmentFailed(source),
                    }
                }
            },
        };
        EndpointCsvRowResult {
            record_number,
            address,
            outcome,
        }
    }

    async fn complete_audit(
        &self,
        mut audit: CsvImportAuditState,
        report: EndpointCsvImportReport<Probe::Error, Enroller::Error>,
    ) -> Result<
        EndpointCsvImportReport<Probe::Error, Enroller::Error>,
        EndpointCsvImportExecutionError<Audit::Error, Probe::Error, Enroller::Error>,
    > {
        audit.sequence = match audit.sequence.next() {
            Ok(sequence) => sequence,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    EndpointCsvImportAuditStage::Completion,
                    report,
                    AuditRecordError::Sequence(source),
                ));
            }
        };
        let completed_at = at_or_after(audit.previous_at, self.clock.now());
        let terminal = if report.failed_count() == 0 {
            AuditEvent::succeeded(audit.context, audit.sequence, completed_at)
        } else {
            AuditEvent::failed(
                audit.context,
                audit.sequence,
                AuditFailure::EndpointImportRowFailed,
                AuditFailureVerification::Rejected,
                completed_at,
            )
        };
        let terminal = match terminal {
            Ok(terminal) => terminal,
            Err(source) => {
                return Err(EndpointCsvImportExecutionError::new(
                    EndpointCsvImportAuditStage::Completion,
                    report,
                    AuditRecordError::Event(source),
                ));
            }
        };
        if let Err(source) = self.audit.append_audit_event(&terminal).await {
            return Err(EndpointCsvImportExecutionError::new(
                EndpointCsvImportAuditStage::Completion,
                report,
                AuditRecordError::Write(source),
            ));
        }
        Ok(report)
    }
}

struct CsvImportAuditState {
    context: AuditOperationContext,
    sequence: AuditSequence,
    previous_at: OffsetDateTime,
}

fn at_or_after(previous: OffsetDateTime, observed: OffsetDateTime) -> OffsetDateTime {
    previous.max(observed)
}

/// The outcome of one validated CSV endpoint row.
#[derive(Debug)]
pub enum EndpointCsvRowOutcome<ProbeError, EnrollmentError> {
    Enrolled(EndpointId),
    TlsProbeFailed(ProbeError),
    TrustRejected(EndpointTrustExpectationError),
    EnrollmentFailed(EnrollmentError),
}

impl<ProbeError, EnrollmentError> EndpointCsvRowOutcome<ProbeError, EnrollmentError> {
    #[must_use]
    pub const fn endpoint_id(&self) -> Option<EndpointId> {
        match self {
            Self::Enrolled(endpoint_id) => Some(*endpoint_id),
            Self::TlsProbeFailed(_) | Self::TrustRejected(_) | Self::EnrollmentFailed(_) => None,
        }
    }

    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Enrolled(_))
    }
}

/// One target's independent result inside a CSV import.
#[derive(Debug)]
pub struct EndpointCsvRowResult<ProbeError, EnrollmentError> {
    record_number: usize,
    address: EndpointAddress,
    outcome: EndpointCsvRowOutcome<ProbeError, EnrollmentError>,
}

impl<ProbeError, EnrollmentError> EndpointCsvRowResult<ProbeError, EnrollmentError> {
    #[must_use]
    pub const fn record_number(&self) -> usize {
        self.record_number
    }

    #[must_use]
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    #[must_use]
    pub const fn outcome(&self) -> &EndpointCsvRowOutcome<ProbeError, EnrollmentError> {
        &self.outcome
    }
}

/// Complete or partial target-by-target results for one import request.
#[derive(Debug)]
pub struct EndpointCsvImportReport<ProbeError, EnrollmentError> {
    total_rows: usize,
    rows: Vec<EndpointCsvRowResult<ProbeError, EnrollmentError>>,
}

impl<ProbeError, EnrollmentError> EndpointCsvImportReport<ProbeError, EnrollmentError> {
    fn new(total_rows: usize) -> Self {
        Self {
            total_rows,
            rows: Vec::with_capacity(total_rows),
        }
    }

    fn push(&mut self, result: EndpointCsvRowResult<ProbeError, EnrollmentError>) {
        self.rows.push(result);
    }

    #[must_use]
    pub const fn total_rows(&self) -> usize {
        self.total_rows
    }

    #[must_use]
    pub fn attempted_count(&self) -> usize {
        self.rows.len()
    }

    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|result| result.outcome.is_success())
            .count()
    }

    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.attempted_count()
            .saturating_sub(self.succeeded_count())
    }

    #[must_use]
    pub fn unattempted_count(&self) -> usize {
        self.total_rows.saturating_sub(self.attempted_count())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unattempted_count() == 0
    }

    #[must_use]
    pub fn rows(&self) -> &[EndpointCsvRowResult<ProbeError, EnrollmentError>] {
        &self.rows
    }

    #[must_use]
    pub fn into_rows(self) -> Vec<EndpointCsvRowResult<ProbeError, EnrollmentError>> {
        self.rows
    }
}

/// The batch audit point that prevented reliable continuation or reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointCsvImportAuditStage {
    Start,
    RowValidated { record: usize },
    Completion,
}

impl fmt::Display for EndpointCsvImportAuditStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => formatter.write_str("start"),
            Self::RowValidated { record } => {
                write!(formatter, "record {record} validation milestone")
            }
            Self::Completion => formatter.write_str("completion"),
        }
    }
}

/// Mandatory batch audit failed, with all safely completed row results kept.
#[derive(Debug, Error)]
#[error("endpoint CSV import audit {stage} failed")]
pub struct EndpointCsvImportExecutionError<AuditError, ProbeError, EnrollmentError>
where
    AuditError: Error + 'static,
    ProbeError: Error + 'static,
    EnrollmentError: Error + 'static,
{
    stage: EndpointCsvImportAuditStage,
    report: EndpointCsvImportReport<ProbeError, EnrollmentError>,
    #[source]
    source: AuditRecordError<AuditError>,
}

impl<AuditError, ProbeError, EnrollmentError>
    EndpointCsvImportExecutionError<AuditError, ProbeError, EnrollmentError>
where
    AuditError: Error + 'static,
    ProbeError: Error + 'static,
    EnrollmentError: Error + 'static,
{
    fn new(
        stage: EndpointCsvImportAuditStage,
        report: EndpointCsvImportReport<ProbeError, EnrollmentError>,
        source: AuditRecordError<AuditError>,
    ) -> Self {
        Self {
            stage,
            report,
            source,
        }
    }

    #[must_use]
    pub const fn stage(&self) -> EndpointCsvImportAuditStage {
        self.stage
    }

    #[must_use]
    pub const fn report(&self) -> &EndpointCsvImportReport<ProbeError, EnrollmentError> {
        &self.report
    }

    #[must_use]
    pub const fn audit_source(&self) -> &AuditRecordError<AuditError> {
        &self.source
    }

    #[must_use]
    pub fn into_report(self) -> EndpointCsvImportReport<ProbeError, EnrollmentError> {
        self.report
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard};

    use rutilus_domain::{AuditOutcome, TlsCertificate};

    use super::*;
    use crate::{BoundaryFuture, SystemCaEvaluation, TlsIdentityObservation, parse_endpoint_csv};

    const CREDENTIAL_ID: &str = "0198e29f-7800-7000-8000-000000000001";

    #[tokio::test]
    async fn isolates_row_outcomes_and_rejects_partial_batch_success() -> Result<(), Box<dyn Error>>
    {
        let state = Arc::new(Mutex::new(MockState::default()));
        let certificate = TlsCertificate::from_der(b"observed import certificate".to_vec())?;
        let different = TlsCertificate::from_der(b"different import certificate".to_vec())?;
        let csv = format!(
            "display_name,address,credential_id,tls_sha256\n\
             Good,https://good.example.test,{CREDENTIAL_ID},\n\
             Wrong Pin,https://pin.example.test,{CREDENTIAL_ID},{}\n\
             No TLS,https://probe-fail.example.test,{CREDENTIAL_ID},\n\
             No Enrollment,https://enroll-fail.example.test,{CREDENTIAL_ID},\n",
            different.fingerprint()
        );
        let executor = executor(Arc::clone(&state), certificate.clone());

        let report = executor
            .execute(parse_endpoint_csv(csv.as_bytes())?)
            .await?;

        assert_eq!(report.total_rows(), 4);
        assert_eq!(report.attempted_count(), 4);
        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.failed_count(), 3);
        assert_eq!(report.unattempted_count(), 0);
        assert!(report.is_complete());
        assert!(matches!(
            report.rows()[0].outcome(),
            EndpointCsvRowOutcome::Enrolled(_)
        ));
        assert!(matches!(
            report.rows()[1].outcome(),
            EndpointCsvRowOutcome::TrustRejected(
                EndpointTrustExpectationError::FingerprintMismatch { expected, observed }
            ) if *expected == different.fingerprint() && *observed == certificate.fingerprint()
        ));
        assert!(matches!(
            report.rows()[2].outcome(),
            EndpointCsvRowOutcome::TlsProbeFailed(MockProbeError)
        ));
        assert!(matches!(
            report.rows()[3].outcome(),
            EndpointCsvRowOutcome::EnrollmentFailed(MockEnrollmentError)
        ));
        assert_eq!(report.rows()[0].record_number(), 2);
        assert_eq!(
            report.rows()[0].address().to_string(),
            "https://good.example.test/"
        );
        assert!(report.rows()[0].outcome().endpoint_id().is_some());
        assert_eq!(report.rows()[1].outcome().endpoint_id(), None);

        let state = lock_state(&state)?;
        assert_eq!(state.probes, 4);
        assert_eq!(state.enrollments, 2);
        assert_eq!(state.audit_events.len(), 6);
        assert_eq!(
            state
                .audit_events
                .iter()
                .map(|event| event.sequence().get())
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
        assert!(matches!(
            state.audit_events[5].outcome(),
            AuditOutcome::Failed {
                failure: AuditFailure::EndpointImportRowFailed,
                verification: AuditFailureVerification::Rejected,
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn confirms_a_fully_successful_batch() -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        let certificate = TlsCertificate::from_der(b"trusted import certificate".to_vec())?;
        let csv = format!(
            "display_name,address,credential_id,tls_sha256\nGood,https://good.example.test,{CREDENTIAL_ID},\n"
        );
        let executor = executor(Arc::clone(&state), certificate);

        let report = executor
            .execute(parse_endpoint_csv(csv.as_bytes())?)
            .await?;

        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.failed_count(), 0);
        assert!(matches!(
            lock_state(&state)?.audit_events[2].outcome(),
            AuditOutcome::Succeeded
        ));
        assert_eq!(report.into_rows().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn audit_failure_stops_new_work_and_preserves_completed_rows()
    -> Result<(), Box<dyn Error>> {
        let certificate = TlsCertificate::from_der(b"audit import certificate".to_vec())?;
        let two_rows = format!(
            "display_name,address,credential_id,tls_sha256\n\
             First,https://first.example.test,{CREDENTIAL_ID},\n\
             Second,https://second.example.test,{CREDENTIAL_ID},\n"
        );

        let start_state = Arc::new(Mutex::new(MockState::with_audit_failure(1)));
        let start = executor(Arc::clone(&start_state), certificate.clone())
            .execute(parse_endpoint_csv(two_rows.as_bytes())?)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("start audit unexpectedly succeeded"))?;
        assert_eq!(start.stage(), EndpointCsvImportAuditStage::Start);
        assert_eq!(start.report().attempted_count(), 0);
        assert_eq!(start.report().unattempted_count(), 2);
        assert!(matches!(
            start.audit_source(),
            AuditRecordError::Write(MockAuditError)
        ));
        assert_eq!(lock_state(&start_state)?.probes, 0);
        assert_eq!(start.into_report().total_rows(), 2);

        let progress_state = Arc::new(Mutex::new(MockState::with_audit_failure(3)));
        let progress = executor(Arc::clone(&progress_state), certificate.clone())
            .execute(parse_endpoint_csv(two_rows.as_bytes())?)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("progress audit unexpectedly succeeded"))?;
        assert_eq!(
            progress.stage(),
            EndpointCsvImportAuditStage::RowValidated { record: 3 }
        );
        assert_eq!(progress.report().succeeded_count(), 1);
        assert_eq!(progress.report().unattempted_count(), 1);
        assert_eq!(lock_state(&progress_state)?.probes, 1);
        assert_eq!(lock_state(&progress_state)?.enrollments, 1);

        let one_row = format!(
            "display_name,address,credential_id,tls_sha256\nOnly,https://only.example.test,{CREDENTIAL_ID},\n"
        );
        let completion_state = Arc::new(Mutex::new(MockState::with_audit_failure(3)));
        let completion = executor(Arc::clone(&completion_state), certificate)
            .execute(parse_endpoint_csv(one_row.as_bytes())?)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("completion audit unexpectedly succeeded"))?;
        assert_eq!(completion.stage(), EndpointCsvImportAuditStage::Completion);
        assert!(completion.report().is_complete());
        assert_eq!(completion.report().succeeded_count(), 1);
        assert_eq!(
            completion.to_string(),
            "endpoint CSV import audit completion failed"
        );
        Ok(())
    }

    fn executor(
        state: Arc<Mutex<MockState>>,
        certificate: TlsCertificate,
    ) -> EndpointCsvImportExecutor<MockProbe, MockEnroller, MockAudit, FixedClock> {
        EndpointCsvImportExecutor::new(
            MockProbe {
                state: Arc::clone(&state),
                certificate,
            },
            MockEnroller {
                state: Arc::clone(&state),
            },
            MockAudit { state },
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        )
    }

    #[derive(Default)]
    struct MockState {
        audit_events: Vec<AuditEvent>,
        audit_attempts: usize,
        fail_audit_on: Option<usize>,
        probes: usize,
        enrollments: usize,
    }

    impl MockState {
        fn with_audit_failure(attempt: usize) -> Self {
            Self {
                fail_audit_on: Some(attempt),
                ..Self::default()
            }
        }
    }

    fn lock_state(
        state: &Arc<Mutex<MockState>>,
    ) -> Result<MutexGuard<'_, MockState>, MockAuditError> {
        state.lock().map_err(|_| MockAuditError)
    }

    #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
    #[error("mock audit failed")]
    struct MockAuditError;

    struct MockAudit {
        state: Arc<Mutex<MockState>>,
    }

    impl AuditEventWriter for MockAudit {
        type Error = MockAuditError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut state = lock_state(&self.state)?;
                state.audit_attempts += 1;
                if state.fail_audit_on == Some(state.audit_attempts) {
                    return Err(MockAuditError);
                }
                state.audit_events.push(event.clone());
                Ok(())
            })
        }
    }

    #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
    #[error("mock TLS probe failed")]
    struct MockProbeError;

    struct MockProbe {
        state: Arc<Mutex<MockState>>,
        certificate: TlsCertificate,
    }

    impl TlsIdentityProbe for MockProbe {
        type Error = MockProbeError;

        fn observe<'a>(
            &'a self,
            address: &'a EndpointAddress,
        ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
            Box::pin(async move {
                let mut state = self.state.lock().map_err(|_| MockProbeError)?;
                state.probes += 1;
                if address.as_url().host_str() == Some("probe-fail.example.test") {
                    return Err(MockProbeError);
                }
                let evaluation = if address.as_url().host_str() == Some("pin.example.test") {
                    SystemCaEvaluation::Rejected
                } else {
                    SystemCaEvaluation::Verified
                };
                Ok(TlsIdentityObservation::new(
                    self.certificate.clone(),
                    evaluation,
                ))
            })
        }
    }

    #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
    #[error("mock enrollment failed")]
    struct MockEnrollmentError;

    struct MockEnroller {
        state: Arc<Mutex<MockState>>,
    }

    impl EndpointEnroller for MockEnroller {
        type Error = MockEnrollmentError;

        fn enroll(
            &self,
            request: OnboardEndpointRequest,
        ) -> BoundaryFuture<'_, Result<EndpointId, Self::Error>> {
            Box::pin(async move {
                let mut state = self.state.lock().map_err(|_| MockEnrollmentError)?;
                state.enrollments += 1;
                if request.target().address().as_url().host_str()
                    == Some("enroll-fail.example.test")
                {
                    return Err(MockEnrollmentError);
                }
                Ok(EndpointId::generate())
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }
}
