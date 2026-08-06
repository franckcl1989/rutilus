//! The persisted remote Task observation model (design section 13.6).
//!
//! When the BMC accepts a write as an asynchronous Task (§13.3 step 7
//! returning `202`), the product persists one [`RemoteTask`] record (§9.3
//! `remote_tasks`) so Task progress survives a process restart: the record
//! carries the Task and `TaskMonitor` URIs plus the newest observation
//! (`last_state`, `last_message`, `percent_complete`, `last_checked_at`),
//! and the §13.6 recovery scan resumes polling from those URIs after the
//! restart.
//!
//! # Why this model lives in `operation-engine`, not `domain`
//!
//! Design section 8 assigns "persistent tasks and recovery" to this crate,
//! and section 7.2 keeps protocol-flavored vocabulary out of the domain:
//! [`RemoteTaskState`] mirrors the Redfish `Task_v1` `TaskState`
//! enumeration, which is a wire-level concept that the domain must not see.
//! [`Operation`](rutilus_domain::Operation) stays in `domain` because it is
//! the universal write record every layer consumes; the remote-task record
//! is the engine's own durable observation log.
//!
//! # State and identity discipline
//!
//! [`RemoteTaskState`] maps the `nv-redfish` 0.13 `Task_v1` CSDL code for
//! code (same stable snake-case codes), so a value read off the wire
//! round-trips through persistence and back without a translation table.
//! The mapping from the wire type is the infra gateway's job (design
//! section 7.2); a code this build cannot classify is refused by
//! [`RemoteTaskState`]'s `FromStr` and must never be disguised as success
//! or failure (design section 7.6).
//!
//! There is deliberately no `RemoteTaskId`: the persisted record is keyed
//! by [`OperationId`] — one operation in `WaitingRemote` owns exactly one
//! task record — so a second identifier would add a join without adding
//! identity (design section 7.1 makes identities explicit, not invented).

use std::{error::Error, fmt, str::FromStr};

use rutilus_domain::{EndpointId, OperationId};
use time::OffsetDateTime;

/// The observed state of one asynchronous BMC Task (design section 13.6).
///
/// The variants mirror the `Task_v1` `TaskState` enumeration of the
/// `nv-redfish` 0.13 CSDL code for code — including `Stopping` and
/// `Service`, which real BMCs report — so every value that can appear on
/// the wire has a home here. [`Self::as_str`] returns the same stable
/// snake-case code the CSDL uses, which is the code persistence stores and
/// `FromStr` accepts, so a task state round-trips through the database
/// without a translation table. A state from a newer CSDL this build cannot
/// classify is refused by `FromStr`; it must never be recorded as a known
/// state (design section 7.6), and the Task monitor treats it as an outcome
/// it cannot prove.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RemoteTaskState {
    /// The task is newly created but has not started.
    ///
    /// This is also the truthful acceptance-time placeholder: when the
    /// product accepts a `202`, it knows the BMC created a task but has not
    /// observed it executing, so [`RemoteTask::new`] starts the observation
    /// log here and the first poll replaces it with a wire-observed state.
    New,
    /// The task is starting.
    Starting,
    /// The task is executing.
    Running,
    /// The task has been suspended but is expected to restart and is
    /// therefore not complete.
    Suspended,
    /// The task has been interrupted but is expected to restart and is
    /// therefore not complete.
    Interrupted,
    /// The task is pending some condition and has not yet begun to execute.
    Pending,
    /// The task is stopping but is not yet complete.
    Stopping,
    /// The task completed successfully or with warnings.
    Completed,
    /// The task is complete because an operator killed it.
    Killed,
    /// The task completed with errors.
    Exception,
    /// The task is running as a service and is expected to continue
    /// operation until stopped or killed — it never completes on its own,
    /// so a monitor must not wait for it indefinitely.
    Service,
    /// The task is in the process of being cancelled.
    Cancelling,
    /// The task was cancelled by an operator or an internal process (for
    /// example a `DELETE` on the task monitor).
    Cancelled,
}

impl RemoteTaskState {
    /// Returns the stable snake-case code used by persistence and the wire.
    ///
    /// The codes are exactly the CSDL `TaskState` values, so an
    /// `nv-redfish` state's `to_snake_case()` code parses back here without
    /// a mapping table.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Interrupted => "interrupted",
            Self::Pending => "pending",
            Self::Stopping => "stopping",
            Self::Completed => "completed",
            Self::Killed => "killed",
            Self::Exception => "exception",
            Self::Service => "service",
            Self::Cancelling => "cancelling",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reports whether the Task has reached a terminal state.
    ///
    /// Per the CSDL completion semantics exactly four states are terminal:
    /// `Completed` (successfully or with warnings), `Exception` (completed
    /// with errors), `Killed` (terminated by an operator), and `Cancelled`
    /// (cancelled by an operator or an internal process). Everything else —
    /// including the look-alike `Cancelling`, `Stopping`, and `Service` —
    /// is still in flight, so the Task monitor keeps polling. The terminal
    /// observation is what lets the operation leave `WaitingRemote`
    /// (§13.3 step 8).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Exception | Self::Killed | Self::Cancelled
        )
    }
}

impl fmt::Display for RemoteTaskState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RemoteTaskState {
    type Err = RemoteTaskStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "new" => Ok(Self::New),
            "starting" => Ok(Self::Starting),
            "running" => Ok(Self::Running),
            "suspended" => Ok(Self::Suspended),
            "interrupted" => Ok(Self::Interrupted),
            "pending" => Ok(Self::Pending),
            "stopping" => Ok(Self::Stopping),
            "completed" => Ok(Self::Completed),
            "killed" => Ok(Self::Killed),
            "exception" => Ok(Self::Exception),
            "service" => Ok(Self::Service),
            "cancelling" => Ok(Self::Cancelling),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(RemoteTaskStateParseError),
        }
    }
}

/// A persisted task state code is unknown to this product build.
///
/// This is also the verdict for a wire value from a newer CSDL: the code
/// exists on the wire but this build cannot classify it, and it must not be
/// recorded as any known state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteTaskStateParseError;

impl fmt::Display for RemoteTaskStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown remote task state code")
    }
}

impl Error for RemoteTaskStateParseError {}

/// A Redfish `Task` or `TaskMonitor` resource URI (design section 13.6).
///
/// Persisted so the §13.6 recovery scan can resume polling without
/// re-discovering the resource. The value is validated the same way the
/// domain validates a resource `@odata.id` — non-empty, exact text without
/// surrounding whitespace, no control characters, bounded length — because
/// the URI is stored and later issued verbatim in HTTP requests: a
/// malformed or hostile value could redirect polling or corrupt the record.
/// The URI is not interpreted here; constructing the request is the infra
/// gateway's job (design section 7.2).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskUri(String);

/// The upper bound of one persisted Task URI, matching the domain's
/// `@odata.id` bound.
const MAX_TASK_URI_BYTES: usize = 4 * 1024;

impl TaskUri {
    /// Validates a Task URI without interpreting or constructing a request.
    ///
    /// # Errors
    ///
    /// Returns [`TaskUriError`] for empty, whitespace-padded,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, TaskUriError> {
        validate_uri_text(value, MAX_TASK_URI_BYTES)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TaskUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TaskUri {
    type Err = TaskUriError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a Task URI cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskUriError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for TaskUriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("task URI must not be empty"),
            Self::SurroundingWhitespace => {
                formatter.write_str("task URI must not be padded with whitespace")
            }
            Self::ControlCharacter => {
                formatter.write_str("task URI must not contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "task URI is {actual} bytes but at most {maximum} are allowed"
            ),
        }
    }
}

impl Error for TaskUriError {}

/// The exact-text validation shared by every URI field.
///
/// Mirrors the domain `ResourceODataId` rules so all persisted Redfish URIs
/// follow one validation story.
fn validate_uri_text(value: &str, maximum: usize) -> Result<(), TaskUriError> {
    if value.is_empty() {
        return Err(TaskUriError::Empty);
    }
    if value.trim() != value {
        return Err(TaskUriError::SurroundingWhitespace);
    }
    if value.chars().any(char::is_control) {
        return Err(TaskUriError::ControlCharacter);
    }
    let actual = value.len();
    if actual > maximum {
        return Err(TaskUriError::TooLong { actual, maximum });
    }
    Ok(())
}

/// One persisted observation record of an asynchronous BMC Task (design
/// section 13.6).
///
/// The record exists from the moment the BMC accepts the write as a `202`
/// Task until the operation leaves `WaitingRemote`: it carries the Task and
/// `TaskMonitor` URIs needed to resume polling after a restart, plus the
/// newest observation (`last_state`, `last_message`, `percent_complete`,
/// `last_checked_at`). It is observation data, not a state machine: the
/// §13.2 operation state is advanced only through
/// [`OperationEngine::apply`](crate::OperationEngine), never by saving a
/// record.
///
/// All fields are private and every record is built through
/// [`Self::new`] or [`Self::try_from_parts`], so a `RemoteTask` cannot be
/// assembled with an invalid state or a corrupt `PercentComplete`
/// (design section 7.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteTask {
    operation_id: OperationId,
    endpoint_id: EndpointId,
    task_uri: TaskUri,
    task_monitor_uri: Option<TaskUri>,
    last_state: RemoteTaskState,
    last_message: Option<String>,
    percent_complete: Option<u64>,
    last_checked_at: OffsetDateTime,
}

impl RemoteTask {
    /// Records the acceptance of one asynchronous Task (§13.6).
    ///
    /// Called the moment a `202` surfaces, before the first poll, so the
    /// URIs are persisted even when the process crashes between acceptance
    /// and the first observation. `last_checked_at` is the acceptance time
    /// from the caller's clock — the model never reads the wall clock, so
    /// tests stay deterministic. `last_state` starts at
    /// [`RemoteTaskState::New`]: the task is newly created and has not been
    /// observed yet, and the first poll replaces the placeholder with a
    /// wire-observed state.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        endpoint_id: EndpointId,
        task_uri: TaskUri,
        task_monitor_uri: Option<TaskUri>,
        last_checked_at: OffsetDateTime,
    ) -> Self {
        Self {
            operation_id,
            endpoint_id,
            task_uri,
            task_monitor_uri,
            last_state: RemoteTaskState::New,
            last_message: None,
            percent_complete: None,
            last_checked_at,
        }
    }

    /// Rehydrates a persisted remote-task record.
    ///
    /// This is the only way to construct a record in an arbitrary observed
    /// state; it is reserved for persistence loading — including the §13.6
    /// restart scan, which must accept whatever the database stored — and
    /// for the Task monitor's poll updates, which replace the stored
    /// observation with the newest one.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTaskError::PercentOutOfRange`] when the persisted
    /// `PercentComplete` lies outside the `0..=100` range the CSDL defines:
    /// a stored 150 is corrupt data and must not be displayed as progress.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_parts(
        operation_id: OperationId,
        endpoint_id: EndpointId,
        task_uri: TaskUri,
        task_monitor_uri: Option<TaskUri>,
        last_state: RemoteTaskState,
        last_message: Option<String>,
        percent_complete: Option<u64>,
        last_checked_at: OffsetDateTime,
    ) -> Result<Self, RemoteTaskError> {
        if let Some(percent_complete) = percent_complete
            && percent_complete > 100
        {
            return Err(RemoteTaskError::PercentOutOfRange { percent_complete });
        }
        Ok(Self {
            operation_id,
            endpoint_id,
            task_uri,
            task_monitor_uri,
            last_state,
            last_message,
            percent_complete,
            last_checked_at,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the canonical Task resource URI.
    #[must_use]
    pub const fn task_uri(&self) -> &TaskUri {
        &self.task_uri
    }

    /// Returns the `TaskMonitor` polling location, when the BMC provided one.
    #[must_use]
    pub const fn task_monitor_uri(&self) -> Option<&TaskUri> {
        self.task_monitor_uri.as_ref()
    }

    /// Returns the newest observed Task state.
    #[must_use]
    pub const fn last_state(&self) -> RemoteTaskState {
        self.last_state
    }

    /// Returns the newest observed Task message, when the BMC reported one.
    #[must_use]
    pub fn last_message(&self) -> Option<&str> {
        self.last_message.as_deref()
    }

    /// Returns the newest observed completion percentage in `0..=100`.
    #[must_use]
    pub const fn percent_complete(&self) -> Option<u64> {
        self.percent_complete
    }

    /// Returns when the newest observation was made (the caller's clock).
    #[must_use]
    pub const fn last_checked_at(&self) -> OffsetDateTime {
        self.last_checked_at
    }

    /// Reports whether the Task reached a terminal state (§13.3 step 8).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.last_state.is_terminal()
    }
}

/// A persisted remote-task record is corrupt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteTaskError {
    /// `PercentComplete` lies outside the `0..=100` range the CSDL defines.
    PercentOutOfRange { percent_complete: u64 },
}

impl fmt::Display for RemoteTaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PercentOutOfRange { percent_complete } => write!(
                formatter,
                "remote task percent complete {percent_complete} lies outside the 0..=100 CSDL range"
            ),
        }
    }
}

impl Error for RemoteTaskError {}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use time::Duration;

    use super::*;

    /// Every CSDL state, so the code and terminality tests cannot silently
    /// miss a variant.
    const ALL_STATES: [RemoteTaskState; 13] = [
        RemoteTaskState::New,
        RemoteTaskState::Starting,
        RemoteTaskState::Running,
        RemoteTaskState::Suspended,
        RemoteTaskState::Interrupted,
        RemoteTaskState::Pending,
        RemoteTaskState::Stopping,
        RemoteTaskState::Completed,
        RemoteTaskState::Killed,
        RemoteTaskState::Exception,
        RemoteTaskState::Service,
        RemoteTaskState::Cancelling,
        RemoteTaskState::Cancelled,
    ];

    #[test]
    fn state_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for state in ALL_STATES {
            let code = state.as_str();
            assert!(!code.is_empty(), "task state codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one task state"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(state));
            assert_eq!(state.to_string(), code);
        }
        // Unknown codes — including `unsupported_value`, the code
        // `nv-redfish` maps a newer-CSDL `TaskState` onto — are refused,
        // never disguised as a known state (§7.6).
        assert_eq!(
            "unsupported_value".parse::<RemoteTaskState>(),
            Err(RemoteTaskStateParseError)
        );
        assert_eq!(
            "stopped".parse::<RemoteTaskState>(),
            Err(RemoteTaskStateParseError)
        );
    }

    #[test]
    fn terminal_states_follow_the_csdl_completion_semantics() {
        for state in ALL_STATES {
            let expected = matches!(
                state,
                RemoteTaskState::Completed
                    | RemoteTaskState::Exception
                    | RemoteTaskState::Killed
                    | RemoteTaskState::Cancelled
            );
            assert_eq!(
                state.is_terminal(),
                expected,
                "terminality of {state} must follow the CSDL completion semantics"
            );
        }
        // The look-alike states are the interesting half of the contract:
        // a task being cancelled or stopped has not finished yet, and a
        // Service task never completes on its own.
        assert!(!RemoteTaskState::Cancelling.is_terminal());
        assert!(!RemoteTaskState::Stopping.is_terminal());
        assert!(!RemoteTaskState::Service.is_terminal());
        assert!(!RemoteTaskState::Suspended.is_terminal());
    }

    #[test]
    fn new_records_the_acceptance_observation() -> Result<(), Box<dyn Error>> {
        let operation_id = OperationId::generate();
        let endpoint_id = EndpointId::generate();
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let monitor_uri = TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/42")?;
        let accepted_at = OffsetDateTime::UNIX_EPOCH;

        let task = RemoteTask::new(
            operation_id,
            endpoint_id,
            task_uri.clone(),
            Some(monitor_uri.clone()),
            accepted_at,
        );

        assert_eq!(task.operation_id(), operation_id);
        assert_eq!(task.endpoint_id(), endpoint_id);
        assert_eq!(task.task_uri(), &task_uri);
        assert_eq!(task.task_monitor_uri(), Some(&monitor_uri));
        // Nothing has been observed yet: the placeholder state, no message,
        // no progress, and the acceptance time as the check time.
        assert_eq!(task.last_state(), RemoteTaskState::New);
        assert_eq!(task.last_message(), None);
        assert_eq!(task.percent_complete(), None);
        assert_eq!(task.last_checked_at(), accepted_at);
        assert!(!task.is_terminal());
        Ok(())
    }

    #[test]
    fn a_task_uri_can_stand_alone_when_the_bmc_gives_only_one_uri() -> Result<(), Box<dyn Error>> {
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/7")?;

        let task = RemoteTask::new(
            OperationId::generate(),
            EndpointId::generate(),
            task_uri.clone(),
            None,
            OffsetDateTime::UNIX_EPOCH,
        );

        assert_eq!(task.task_uri(), &task_uri);
        assert_eq!(task.task_monitor_uri(), None);
        Ok(())
    }

    #[test]
    fn try_from_parts_restores_a_persisted_record() -> Result<(), Box<dyn Error>> {
        let operation_id = OperationId::generate();
        let endpoint_id = EndpointId::generate();
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let monitor_uri = TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/42")?;
        let checked_at = OffsetDateTime::UNIX_EPOCH + Duration::MINUTE;

        let restored = RemoteTask::try_from_parts(
            operation_id,
            endpoint_id,
            task_uri.clone(),
            Some(monitor_uri.clone()),
            RemoteTaskState::Running,
            Some("performing the power cycle".to_owned()),
            Some(40),
            checked_at,
        )?;

        assert_eq!(restored.operation_id(), operation_id);
        assert_eq!(restored.endpoint_id(), endpoint_id);
        assert_eq!(restored.task_uri(), &task_uri);
        assert_eq!(restored.task_monitor_uri(), Some(&monitor_uri));
        assert_eq!(restored.last_state(), RemoteTaskState::Running);
        assert_eq!(restored.last_message(), Some("performing the power cycle"));
        assert_eq!(restored.percent_complete(), Some(40));
        assert_eq!(restored.last_checked_at(), checked_at);
        assert!(!restored.is_terminal());
        Ok(())
    }

    #[test]
    fn try_from_parts_rejects_a_corrupt_percent_complete() -> Result<(), Box<dyn Error>> {
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;

        assert_eq!(
            RemoteTask::try_from_parts(
                OperationId::generate(),
                EndpointId::generate(),
                task_uri,
                None,
                RemoteTaskState::Running,
                None,
                Some(150),
                OffsetDateTime::UNIX_EPOCH,
            ),
            Err(RemoteTaskError::PercentOutOfRange {
                percent_complete: 150,
            })
        );
        // The CSDL boundary values are legal.
        let boundary = RemoteTask::try_from_parts(
            OperationId::generate(),
            EndpointId::generate(),
            TaskUri::parse("/redfish/v1/TaskService/Tasks/43")?,
            None,
            RemoteTaskState::Completed,
            None,
            Some(100),
            OffsetDateTime::UNIX_EPOCH,
        )?;
        assert_eq!(boundary.percent_complete(), Some(100));
        Ok(())
    }

    #[test]
    fn task_uri_rejects_blank_and_malformed_values() {
        assert_eq!(TaskUri::parse(""), Err(TaskUriError::Empty));
        assert_eq!(
            TaskUri::parse(" /redfish/v1/TaskService/Tasks/42"),
            Err(TaskUriError::SurroundingWhitespace)
        );
        assert_eq!(
            TaskUri::parse("/redfish/v1/TaskService/Tasks/4\u{1}2"),
            Err(TaskUriError::ControlCharacter)
        );
        let prefix = "/redfish/v1/TaskService/Tasks/";
        let oversized = format!("{prefix}{}", "x".repeat(MAX_TASK_URI_BYTES));
        assert_eq!(
            TaskUri::parse(&oversized),
            Err(TaskUriError::TooLong {
                actual: prefix.len() + MAX_TASK_URI_BYTES,
                maximum: MAX_TASK_URI_BYTES,
            })
        );
    }

    #[test]
    fn task_uri_round_trips_through_text() -> Result<(), Box<dyn Error>> {
        let original = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;

        let parsed = original.to_string().parse::<TaskUri>()?;

        assert_eq!(parsed, original);
        assert_eq!(parsed.as_str(), "/redfish/v1/TaskService/Tasks/42");
        Ok(())
    }
}
