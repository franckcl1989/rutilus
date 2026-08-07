//! The persistent Operation lifecycle engine (design section 13).
//!
//! Design section 13.1 turns every write the product performs into a persisted
//! [`Operation`](rutilus_domain::Operation) that is advanced through the
//! domain state machine one persisted step at a time (design section 13.3), so
//! unfinished work survives a process restart and can be recovered (design
//! section 13.6).
//!
//! # Crate shape
//!
//! - [`OperationStore`] is the persistence boundary: it is implemented by
//!   `rutilus-persistence` in production and by an in-memory fake in tests.
//!   The engine never sees `SQLite` or `SeaORM` (design section 7.3). The
//!   boundary also carries the §13.7 batch surface — `create_batch` commits
//!   one batch parent and its ordinary single-target child operations
//!   atomically and idempotently, plus the batch read queries — because a
//!   batch is persisted through the same store as every other operation.
//! - [`OperationEngine`] is the generic coordinator: it constructs and
//!   persists new operations, applies domain events, lists operations,
//!   constructs batch parents with their child operations, and reports the
//!   operations left in a recoverable state after a restart.
//! - [`EngineError`] wraps the store's own error type so every persistence
//!   failure keeps its context while the engine adds its own verdicts.
//! - [`RemoteTask`], [`RemoteTaskState`], and [`TaskUri`] are the §13.6
//!   observation model: one record per operation that reached
//!   `WaitingRemote`, carrying the Task and `TaskMonitor` URIs plus the
//!   newest observed state, message, and progress.
//! - [`RemoteTaskStore`] is the observation persistence boundary, also
//!   implemented by `rutilus-persistence` in production and by an in-memory
//!   fake in tests. Saving an observation never moves the operation state
//!   machine — that is always [`OperationEngine::apply`]'s job.
//!
//! # Driving the Task flow (§13.6)
//!
//! The Task acceptance and completion events (`RemoteTaskStarted`,
//! `RemoteTaskCompleted`) are ordinary
//! [`OperationEvent`](rutilus_domain::OperationEvent)s already driven
//! through [`OperationEngine::apply`]; no separate Task engine API exists.
//! The application's Task monitor composes the two boundaries: on
//! acceptance and on every poll it saves the newest observation through
//! [`RemoteTaskStore::save_remote_task`], and when the observation is
//! terminal it applies the corresponding event. The composition needs no
//! atomicity: both halves are idempotent, so a crash between them leaves
//! the terminal observation persisted and the §13.6 restart scan resumes by
//! re-reading the row and applying the event. The scan itself is
//! [`OperationEngine::recover_pending`] plus a `RemoteTaskStore` read per
//! `WaitingRemote` operation.
//!
//! Executing BMC actions is deliberately out of scope for this crate: the
//! engine persists and advances state, and the future scheduler in
//! `rutilus-application` performs the actual work between steps (design
//! section 13.3 steps 7-10).

#![forbid(unsafe_code)]

mod operation_engine;
mod operation_store;
mod remote_task;
mod remote_task_store;

pub use operation_engine::{EngineError, MAX_BATCH_TARGETS, OperationEngine, RECOVERABLE_STATES};
pub use operation_store::{BoundaryFuture, ClassifiedBatchChild, OperationStore};
pub use remote_task::{
    RemoteTask, RemoteTaskError, RemoteTaskState, RemoteTaskStateParseError, TaskUri, TaskUriError,
};
pub use remote_task_store::RemoteTaskStore;
