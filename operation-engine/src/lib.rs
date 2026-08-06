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
//!   The engine never sees `SQLite` or `SeaORM` (design section 7.3).
//! - [`OperationEngine`] is the generic coordinator: it constructs and
//!   persists new operations, applies domain events, lists operations, and
//!   reports the operations left in a recoverable state after a restart.
//! - [`EngineError`] wraps the store's own error type so every persistence
//!   failure keeps its context while the engine adds its own verdicts.
//!
//! Executing BMC actions is deliberately out of scope for this crate: the
//! engine persists and advances state, and the future scheduler in
//! `rutilus-application` performs the actual work between steps (design
//! section 13.3 steps 7-10).

#![forbid(unsafe_code)]

mod operation_engine;
mod operation_store;

pub use operation_engine::{EngineError, OperationEngine, RECOVERABLE_STATES};
pub use operation_store::{BoundaryFuture, OperationStore};
