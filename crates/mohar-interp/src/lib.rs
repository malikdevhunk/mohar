//! Tree-walking interpreter.
//!
//! v0.1 executes the typed tree rather than a separate bytecode. The same
//! tree is what the IR printer hashes, so the seal describes the program
//! that runs. Capability operations are checked again here, including path
//! normalisation, so a bug in the checker is not the only line of defence.
//!
//! The interpreter is not constant-time. Rejecting secret branches in the
//! checker does not make this walk, the allocator, or the CPU constant-time.

mod exec;
mod host;
mod value;

pub use exec::{Outcome, run_program};
pub use host::{Host, Trap};
pub use value::{Cap, Value};
