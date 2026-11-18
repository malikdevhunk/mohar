//! Bidirectional type checker for Mohar.
//!
//! Checking order is the one in the design: shapes, then labels, then the
//! program-counter label, then capabilities and scopes, then the profile,
//! then the crypto policy. Diagnostics name the place a `secret` or
//! `untrusted` label was introduced.

mod check;
mod label;
mod policy;
mod ty;

pub use check::{CheckOptions, Checked, Res, check_source};
pub use label::{Conf, Integ, Label};
pub use policy::{
    AuthorityEntry, CryptoPolicy, CryptoUse, FlowNote, FlowNoteKind, Grant, Origin, PolicyKind,
    Profile,
};
pub use ty::{BaseTy, IntKind, Ty, cap_subtype, host_narrows, normalize_scope, path_narrows};
