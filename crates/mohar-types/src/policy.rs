//! Compile-time crypto policy.
//!
//! `pq-hybrid` (the default) resolves `Kem::default` to X25519 + ML-KEM-768
//! and `Sig::default` to ML-DSA-65, and admits legacy algorithms with a
//! warning until `allow_legacy_until`. `pq-only` resolves the KEM to
//! ML-KEM-1024 and rejects legacy algorithms. `legacy` keeps the hybrid KEM
//! default but is explicit that classical algorithms are expected.

use mohar_diag::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyKind {
    PqHybrid,
    PqOnly,
    Legacy,
}

impl PolicyKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pq-hybrid" => Some(Self::PqHybrid),
            "pq-only" => Some(Self::PqOnly),
            "legacy" => Some(Self::Legacy),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqHybrid => "pq-hybrid",
            Self::PqOnly => "pq-only",
            Self::Legacy => "legacy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoPolicy {
    pub kind: PolicyKind,
    /// Inclusive last day, `YYYY-MM-DD`. Compared lexicographically, which
    /// works for this fixed format.
    pub allow_legacy_until: String,
    /// The day the compiler treats as "today", so tests do not depend on the clock.
    pub today: String,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            kind: PolicyKind::PqHybrid,
            allow_legacy_until: "2030-01-01".to_string(),
            today: "2026-11-18".to_string(),
        }
    }
}

impl CryptoPolicy {
    pub fn legacy_allowed(&self) -> bool {
        self.kind != PolicyKind::PqOnly && self.today.as_str() <= self.allow_legacy_until.as_str()
    }

    pub fn default_kem(&self) -> &'static str {
        match self.kind {
            PolicyKind::PqOnly => "ML-KEM-1024",
            PolicyKind::PqHybrid | PolicyKind::Legacy => "X25519-MLKEM768",
        }
    }

    pub fn default_sig(&self) -> &'static str {
        "ML-DSA-65"
    }
}

/// One cryptographic call the checker resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoUse {
    pub span: Span,
    pub algorithm: String,
    pub quantum_safe: bool,
    pub site: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Profile {
    #[default]
    Default,
    Sealed,
    Plan,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "sealed" => Some(Self::Sealed),
            "plan" => Some(Self::Plan),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Sealed => "sealed",
            Self::Plan => "plan",
        }
    }

    /// Sealed and plan both require constant scopes and an explicit fuel limit.
    pub fn is_sealed(self) -> bool {
        matches!(self, Self::Sealed | Self::Plan)
    }
}

/// Host grant. Absent means the checker does not assume one; `mohar run`
/// still applies the developer grant (console, rand, clock).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub console: bool,
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub net: Vec<String>,
    pub tools: Vec<String>,
    pub model: bool,
    pub rand: bool,
    pub clock: bool,
    pub declassify: bool,
    pub endorse: bool,
    pub fuel: u64,
    pub memory_mib: u64,
}

impl Default for Grant {
    fn default() -> Self {
        Self {
            console: true,
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            net: Vec::new(),
            tools: Vec::new(),
            model: false,
            rand: true,
            clock: true,
            declassify: false,
            endorse: false,
            fuel: 5_000_000,
            memory_mib: 64,
        }
    }
}

impl Grant {
    pub fn covers_cap(&self, cap: &str, scope: Option<&str>) -> bool {
        match cap {
            "Console" => self.console,
            "Model" => self.model,
            "Rand" => self.rand,
            "Clock" => self.clock,
            "Declassify" => self.declassify,
            "Endorse" => self.endorse,
            "FsRead" => {
                scope.is_some_and(|s| self.fs_read.iter().any(|g| crate::ty::path_narrows(s, g)))
            }
            "FsWrite" => {
                scope.is_some_and(|s| self.fs_write.iter().any(|g| crate::ty::path_narrows(s, g)))
            }
            "Net" => scope.is_some_and(|s| {
                self.net
                    .iter()
                    .any(|g| crate::ty::host_narrows(s, g) || s == g)
            }),
            "Tool" => scope.is_some_and(|s| self.tools.iter().any(|g| g == s)),
            _ => false,
        }
    }
}

/// Where a label was introduced, so an error can point at it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub span: Span,
    pub name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEntry {
    pub cap: String,
    pub scope: Option<String>,
    pub ops: Vec<String>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowNote {
    pub kind: FlowNoteKind,
    pub name: String,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowNoteKind {
    Declassify,
    Endorse,
    TrustedDeclassifier,
    TrustedEndorser,
}
