//! Stable diagnostic codes.
//!
//! * `E0xx` — syntax and ordinary types
//! * `E1xx` — secrecy and constant-time rules
//! * `E2xx` — capabilities, scopes and profiles
//! * `E3xx` — integrity
//! * `E4xx` — crypto policy
//! * `Q1xx` — quantum-vulnerability lints

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A stable code printed as `E101` or `Q101`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    // Syntax and base types.
    E001,
    E002,
    E003,
    E004,
    E005,
    E006,
    E007,
    E008,
    E009,
    // Secrecy / constant time.
    E101,
    E102,
    E103,
    E104,
    E105,
    // Capabilities.
    E201,
    E202,
    E203,
    E204,
    E205,
    E206,
    E207,
    E208,
    E209,
    E210,
    E211,
    E212,
    // Integrity.
    E301,
    E302,
    // Crypto policy.
    E401,
    E402,
    E403,
    // Quantum lint.
    Q101,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::E001 => "E001",
            Self::E002 => "E002",
            Self::E003 => "E003",
            Self::E004 => "E004",
            Self::E005 => "E005",
            Self::E006 => "E006",
            Self::E007 => "E007",
            Self::E008 => "E008",
            Self::E009 => "E009",
            Self::E101 => "E101",
            Self::E102 => "E102",
            Self::E103 => "E103",
            Self::E104 => "E104",
            Self::E105 => "E105",
            Self::E201 => "E201",
            Self::E202 => "E202",
            Self::E203 => "E203",
            Self::E204 => "E204",
            Self::E205 => "E205",
            Self::E206 => "E206",
            Self::E207 => "E207",
            Self::E208 => "E208",
            Self::E209 => "E209",
            Self::E210 => "E210",
            Self::E211 => "E211",
            Self::E212 => "E212",
            Self::E301 => "E301",
            Self::E302 => "E302",
            Self::E401 => "E401",
            Self::E402 => "E402",
            Self::E403 => "E403",
            Self::Q101 => "Q101",
        }
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
