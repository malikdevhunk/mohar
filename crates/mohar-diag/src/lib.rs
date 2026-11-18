//! Diagnostics for the Mohar compiler.
//!
//! Every diagnostic carries a stable error code, one or more spans, and
//! optional notes and hints. The renderer prints them in the familiar
//! compiler style: message, file location, source line, carets.

mod codes;
mod emit;
mod span;

pub use codes::{Code, Severity};
pub use emit::render;
pub use span::{SourceFile, Span};

/// One labelled region of source attached to a diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanLabel {
    pub span: Span,
    pub message: Option<String>,
    pub primary: bool,
}

/// A single compiler diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: Option<Code>,
    pub message: String,
    pub labels: Vec<SpanLabel>,
    pub notes: Vec<String>,
    pub help: Vec<String>,
}

impl Diagnostic {
    pub fn error(code: Code, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: Some(code),
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
        }
    }

    pub fn warning(code: Code, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: Some(code),
            message: message.into(),
            labels: Vec::new(),
            notes: Vec::new(),
            help: Vec::new(),
        }
    }

    pub fn with_primary(mut self, span: Span, message: impl Into<String>) -> Self {
        let message = message.into();
        self.labels.push(SpanLabel {
            span,
            message: if message.is_empty() {
                None
            } else {
                Some(message)
            },
            primary: true,
        });
        self
    }

    pub fn with_secondary(mut self, span: Span, message: impl Into<String>) -> Self {
        self.labels.push(SpanLabel {
            span,
            message: Some(message.into()),
            primary: false,
        });
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help.push(help.into());
        self
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// Render a batch of diagnostics, sorted by source position.
pub fn render_all(file: &SourceFile, diags: &[Diagnostic]) -> String {
    let mut ordered: Vec<&Diagnostic> = diags.iter().collect();
    ordered.sort_by_key(|d| {
        d.labels
            .iter()
            .find(|l| l.primary)
            .map(|l| l.span.start)
            .unwrap_or(0)
    });
    let mut out = String::new();
    for (i, d) in ordered.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&render(file, d));
        out.push('\n');
    }
    let errors = diags.iter().filter(|d| d.is_error()).count();
    let warnings = diags.len() - errors;
    if errors > 0 || warnings > 0 {
        if !out.is_empty() {
            out.push('\n');
        }
        if errors > 0 {
            out.push_str(&format!(
                "error: aborting due to {errors} previous error{}\n",
                if errors == 1 { "" } else { "s" }
            ));
        }
        if warnings > 0 {
            out.push_str(&format!(
                "warning: {warnings} warning{} emitted\n",
                if warnings == 1 { "" } else { "s" }
            ));
        }
    }
    out
}

pub fn has_errors(diags: &[Diagnostic]) -> bool {
    diags.iter().any(Diagnostic::is_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caret_points_at_the_span() {
        let file = SourceFile::new("bad.mo", "fn main() {\n    if secret { 1 }\n}\n");
        let diag = Diagnostic::error(Code::E101, "branch condition depends on a secret value")
            .with_primary(Span::new(19, 25), "")
            .with_help(
                "use std.ct::select or std.ct::verify_eq; secret-dependent branches leak timing",
            );
        let text = render(&file, &diag);
        assert!(text.contains("error[E101]: branch condition depends on a secret value"));
        assert!(text.contains("--> bad.mo:2:8"));
        assert!(text.contains("^^^^^^"));
        assert!(text.contains("= help: use std.ct::select"));
    }
}
