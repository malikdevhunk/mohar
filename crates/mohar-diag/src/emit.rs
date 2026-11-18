//! Plain-text diagnostic rendering.
//!
//! Colour is intentionally not applied here. Callers that want a terminal
//! palette can wrap the severity word; tests and seals depend on the bytes
//! being stable.

use crate::{Diagnostic, SourceFile, Span};

pub fn render(file: &SourceFile, diag: &Diagnostic) -> String {
    let mut out = String::new();
    let sev = match diag.severity {
        crate::Severity::Error => "error",
        crate::Severity::Warning => "warning",
    };
    if let Some(code) = diag.code {
        out.push_str(&format!("{sev}[{code}]: {}\n", diag.message));
    } else {
        out.push_str(&format!("{sev}: {}\n", diag.message));
    }

    let primary = diag.labels.iter().find(|l| l.primary);
    let anchor = primary.map(|l| l.span).unwrap_or(Span::DUMMY);
    let (line, col) = file.line_col(anchor.start);
    let name = &file.name;
    out.push_str(&format!("  --> {name}:{line}:{col}\n"));

    let mut spans: Vec<&crate::SpanLabel> = diag.labels.iter().collect();
    spans.sort_by_key(|l| (l.span.start, !l.primary));

    // Group by source line. v0.1 prints one caret line per label, which is
    // enough for the messages we emit (a primary span plus the place a label
    // was introduced).
    if spans.is_empty() {
        out.push_str("   |\n");
    }
    let mut last_line = 0u32;
    for label in spans {
        let (l, c) = file.line_col(label.span.start);
        if l != last_line {
            out.push_str("   |\n");
            let text = file.line_text(l);
            let num = l.to_string();
            let pad = num.len();
            out.push_str(&format!("{num:>pad$} | {text}\n"));
            last_line = l;
        }
        let caret_len = caret_width(file, label.span).max(1);
        let spaces = " ".repeat(c.saturating_sub(1) as usize);
        let carets = if label.primary {
            "^".repeat(caret_len)
        } else {
            "-".repeat(caret_len)
        };
        let num_width = l.to_string().len();
        out.push_str(&format!("{:num_width$} | {spaces}{carets}", ""));
        if let Some(msg) = &label.message {
            out.push(' ');
            out.push_str(msg);
        }
        out.push('\n');
    }

    for note in &diag.notes {
        out.push_str(&format!("   |\n   = note: {note}\n"));
    }
    for help in &diag.help {
        if diag.notes.is_empty() {
            out.push_str("   |\n");
        }
        out.push_str(&format!("   = help: {help}\n"));
    }
    // Trim the trailing newline so callers can join diagnostics themselves.
    while out.ends_with('\n') {
        out.pop();
    }
    out
}

fn caret_width(file: &SourceFile, span: Span) -> usize {
    let (line, col) = file.line_col(span.start);
    let line_text = file.line_text(line);
    let start_idx = col.saturating_sub(1) as usize;
    let chars: Vec<char> = line_text.chars().collect();
    if start_idx >= chars.len() {
        return 1;
    }
    let (end_line, end_col) = file.line_col(span.end);
    if end_line != line {
        return chars.len().saturating_sub(start_idx).max(1);
    }
    let end_idx = (end_col.saturating_sub(1) as usize).min(chars.len());
    end_idx.saturating_sub(start_idx).max(1)
}
