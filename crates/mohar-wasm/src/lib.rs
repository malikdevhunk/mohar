//! A small wrapper the playground can call.
//!
//! v0.1 compiles this as an ordinary Rust library: `check` returns the
//! diagnostic text, `review` returns the authority report. Binding it with
//! `wasm-bindgen` and serving `playground/` is the next step. The crate is
//! here so that binding does not have to reach into the checker by hand.

use mohar_diag::{SourceFile, render_all};
use mohar_types::{CheckOptions, check_source};

/// Type-check `source` and return the diagnostic text (empty if it is clean).
pub fn check(source: &str) -> String {
    let file = SourceFile::new("playground.mo", source);
    let checked = check_source(&file, &CheckOptions::default());
    render_all(&file, &checked.diagnostics)
}

/// Authority report for a program that type-checks. If it does not, the
/// diagnostics are returned instead, so a page can show one string.
pub fn review(source: &str) -> String {
    let file = SourceFile::new("playground.mo", source);
    let checked = check_source(&file, &CheckOptions::default());
    if !checked.ok() {
        return render_all(&file, &checked.diagnostics);
    }
    mohar_seal::review_text(&checked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_has_no_diagnostics() {
        let src = "fn main(caps: Caps) {\n    let out = caps.console();\n    out.println(\"namaste, duniya\");\n}\n";
        assert!(check(src).is_empty() || !check(src).contains("error["));
        let report = review(src);
        assert!(report.contains("Console"));
    }
}
