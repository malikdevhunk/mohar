//! The behavioural corpus: programs that run, and programs that must not.
//!
//! Leak tests name the error code they must produce. A diagnostic that
//! mentions the wrong code, or a program that type-checks, fails the test.

use std::fs;
use std::path::{Path, PathBuf};

use mohar_diag::{SourceFile, render_all};
use mohar_interp::{Host, run_program};
use mohar_types::{CheckOptions, CryptoPolicy, Grant, PolicyKind, check_source};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn header<'a>(src: &'a str, key: &str) -> Option<&'a str> {
    for line in src.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("//") {
            let rest = rest.trim();
            if let Some(value) = rest.strip_prefix(key) {
                return Some(value.trim().trim_start_matches(':').trim());
            }
        } else if !line.is_empty() {
            break;
        }
    }
    None
}

fn options_for(src: &str) -> CheckOptions {
    let mut opts = CheckOptions::default();
    if let Some(policy) = header(src, "policy") {
        opts.policy.kind = PolicyKind::parse(policy.trim()).expect("policy name");
    }
    if header(src, "grant").is_some() {
        opts.grant = Some(Grant {
            net: vec!["api.example.com:443".into()],
            console: true,
            ..Grant::default()
        });
    }
    opts.policy.today = "2026-11-18".into();
    opts
}

#[test]
fn leaks_fail_with_the_named_code() {
    let dir = root().join("tests/leaks");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.retain(|p| p.extension().and_then(|s| s.to_str()) == Some("mo"));
    files.sort();
    assert!(
        files.len() >= 40,
        "expected at least 40 must-not-compile tests, found {}",
        files.len()
    );
    for path in files {
        let src = fs::read_to_string(&path).unwrap();
        let code =
            header(&src, "error").unwrap_or_else(|| panic!("{} missing // error:", path.display()));
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let file = SourceFile::new(&name, src.clone());
        let checked = check_source(&file, &options_for(&src));
        let rendered = render_all(&file, &checked.diagnostics);
        assert!(
            !checked.ok(),
            "{} type-checked, but it must be rejected:\n{rendered}",
            path.display()
        );
        assert!(
            rendered.contains(&format!("[{code}]")) || rendered.contains(&format!("error[{code}]")),
            "{} did not report {code}:\n{rendered}",
            path.display()
        );
    }
}

#[test]
fn ok_programs_behave() {
    let dir = root().join("tests/ok");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.retain(|p| p.extension().and_then(|s| s.to_str()) == Some("mo"));
    files.sort();
    assert!(
        files.len() >= 20,
        "expected at least 20 positive tests, found {}",
        files.len()
    );
    for path in files {
        let src = fs::read_to_string(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let file = SourceFile::new(&name, src.clone());
        let checked = check_source(&file, &options_for(&src));
        let rendered = render_all(&file, &checked.diagnostics);
        assert!(
            checked.ok(),
            "{} failed to type-check:\n{rendered}",
            path.display()
        );
        if header(&src, "check").is_some() && header(&src, "stdout").is_none() {
            continue;
        }
        if let Some(expect) = header(&src, "stdout") {
            let expect = expect.replace("\\n", "\n");
            let mut host = Host::new(Grant::default(), PathBuf::from("."));
            let outcome = run_program(&checked, &mut host)
                .unwrap_or_else(|e| panic!("{} runtime error: {}", path.display(), e.0));
            assert_eq!(outcome.stdout, expect, "{}", path.display());
        }
    }
}

#[test]
fn flagship_diagnostics_quote_the_source() {
    let src = "fn bad(expected: secret [u8; 32], given: [u8; 32]) -> bool {\n    if expected == given { true } else { false }\n}\n";
    let file = SourceFile::new("bad.mo", src);
    let checked = check_source(&file, &CheckOptions::default());
    let text = render_all(&file, &checked.diagnostics);
    assert!(text.contains("error[E101]: branch condition depends on a secret value"));
    assert!(text.contains("--> bad.mo:2:8"));
    assert!(text.contains("use std.ct::select or std.ct::verify_eq"));
}

#[test]
fn legacy_use_warns_under_hybrid_policy() {
    let src = "use std.legacy::ecdsa_p256;\nfn main(caps: Caps) {}\n";
    let file = SourceFile::new("legacy.mo", src);
    let opts = CheckOptions {
        policy: CryptoPolicy {
            today: "2026-11-18".into(),
            ..CryptoPolicy::default()
        },
        ..CheckOptions::default()
    };
    let checked = check_source(&file, &opts);
    assert!(checked.ok());
    let text = render_all(&file, &checked.diagnostics);
    assert!(text.contains("warning[Q101]"));
    assert!(text.contains("2030"));
}

#[test]
fn two_builds_hash_the_same() {
    let src = fs::read_to_string(root().join("examples/hello.mo")).unwrap();
    let file = SourceFile::new("hello.mo", src.clone());
    let a = check_source(&file, &CheckOptions::default());
    let b = check_source(&file, &CheckOptions::default());
    let ha = mohar_ir::emit(&a, &src);
    let hb = mohar_ir::emit(&b, &src);
    assert_eq!(ha.ir, hb.ir);
    assert_eq!(ha.ir_sha3_256, hb.ir_sha3_256);
}

#[test]
fn authority_trace_is_covered_by_the_report() {
    let src = fs::read_to_string(root().join("examples/invoice_plan.mo")).unwrap();
    let file = SourceFile::new("invoice_plan.mo", src);
    let opts = CheckOptions {
        grant: Some(Grant {
            fs_read: vec!["inbox".into()],
            model: true,
            tools: vec!["mail.send".into()],
            console: false,
            rand: false,
            clock: false,
            ..Grant::default()
        }),
        ..CheckOptions::default()
    };
    let checked = check_source(&file, &opts);
    assert!(checked.ok(), "{}", render_all(&file, &checked.diagnostics));
    let mut host = Host::new(opts.grant.clone().unwrap(), root().join("examples"));
    run_program(&checked, &mut host).unwrap();
    for line in &host.trace {
        let cap = line.split_whitespace().next().unwrap();
        assert!(
            checked.authority.iter().any(|a| a.cap == cap),
            "trace {line} not in {:?}",
            checked.authority
        );
    }
}

fn _path(p: &Path) -> &Path {
    p
}
