//! Library surface used by the `mohar` binary and the integration tests.

use std::fs;
use std::path::{Path, PathBuf};

use mohar_diag::{SourceFile, render_all};
use mohar_interp::{Host, run_program};
use mohar_ir::emit;
use mohar_seal::{load_config, load_grant};
use mohar_std::version::AUDIT_NOTICE;
use mohar_syntax::print::format_program;
use mohar_types::{CheckOptions, CryptoPolicy, Grant, check_source};

pub struct Pipeline {
    pub checked: mohar_types::Checked,
    pub source: String,
    pub file: SourceFile,
    pub config: mohar_seal::Config,
}

pub fn load_pipeline(
    path: &Path,
    grant: Option<&Path>,
    config: Option<&Path>,
) -> Result<Pipeline, String> {
    let source = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input.mo");
    let file = SourceFile::new(name, source.clone());
    let cfg_path = config
        .map(Path::to_path_buf)
        .or_else(|| find_up(path, "mohar.toml"));
    let mut config = if let Some(p) = cfg_path {
        load_config(&p).map_err(|e| e.to_string())?
    } else {
        mohar_seal::Config::default()
    };
    config.policy.today = today_iso();
    let grant = if let Some(g) = grant {
        Some(load_grant(g).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let opts = CheckOptions {
        policy: config.policy.clone(),
        grant,
    };
    let checked = check_source(&file, &opts);
    Ok(Pipeline {
        checked,
        source,
        file,
        config,
    })
}

pub fn diagnostics(pipeline: &Pipeline) -> String {
    render_all(&pipeline.file, &pipeline.checked.diagnostics)
}

pub fn developer_grant(fuel: u64, memory_mib: u64) -> Grant {
    Grant {
        fuel,
        memory_mib,
        ..Grant::default()
    }
}

pub fn run_with(pipeline: &Pipeline, grant: Grant, root: PathBuf) -> Result<Host, String> {
    if !pipeline.checked.ok() {
        return Err(diagnostics(pipeline));
    }
    let mut host = Host::new(grant, root);
    host.kem_algorithm = pipeline.config.policy.default_kem().to_string();
    host.sig_algorithm = pipeline.config.policy.default_sig().to_string();
    let outcome = run_program(&pipeline.checked, &mut host).map_err(|e| e.0)?;
    host.stdout = outcome.stdout;
    Ok(host)
}

pub fn build_artifact(pipeline: &Pipeline) -> mohar_ir::Artifact {
    emit(&pipeline.checked, &pipeline.source)
}

pub fn format_source(source: &str, name: &str) -> Result<String, String> {
    let file = SourceFile::new(name, source);
    let parsed = mohar_syntax::parse(&file);
    if mohar_diag::has_errors(&parsed.diagnostics) {
        return Err(render_all(&file, &parsed.diagnostics));
    }
    Ok(format_program(&parsed.program))
}

pub fn audit_notice() -> &'static str {
    AUDIT_NOTICE
}

pub fn policy_of(pipeline: &Pipeline) -> &CryptoPolicy {
    &pipeline.config.policy
}

pub fn find_up(start: &Path, name: &str) -> Option<PathBuf> {
    let mut dir = start.parent()?.to_path_buf();
    loop {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn today_iso() -> String {
    // A fixed calendar read so the binary does not need an extra date crate.
    // The process clock is civil time; we only need YYYY-MM-DD.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 2026-11-18 is day 20779 of the unix epoch? We compute via the civil
    // algorithm from Howard Hinnant, which is public domain.
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub use mohar_seal::{PublicKeyFile, review_against, review_text, seal_program, verify_seal};
