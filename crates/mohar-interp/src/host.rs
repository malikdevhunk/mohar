//! The capability host. Every operation re-checks the grant and, for files,
//! refuses `..`, absolute paths and symlinks.

use std::fs;
use std::path::{Path, PathBuf};

use mohar_types::Grant;

use crate::value::Cap;

/// A runtime failure: fuel, a grant check, a bad path, a crypto error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trap(pub String);

#[derive(Clone, Debug)]
pub struct Host {
    pub grant: Grant,
    pub root: PathBuf,
    pub stdout: String,
    pub trace: Vec<String>,
    pub fuel: u64,
    pub memory_used: u64,
    pub net_log: Vec<(String, Vec<u8>)>,
    pub tool_log: Vec<(String, Vec<String>)>,
    /// Deterministic stand-in for `model.ask`. The real host can replace this.
    pub model_reply: String,
    /// Algorithm `Kem::default` resolved to. Set from the crypto policy.
    pub kem_algorithm: String,
    /// Algorithm `Sig::default` resolved to.
    pub sig_algorithm: String,
}

impl Host {
    pub fn new(grant: Grant, root: PathBuf) -> Self {
        let fuel = grant.fuel;
        Self {
            grant,
            root,
            stdout: String::new(),
            trace: Vec::new(),
            fuel,
            memory_used: 0,
            net_log: Vec::new(),
            tool_log: Vec::new(),
            model_reply: "Two sentence summary.".into(),
            kem_algorithm: "X25519-MLKEM768".into(),
            sig_algorithm: "ML-DSA-65".into(),
        }
    }

    pub fn charge(&mut self, n: u64) -> Result<(), Trap> {
        if self.fuel < n {
            return Err(Trap("out of fuel".into()));
        }
        self.fuel -= n;
        Ok(())
    }

    pub fn charge_mem(&mut self, n: u64) -> Result<(), Trap> {
        let limit = self.grant.memory_mib.saturating_mul(1024 * 1024);
        self.memory_used = self.memory_used.saturating_add(n);
        if self.memory_used > limit {
            return Err(Trap("memory limit exceeded".into()));
        }
        Ok(())
    }

    pub fn trace_op(&mut self, cap: &str, scope: Option<&str>, op: &str) {
        let scope = scope.unwrap_or("-");
        self.trace.push(format!("{cap} {scope} {op}"));
    }

    pub fn allow(&self, cap: &Cap) -> Result<(), Trap> {
        let (name, scope) = cap_parts(cap);
        if self.grant.covers_cap(name, scope) {
            Ok(())
        } else {
            Err(Trap(format!(
                "capability {name}{} was not granted",
                scope.map(|s| format!("<{s}>")).unwrap_or_default()
            )))
        }
    }

    /// Map a path onto the sandbox root, or reject it.
    pub fn resolve_file(&self, scope: &str, rel: &str) -> Result<PathBuf, Trap> {
        if rel.contains('\0') || rel.starts_with('/') || rel.starts_with('\\') {
            return Err(Trap("path escapes its scope".into()));
        }
        if rel.split(['/', '\\']).any(|p| p == "..") {
            return Err(Trap("path escapes its scope".into()));
        }
        let scope = scope.strip_prefix("./").unwrap_or(scope);
        let rel = rel.strip_prefix("./").unwrap_or(rel);
        let full = self.root.join(scope).join(rel);
        reject_symlinks(&self.root, &full)?;
        let root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        let check = if full.exists() {
            full.canonicalize().unwrap_or(full.clone())
        } else {
            full.clone()
        };
        if !check.starts_with(&root) && !full.starts_with(&self.root) {
            return Err(Trap("path escapes the sandbox root".into()));
        }
        Ok(full)
    }
}

fn cap_parts(cap: &Cap) -> (&'static str, Option<&str>) {
    match cap {
        Cap::Console => ("Console", None),
        Cap::FsRead(s) => ("FsRead", Some(s)),
        Cap::FsWrite(s) => ("FsWrite", Some(s)),
        Cap::Net(s) => ("Net", Some(s)),
        Cap::Tool(s) => ("Tool", Some(s)),
        Cap::Model => ("Model", None),
        Cap::Rand => ("Rand", None),
        Cap::Clock => ("Clock", None),
        Cap::Declassify => ("Declassify", None),
        Cap::Endorse => ("Endorse", None),
    }
}

fn reject_symlinks(root: &Path, full: &Path) -> Result<(), Trap> {
    let mut cur = root.to_path_buf();
    let Ok(rest) = full.strip_prefix(root) else {
        return Ok(());
    };
    for comp in rest.components() {
        cur.push(comp);
        if cur.exists() {
            let meta = fs::symlink_metadata(&cur).map_err(|e| Trap(e.to_string()))?;
            if meta.file_type().is_symlink() {
                return Err(Trap("symlink refused".into()));
            }
        }
    }
    Ok(())
}
