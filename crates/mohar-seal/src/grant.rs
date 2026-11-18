//! `mohar.toml`, grant files and trust files.

use std::fs;
use std::path::Path;

use mohar_types::{CryptoPolicy, Grant, PolicyKind};
use serde::Deserialize;

use crate::keys::PublicKeyFile;
use crate::seal::SealError;

#[derive(Clone, Debug)]
pub struct Config {
    pub policy: CryptoPolicy,
    pub fuel: u64,
    pub memory_mib: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policy: CryptoPolicy::default(),
            fuel: 5_000_000,
            memory_mib: 64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrustFile {
    pub keys: Vec<PublicKeyFile>,
}

#[derive(Debug, Deserialize)]
struct TomlFile {
    crypto: Option<CryptoToml>,
    limits: Option<LimitsToml>,
    grant: Option<GrantToml>,
}

#[derive(Debug, Deserialize)]
struct CryptoToml {
    policy: Option<String>,
    allow_legacy_until: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LimitsToml {
    fuel: Option<u64>,
    memory_mib: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GrantToml {
    console: Option<bool>,
    fs_read: Option<Vec<String>>,
    fs_write: Option<Vec<String>>,
    net: Option<Vec<String>>,
    tools: Option<Vec<String>>,
    model: Option<bool>,
    rand: Option<bool>,
    clock: Option<bool>,
    declassify: Option<bool>,
    endorse: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TrustToml {
    keys: Option<Vec<TrustKey>>,
}

#[derive(Debug, Deserialize)]
struct TrustKey {
    key_id: Option<String>,
    public_key: String,
}

pub fn load_config(path: &Path) -> Result<Config, SealError> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?;
    let file: TomlFile = toml::from_str(&text).map_err(|e| SealError::Io(e.to_string()))?;
    let mut cfg = Config::default();
    if let Some(c) = file.crypto {
        if let Some(p) = c.policy {
            cfg.policy.kind = PolicyKind::parse(&p)
                .ok_or_else(|| SealError::Io(format!("unknown policy `{p}`")))?;
        }
        if let Some(until) = c.allow_legacy_until {
            cfg.policy.allow_legacy_until = until;
        }
    }
    if let Some(l) = file.limits {
        if let Some(f) = l.fuel {
            cfg.fuel = f;
        }
        if let Some(m) = l.memory_mib {
            cfg.memory_mib = m;
        }
    }
    Ok(cfg)
}

pub fn load_grant(path: &Path) -> Result<Grant, SealError> {
    let text = fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?;
    let file: TomlFile = toml::from_str(&text).map_err(|e| SealError::Io(e.to_string()))?;
    let g = file
        .grant
        .ok_or_else(|| SealError::Io("grant file has no [grant] table".into()))?;
    let mut grant = Grant {
        console: false,
        fs_read: Vec::new(),
        fs_write: Vec::new(),
        net: Vec::new(),
        tools: Vec::new(),
        model: false,
        rand: false,
        clock: false,
        declassify: false,
        endorse: false,
        fuel: 5_000_000,
        memory_mib: 64,
    };
    if let Some(v) = g.console {
        grant.console = v;
    }
    if let Some(v) = g.fs_read {
        grant.fs_read = v.into_iter().map(norm).collect();
    }
    if let Some(v) = g.fs_write {
        grant.fs_write = v.into_iter().map(norm).collect();
    }
    if let Some(v) = g.net {
        grant.net = v;
    }
    if let Some(v) = g.tools {
        grant.tools = v;
    }
    if let Some(v) = g.model {
        grant.model = v;
    }
    if let Some(v) = g.rand {
        grant.rand = v;
    }
    if let Some(v) = g.clock {
        grant.clock = v;
    }
    if let Some(v) = g.declassify {
        grant.declassify = v;
    }
    if let Some(v) = g.endorse {
        grant.endorse = v;
    }
    if let Some(l) = file.limits {
        if let Some(f) = l.fuel {
            grant.fuel = f;
        }
        if let Some(m) = l.memory_mib {
            grant.memory_mib = m;
        }
    }
    Ok(grant)
}

pub fn load_trust(path: &Path) -> Result<TrustFile, SealError> {
    let text = fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?;
    let file: TrustToml = toml::from_str(&text).map_err(|e| SealError::Io(e.to_string()))?;
    let mut keys = Vec::new();
    for k in file.keys.unwrap_or_default() {
        let public_key =
            hex::decode(k.public_key.trim()).map_err(|e| SealError::Key(e.to_string()))?;
        let key_id = k.key_id.unwrap_or_else(|| crate::keys::key_id(&public_key));
        keys.push(PublicKeyFile { key_id, public_key });
    }
    Ok(TrustFile { keys })
}

fn norm(s: String) -> String {
    s.trim_start_matches("./").trim_matches('/').to_string()
}
