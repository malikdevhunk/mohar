//! Build, sign and verify a seal document.

use mohar_ir::Artifact;
use mohar_std::version::{AUDIT_NOTICE, BACKEND_NAME, CRATES, STD_FINGERPRINT};
use mohar_types::{AuthorityEntry, Checked, Grant};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::keys::{self, PublicKeyFile};
use crate::report::review_against;
use crate::{COMPILER, FORMAT};

#[derive(Debug)]
pub enum SealError {
    Io(String),
    Key(String),
    Verify(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) | Self::Key(s) | Self::Verify(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SealError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Seal {
    pub format: String,
    pub ir: String,
    pub source: String,
    pub artifact: ArtifactInfo,
    pub profile: String,
    pub authority: Vec<AuthJson>,
    pub flows: FlowsJson,
    pub crypto: Vec<CryptoJson>,
    pub limits: LimitsJson,
    pub backend: BackendJson,
    #[serde(default)]
    pub signatures: Vec<SigJson>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub ir_sha3_256: String,
    pub source_sha3_256: String,
    pub std_sha3_256: String,
    pub compiler: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthJson {
    pub cap: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub ops: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowsJson {
    pub declassify: Vec<String>,
    pub endorse: Vec<String>,
    pub trusted_declassifiers_used: Vec<String>,
    pub trusted_endorsers_used: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoJson {
    pub algorithm: String,
    pub quantum_safe: bool,
    pub site: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LimitsJson {
    pub fuel: u64,
    pub memory_mib: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendJson {
    pub name: String,
    pub crates: Vec<String>,
    pub audit: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigJson {
    pub alg: String,
    pub key_id: String,
    pub sig: String,
}

pub fn seal_program(
    checked: &Checked,
    source: &str,
    artifact: &Artifact,
    fuel: u64,
    memory_mib: u64,
    seed: &[u8],
    public: &PublicKeyFile,
) -> Result<String, SealError> {
    let seal = unsigned(checked, source, artifact, fuel, memory_mib);
    let payload = canonical_without_sigs(&seal)?;
    let sig = keys::sign_bytes(seed, payload.as_bytes())?;
    let mut value = serde_json::to_value(&seal).map_err(|e| SealError::Io(e.to_string()))?;
    value["signatures"] = json!([{
        "alg": "ML-DSA-65",
        "key_id": public.key_id,
        "sig": hex::encode(sig),
    }]);
    serde_json::to_string_pretty(&value).map_err(|e| SealError::Io(e.to_string()))
}

pub fn verify_seal(
    text: &str,
    trusted: &[PublicKeyFile],
    grant: Option<&Grant>,
) -> Result<Seal, SealError> {
    let seal: Seal = serde_json::from_str(text).map_err(|e| SealError::Verify(e.to_string()))?;
    if seal.format != FORMAT {
        return Err(SealError::Verify(format!(
            "unknown seal format {}",
            seal.format
        )));
    }
    let payload = canonical_without_sigs(&seal)?;
    if seal.signatures.is_empty() {
        return Err(SealError::Verify("seal has no signature".into()));
    }
    let mut matched = false;
    for sig in &seal.signatures {
        if sig.alg != "ML-DSA-65" {
            return Err(SealError::Verify(format!(
                "unsupported signature algorithm {}",
                sig.alg
            )));
        }
        let Some(key) = trusted.iter().find(|k| k.key_id == sig.key_id) else {
            continue;
        };
        let bytes = hex::decode(&sig.sig).map_err(|e| SealError::Verify(e.to_string()))?;
        if !keys::verify_bytes(&key.public_key, payload.as_bytes(), &bytes) {
            return Err(SealError::Verify("signature does not verify".into()));
        }
        matched = true;
    }
    if !matched {
        return Err(SealError::Verify("no trusted key matched the seal".into()));
    }
    let recomputed = mohar_ir::sha3_hex(seal.ir.as_bytes());
    if recomputed != seal.artifact.ir_sha3_256 {
        return Err(SealError::Verify(
            "IR hash does not match the embedded IR".into(),
        ));
    }
    let source_hash = mohar_ir::sha3_hex(seal.source.as_bytes());
    if source_hash != seal.artifact.source_sha3_256 {
        return Err(SealError::Verify("source hash does not match".into()));
    }
    if let Some(grant) = grant {
        let checked_authority = seal.authority.iter().map(|a| AuthorityEntry {
            cap: a.cap.clone(),
            scope: a.scope.clone(),
            ops: a.ops.clone(),
            span: mohar_diag::Span::DUMMY,
        });
        for entry in checked_authority {
            if !grant.covers_cap(&entry.cap, entry.scope.as_deref()) {
                return Err(SealError::Verify(format!(
                    "authority {} exceeds the grant",
                    entry.cap
                )));
            }
        }
        let _ = review_against;
    }
    Ok(seal)
}

fn unsigned(
    checked: &Checked,
    source: &str,
    artifact: &Artifact,
    fuel: u64,
    memory_mib: u64,
) -> Seal {
    let mut declassify = Vec::new();
    let mut endorse = Vec::new();
    let mut decl_used = Vec::new();
    let mut end_used = Vec::new();
    for flow in &checked.flows {
        match flow.kind {
            mohar_types::FlowNoteKind::Declassify => declassify.push(flow.name.clone()),
            mohar_types::FlowNoteKind::Endorse => endorse.push(flow.name.clone()),
            mohar_types::FlowNoteKind::TrustedDeclassifier => decl_used.push(flow.name.clone()),
            mohar_types::FlowNoteKind::TrustedEndorser => end_used.push(flow.name.clone()),
        }
    }
    decl_used.sort();
    decl_used.dedup();
    end_used.sort();
    end_used.dedup();
    Seal {
        format: FORMAT.into(),
        ir: artifact.ir.clone(),
        source: source.to_string(),
        artifact: ArtifactInfo {
            ir_sha3_256: artifact.ir_sha3_256.clone(),
            source_sha3_256: artifact.source_sha3_256.clone(),
            std_sha3_256: mohar_ir::sha3_hex(STD_FINGERPRINT.as_bytes()),
            compiler: COMPILER.into(),
        },
        profile: checked.profile.as_str().into(),
        authority: checked
            .authority
            .iter()
            .map(|a| AuthJson {
                cap: a.cap.clone(),
                scope: a.scope.clone(),
                ops: a.ops.clone(),
            })
            .collect(),
        flows: FlowsJson {
            declassify,
            endorse,
            trusted_declassifiers_used: decl_used,
            trusted_endorsers_used: end_used,
        },
        crypto: checked
            .crypto
            .iter()
            .map(|c| CryptoJson {
                algorithm: c.algorithm.clone(),
                quantum_safe: c.quantum_safe,
                site: c.site.clone(),
            })
            .collect(),
        limits: LimitsJson { fuel, memory_mib },
        backend: BackendJson {
            name: BACKEND_NAME.into(),
            crates: CRATES.iter().map(|(n, v)| format!("{n} {v}")).collect(),
            audit: AUDIT_NOTICE.into(),
        },
        signatures: Vec::new(),
    }
}

fn canonical_without_sigs(seal: &Seal) -> Result<String, SealError> {
    let mut value = serde_json::to_value(seal).map_err(|e| SealError::Io(e.to_string()))?;
    if let Value::Object(map) = &mut value {
        map.remove("signatures");
    }
    serde_jcs::to_string(&value).map_err(|e| SealError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;
    use mohar_diag::SourceFile;
    use mohar_ir::emit;
    use mohar_types::{CheckOptions, check_source};

    #[test]
    fn sign_and_reject_a_tampered_byte() {
        let src = "fn main(caps: Caps) {\n    let out = caps.console();\n    out.println(\"namaste, duniya\");\n}\n";
        let file = SourceFile::new("hello.mo", src);
        let checked = check_source(&file, &CheckOptions::default());
        assert!(
            checked.ok(),
            "{}",
            mohar_diag::render_all(&file, &checked.diagnostics)
        );
        let artifact = emit(&checked, src);
        let (seed, public) = generate_keypair().unwrap();
        let text = seal_program(&checked, src, &artifact, 1000, 64, &seed, &public).unwrap();
        let ok = verify_seal(&text, std::slice::from_ref(&public), None).unwrap();
        assert_eq!(ok.artifact.ir_sha3_256, artifact.ir_sha3_256);
        let mut tampered = text.clone();
        // Flip a character inside the IR string, which is covered by the signature.
        if let Some(idx) = tampered.find("namaste") {
            tampered.replace_range(idx..idx + 1, "N");
        }
        assert!(verify_seal(&tampered, &[public], None).is_err());
    }
}
