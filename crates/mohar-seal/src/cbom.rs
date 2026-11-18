//! CycloneDX-shaped cryptographic bill of materials.
//!
//! The components come from what the type checker resolved, not from a
//! scanner guessing at byte patterns.

use mohar_types::CryptoUse;
use serde_json::{Value, json};

pub fn cbom_json(uses: &[CryptoUse]) -> Value {
    let mut components = Vec::new();
    for use_ in uses {
        let (line, col) = (0, 0);
        let _ = (line, col);
        components.push(json!({
            "type": "cryptographic-asset",
            "name": use_.algorithm,
            "assetType": "algorithm",
            "quantumSafe": use_.quantum_safe,
            "evidence": format!("{}:{} {}", use_.span.start, use_.span.end, use_.site),
        }));
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": { "type": "application", "name": "mohar-program" }
        },
        "components": components
    })
}
