//! Human authority reports.

use mohar_types::{AuthorityEntry, Checked, Grant};

pub fn review_text(checked: &Checked) -> String {
    let mut lines = Vec::new();
    lines.push(format!("profile:    {}", checked.profile.as_str()));
    let caps = describe(&checked.authority);
    if caps.is_empty() {
        lines.push("authority:  none".into());
    } else if checked.authority.len() == 1 && checked.authority[0].cap == "Console" {
        lines.push("authority:  Console (write)".into());
    } else {
        lines.push("authority:".into());
        for line in &caps {
            lines.push(format!("  {line}"));
        }
    }
    let files = file_line(&checked.authority);
    let network = net_line(&checked.authority);
    lines.push(format!("files:      {files}"));
    lines.push(format!("network:    {network}"));
    if checked.crypto.is_empty() {
        lines.push("crypto:     none".into());
    } else {
        let algs: Vec<_> = checked
            .crypto
            .iter()
            .map(|c| c.algorithm.as_str())
            .collect();
        lines.push(format!("crypto:     {}", algs.join(", ")));
    }
    let declass: Vec<_> = checked
        .flows
        .iter()
        .filter(|f| matches!(f.kind, mohar_types::FlowNoteKind::Declassify))
        .map(|f| f.name.as_str())
        .collect();
    let endorse: Vec<_> = checked
        .flows
        .iter()
        .filter(|f| matches!(f.kind, mohar_types::FlowNoteKind::Endorse))
        .map(|f| f.name.as_str())
        .collect();
    if declass.is_empty() && endorse.is_empty() {
        lines.push("flows:      no declassify, no endorse".into());
    } else {
        lines.push(format!(
            "flows:      declassify [{}], endorse [{}]",
            declass.join(", "),
            endorse.join(", ")
        ));
    }
    lines.push(format!(
        "verdict:    {}",
        verdict(&checked.authority, &checked.crypto)
    ));
    lines.push(String::new());
    lines.join("\n")
}

pub fn review_against(checked: &Checked, grant: &Grant) -> String {
    let mut lines = vec!["grant check".to_string()];
    let mut ok = true;
    if checked.authority.is_empty() {
        lines.push("  (program asks for nothing)".into());
    }
    for entry in &checked.authority {
        let scope = entry.scope.as_deref();
        let label = match &entry.scope {
            Some(s) => format!("{} {s}", entry.cap),
            None => entry.cap.clone(),
        };
        if grant.covers_cap(&entry.cap, scope) {
            lines.push(format!("  {label:<22} granted"));
        } else {
            ok = false;
            lines.push(format!("  {label:<22} NOT GRANTED"));
        }
    }
    if ok {
        lines.push("verdict: seal is within the grant".into());
    } else {
        lines.push("verdict: seal exceeds grant".into());
    }
    lines.push(String::new());
    lines.join("\n")
}

fn describe(entries: &[AuthorityEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| match &e.scope {
            Some(s) => format!("{}<{s}> ({})", e.cap, e.ops.join(", ")),
            None => format!("{} ({})", e.cap, e.ops.join(", ")),
        })
        .collect()
}

fn file_line(entries: &[AuthorityEntry]) -> String {
    let mut parts = Vec::new();
    for e in entries {
        if e.cap == "FsRead" || e.cap == "FsWrite" {
            let scope = e.scope.as_deref().unwrap_or("");
            parts.push(format!("{} {scope}", e.cap));
        }
    }
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join(", ")
    }
}

fn net_line(entries: &[AuthorityEntry]) -> String {
    let hosts: Vec<_> = entries
        .iter()
        .filter(|e| e.cap == "Net")
        .filter_map(|e| e.scope.clone())
        .collect();
    if hosts.is_empty() {
        "none".into()
    } else {
        hosts.join(", ")
    }
}

fn verdict(entries: &[AuthorityEntry], crypto: &[mohar_types::CryptoUse]) -> String {
    let only_console = entries.len() == 1 && entries[0].cap == "Console" && crypto.is_empty();
    if only_console {
        return "nothing beyond printing to the terminal".into();
    }
    if entries.is_empty() && crypto.is_empty() {
        return "no authority and no cryptography".into();
    }
    let mut bits = Vec::new();
    if entries
        .iter()
        .any(|e| e.cap == "FsRead" || e.cap == "FsWrite")
    {
        bits.push("touches files");
    }
    if entries.iter().any(|e| e.cap == "Net") {
        bits.push("talks to the network");
    }
    if entries.iter().any(|e| e.cap == "Tool") {
        bits.push("calls a host tool");
    }
    if entries.iter().any(|e| e.cap == "Model") {
        bits.push("asks a model");
    }
    if !crypto.is_empty() {
        bits.push("uses cryptography");
    }
    if bits.is_empty() {
        "limited authority".into()
    } else {
        bits.join("; ")
    }
}
