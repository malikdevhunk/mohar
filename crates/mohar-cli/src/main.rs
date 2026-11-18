//! `mohar` — check, run, build, seal, review, cbom.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use mohar_cli::{
    audit_notice, build_artifact, developer_grant, diagnostics, format_source, load_pipeline,
    review_against, review_text, run_with, seal_program, verify_seal,
};
use mohar_seal::{
    PublicKeyFile, cbom_json, generate_keypair, load_grant, load_trust, read_secret_key,
    write_keypair,
};
use mohar_std::version::CRATES;

#[derive(Parser)]
#[command(
    name = "mohar",
    version,
    about = "Mohar — secrets, authority and untrusted input are types."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Type-check a program.
    Check {
        file: PathBuf,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Fail if any warning is emitted.
        #[arg(long)]
        deny_warnings: bool,
    },
    /// Run a .mo program, or a sealed .mohar with --require-seal.
    Run {
        file: PathBuf,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long)]
        require_seal: bool,
        #[arg(long)]
        trust: Option<PathBuf>,
        #[arg(long)]
        trace: bool,
    },
    /// Write the canonical IR (.mhr) for a program.
    Build {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Sign an IR (or a .mo, which is built first) into a .mohar seal.
    Seal {
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Print the authority report, or diff a seal against a grant.
    Review {
        file: PathBuf,
        #[arg(long)]
        against: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Emit a CycloneDX cryptographic bill of materials.
    Cbom {
        file: PathBuf,
        #[arg(long, default_value = "cyclonedx")]
        format: String,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Reprint a program from its syntax tree.
    Fmt {
        file: PathBuf,
        #[arg(long)]
        write: bool,
    },
    /// Generate an ML-DSA-65 seal key (seed file plus a .pub sibling).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Read expressions, check them, and print the result. Experimental.
    Repl,
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Check {
            file,
            grant,
            config,
            deny_warnings,
        } => {
            let pipeline = match load_pipeline(&file, grant.as_deref(), config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let text = diagnostics(&pipeline);
            if !text.is_empty() {
                eprint!("{text}");
            }
            if !pipeline.checked.ok() {
                return ExitCode::from(1);
            }
            if deny_warnings && pipeline.checked.diagnostics.iter().any(|d| !d.is_error()) {
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Cmd::Run {
            file,
            grant,
            config,
            root,
            require_seal,
            trust,
            trace,
        } => {
            if require_seal {
                return run_sealed(&file, grant.as_deref(), trust.as_deref(), &root, trace);
            }
            let pipeline = match load_pipeline(&file, grant.as_deref(), config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            if !pipeline.checked.ok() {
                eprint!("{}", diagnostics(&pipeline));
                return ExitCode::from(1);
            }
            let grant = if let Some(path) = &grant {
                match load_grant(path) {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                }
            } else {
                developer_grant(pipeline.config.fuel, pipeline.config.memory_mib)
            };
            notice_if_crypto(&pipeline.checked);
            match run_with(&pipeline, grant, root) {
                Ok(host) => {
                    print!("{}", host.stdout);
                    if trace {
                        for line in &host.trace {
                            eprintln!("trace: {line}");
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("runtime error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Cmd::Build {
            file,
            output,
            config,
        } => {
            let pipeline = match load_pipeline(&file, None, config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            if !pipeline.checked.ok() {
                eprint!("{}", diagnostics(&pipeline));
                return ExitCode::from(1);
            }
            let artifact = build_artifact(&pipeline);
            let out = output.unwrap_or_else(|| file.with_extension("mhr"));
            if let Err(e) = fs::write(&out, &artifact.ir) {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
            println!("{}", artifact.ir_sha3_256);
            ExitCode::SUCCESS
        }
        Cmd::Seal {
            file,
            key,
            output,
            config,
        } => {
            let pipeline = match load_pipeline(&file, None, config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            if !pipeline.checked.ok() {
                eprint!("{}", diagnostics(&pipeline));
                return ExitCode::from(1);
            }
            let seed = match read_secret_key(&key) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let pub_path = {
                let mut p = key.into_os_string();
                p.push(".pub");
                PathBuf::from(p)
            };
            let public = match mohar_seal::read_public_key(&pub_path) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("reading {}: {e}", pub_path.display());
                    return ExitCode::from(2);
                }
            };
            eprintln!("{AUDIT}", AUDIT = audit_notice());
            let artifact = build_artifact(&pipeline);
            let text = match seal_program(
                &pipeline.checked,
                &pipeline.source,
                &artifact,
                pipeline.config.fuel,
                pipeline.config.memory_mib,
                &seed,
                &public,
            ) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            let out = output.unwrap_or_else(|| file.with_extension("mohar"));
            if let Err(e) = fs::write(&out, text) {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
            println!("sealed {}", out.display());
            ExitCode::SUCCESS
        }
        Cmd::Review {
            file,
            against,
            config,
        } => {
            if file.extension().and_then(|s| s.to_str()) == Some("mohar") {
                let text = match fs::read_to_string(&file) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                };
                // Review a seal without trusting a key: parse the JSON authority.
                let value: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(1);
                    }
                };
                println!(
                    "{}",
                    value.get("authority").unwrap_or(&serde_json::Value::Null)
                );
                if let Some(grant_path) = against {
                    let grant = match load_grant(&grant_path) {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    };
                    // Re-check the embedded source so the diff uses the same rules.
                    let source = value.get("source").and_then(|s| s.as_str()).unwrap_or("");
                    let tmp = std::env::temp_dir().join("mohar-review.mo");
                    let _ = fs::write(&tmp, source);
                    let pipeline = match load_pipeline(&tmp, Some(&grant_path), config.as_deref()) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    };
                    print!("{}", review_against(&pipeline.checked, &grant));
                    let _ = grant;
                }
                return ExitCode::SUCCESS;
            }
            let pipeline = match load_pipeline(&file, against.as_deref(), config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            if !pipeline.checked.ok() {
                eprint!("{}", diagnostics(&pipeline));
                return ExitCode::from(1);
            }
            print!("{}", review_text(&pipeline.checked));
            if let Some(path) = against {
                let grant = match load_grant(&path) {
                    Ok(g) => g,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                };
                print!("{}", review_against(&pipeline.checked, &grant));
            }
            ExitCode::SUCCESS
        }
        Cmd::Cbom {
            file,
            format,
            config,
        } => {
            if format != "cyclonedx" {
                eprintln!("v0.1 writes CycloneDX JSON; got `{format}`");
                return ExitCode::from(2);
            }
            let pipeline = match load_pipeline(&file, None, config.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            if !pipeline.checked.ok() {
                eprint!("{}", diagnostics(&pipeline));
                return ExitCode::from(1);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&cbom_json(&pipeline.checked.crypto)).unwrap()
            );
            ExitCode::SUCCESS
        }
        Cmd::Fmt { file, write } => {
            let source = match fs::read_to_string(&file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let name = file
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("input.mo");
            match format_source(&source, name) {
                Ok(formatted) => {
                    if write {
                        if let Err(e) = fs::write(&file, formatted) {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    } else {
                        print!("{formatted}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprint!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        Cmd::Keygen { out } => {
            eprintln!("{}", audit_notice());
            let (seed, public) = match generate_keypair() {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            if let Err(e) = write_keypair(&out, &seed, &public) {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
            println!("wrote {} and {}.pub", out.display(), out.display());
            println!("key id {}", public.key_id);
            println!(
                "backend {}",
                CRATES
                    .iter()
                    .map(|(n, v)| format!("{n}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            ExitCode::SUCCESS
        }
        Cmd::Repl => repl(),
    }
}

fn run_sealed(
    file: &std::path::Path,
    grant: Option<&std::path::Path>,
    trust: Option<&std::path::Path>,
    root: &std::path::Path,
    trace: bool,
) -> ExitCode {
    let Some(trust_path) = trust else {
        eprintln!("--require-seal needs --trust <trusted-keys.toml>");
        return ExitCode::from(2);
    };
    let text = match fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let trust = match load_trust(trust_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let grant = if let Some(path) = grant {
        match load_grant(path) {
            Ok(g) => Some(g),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    let seal = match verify_seal(&text, &trust.keys, grant.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("seal rejected: {e}");
            return ExitCode::from(1);
        }
    };
    let tmp = std::env::temp_dir().join(format!("mohar-run-{}.mo", seal.artifact.ir_sha3_256));
    if let Err(e) = fs::write(&tmp, &seal.source) {
        eprintln!("{e}");
        return ExitCode::from(2);
    }
    let pipeline = match load_pipeline(
        &tmp,
        grant
            .as_ref()
            .map(|_| PathBuf::from(""))
            .as_deref()
            .filter(|_| false),
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    // Recompile and demand the IR hash match the seal.
    let artifact = build_artifact(&pipeline);
    if artifact.ir_sha3_256 != seal.artifact.ir_sha3_256 {
        eprintln!("seal rejected: recompiled IR hash does not match the seal");
        return ExitCode::from(1);
    }
    if !pipeline.checked.ok() {
        eprint!("{}", diagnostics(&pipeline));
        return ExitCode::from(1);
    }
    let grant = grant.unwrap_or_else(|| developer_grant(seal.limits.fuel, seal.limits.memory_mib));
    eprintln!("{}", audit_notice());
    match run_with(&pipeline, grant, root.to_path_buf()) {
        Ok(host) => {
            print!("{}", host.stdout);
            if trace {
                for line in &host.trace {
                    eprintln!("trace: {line}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("runtime error: {e}");
            ExitCode::from(1)
        }
    }
}

fn notice_if_crypto(checked: &mohar_types::Checked) {
    if !checked.crypto.is_empty() {
        eprintln!("{}", audit_notice());
    }
}

fn repl() -> ExitCode {
    use std::io::{BufRead, Write};
    eprintln!("mohar repl. Empty line runs the buffer. :quit leaves.");
    let stdin = std::io::stdin();
    let mut buf = String::new();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line == ":quit" {
            break;
        }
        if line.is_empty() {
            let wrapped = format!("fn main(caps: Caps) {{\n{buf}\n}}\n");
            let file = mohar_diag::SourceFile::new("repl.mo", wrapped.clone());
            let checked = mohar_types::check_source(&file, &mohar_types::CheckOptions::default());
            if !checked.ok() {
                eprint!("{}", mohar_diag::render_all(&file, &checked.diagnostics));
            } else {
                let pipeline = mohar_cli::Pipeline {
                    config: mohar_seal::Config::default(),
                    source: wrapped,
                    file,
                    checked,
                };
                match run_with(
                    &pipeline,
                    developer_grant(1_000_000, 64),
                    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                ) {
                    Ok(host) => print!("{}", host.stdout),
                    Err(e) => eprintln!("runtime error: {e}"),
                }
            }
            buf.clear();
            continue;
        }
        buf.push_str(&line);
        buf.push('\n');
        let _ = std::io::stdout().flush();
    }
    ExitCode::SUCCESS
}

// Keep the type visible for rustdoc links from the binary.
#[allow(dead_code)]
fn _pub(k: PublicKeyFile) -> String {
    k.key_id
}
