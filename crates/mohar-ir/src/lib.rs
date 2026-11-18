//! Canonical mid-level IR.
//!
//! The printer walks the typed tree in source order and writes one
//! deterministic line per node. Types and labels are on every binding.
//! `sha3_256` of those bytes is the artifact hash inside a seal. There are
//! no timestamps, addresses or floating values, so two machines hashing the
//! same source get the same digest.

use std::fmt::Write as _;

use mohar_syntax::{BinOp, Block, Expr, ExprKind, ItemKind, Program, StmtKind, UnOp};
use mohar_types::{Checked, Ty};
use sha3::{Digest, Sha3_256};

pub struct Artifact {
    pub ir: String,
    pub ir_sha3_256: String,
    pub source_sha3_256: String,
}

pub fn emit(checked: &Checked, source: &str) -> Artifact {
    let ir = render(&checked.ast, &checked.types);
    Artifact {
        ir_sha3_256: hex::encode(Sha3_256::digest(ir.as_bytes())),
        source_sha3_256: hex::encode(Sha3_256::digest(source.as_bytes())),
        ir,
    }
}

pub fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

fn render(program: &Program, types: &std::collections::HashMap<u32, Ty>) -> String {
    let mut out = String::from("mohar-ir 0.1.0\n");
    for item in &program.items {
        match &item.kind {
            ItemKind::Fn(f) => {
                let _ = writeln!(out, "fn {} -> {}", f.name, ty_of(types, f.body.id));
                render_block(&mut out, &f.body, types, 1);
            }
            ItemKind::Struct(s) => {
                let _ = writeln!(out, "struct {}", s.name);
            }
            ItemKind::Enum(e) => {
                let _ = writeln!(out, "enum {}", e.name);
            }
            ItemKind::Const(c) => {
                let _ = writeln!(out, "const {}", c.name);
            }
            ItemKind::Use(_) | ItemKind::Mod(_) => {}
        }
    }
    out
}

fn render_block(
    out: &mut String,
    block: &Block,
    types: &std::collections::HashMap<u32, Ty>,
    indent: usize,
) {
    for stmt in &block.stmts {
        pad(out, indent);
        match &stmt.kind {
            StmtKind::Let { pat, value, .. } => {
                let _ = writeln!(out, "let {} = {}", pat_name(pat), render_expr(value, types));
            }
            StmtKind::Assign { name, value, .. } => {
                let _ = writeln!(out, "{name} = {}", render_expr(value, types));
            }
            StmtKind::Expr(e) => {
                let _ = writeln!(out, "{}", render_expr(e, types));
            }
            StmtKind::Return(v) => {
                let _ = writeln!(
                    out,
                    "return {}",
                    v.as_ref()
                        .map(|e| render_expr(e, types))
                        .unwrap_or_else(|| "()".into())
                );
            }
            StmtKind::While { cond, body } => {
                let _ = writeln!(out, "while {}", render_expr(cond, types));
                render_block(out, body, types, indent + 1);
            }
            StmtKind::For {
                name, iter, body, ..
            } => {
                let _ = writeln!(out, "for {name} in {}", render_expr(iter, types));
                render_block(out, body, types, indent + 1);
            }
        }
    }
    if let Some(tail) = &block.tail {
        pad(out, indent);
        let _ = writeln!(
            out,
            "yield {} : {}",
            render_expr(tail, types),
            ty_of(types, tail.id)
        );
    }
}

fn render_expr(expr: &Expr, types: &std::collections::HashMap<u32, Ty>) -> String {
    let body = render_expr_body(expr, types);
    format!("{body} : {}", ty_of(types, expr.id))
}

fn render_expr_body(expr: &Expr, types: &std::collections::HashMap<u32, Ty>) -> String {
    match &expr.kind {
        ExprKind::Path(p) => p
            .segments
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join("::"),
        ExprKind::Int { value, .. } => value.to_string(),
        ExprKind::String(s) => format!("{s:?}"),
        ExprKind::Bytes(b) => format!("b[{}]", b.len()),
        ExprKind::Bool(b) => b.to_string(),
        ExprKind::Unit => "()".into(),
        ExprKind::Call { callee, args } => {
            let args: Vec<_> = args.iter().map(|a| render_expr(a, types)).collect();
            format!("{}({})", render_expr_body(callee, types), args.join(", "))
        }
        ExprKind::Method {
            receiver,
            name,
            args,
            ..
        } => {
            let args: Vec<_> = args.iter().map(|a| render_expr(a, types)).collect();
            format!(
                "{}.{}({})",
                render_expr_body(receiver, types),
                name,
                args.join(", ")
            )
        }
        ExprKind::Binary { op, lhs, rhs } => {
            format!(
                "({} {} {})",
                render_expr_body(lhs, types),
                op.as_str(),
                render_expr_body(rhs, types)
            )
        }
        ExprKind::Unary { op, expr } => {
            let sym = match op {
                UnOp::Neg => "-",
                UnOp::Not => "!",
            };
            format!("{sym}{}", render_expr_body(expr, types))
        }
        ExprKind::Field { base, name, .. } => format!("{}.{}", render_expr_body(base, types), name),
        ExprKind::Index { base, index } => {
            format!(
                "{}[{}]",
                render_expr_body(base, types),
                render_expr_body(index, types)
            )
        }
        ExprKind::Tuple(xs) => {
            let xs: Vec<_> = xs.iter().map(|e| render_expr_body(e, types)).collect();
            format!("({})", xs.join(", "))
        }
        ExprKind::Array(xs) => {
            let xs: Vec<_> = xs.iter().map(|e| render_expr_body(e, types)).collect();
            format!("[{}]", xs.join(", "))
        }
        ExprKind::If { cond, .. } => format!("if {}", render_expr_body(cond, types)),
        ExprKind::Block(_) => "{...}".into(),
        ExprKind::Struct { path, .. } => format!(
            "{} {{...}}",
            path.segments
                .last()
                .map(|s| s.name.as_str())
                .unwrap_or("struct")
        ),
        _ => "_".into(),
    }
}

fn pat_name(pat: &mohar_syntax::Pattern) -> String {
    match &pat.kind {
        mohar_syntax::PatKind::Binding { name, .. } => name.clone(),
        mohar_syntax::PatKind::Wild => "_".into(),
        mohar_syntax::PatKind::Tuple(ps) => {
            let ps: Vec<_> = ps.iter().map(pat_name).collect();
            format!("({})", ps.join(", "))
        }
        _ => "pat".into(),
    }
}

fn ty_of(types: &std::collections::HashMap<u32, Ty>, id: u32) -> String {
    types.get(&id).map(Ty::render).unwrap_or_else(|| "_".into())
}

fn pad(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

// Keep BinOp's Display path referenced for the match above.
#[allow(dead_code)]
fn _op(op: BinOp) -> &'static str {
    op.as_str()
}
