//! Pretty-printer.
//!
//! `mohar fmt` reprints the AST. The printer is deterministic: one style,
//! trailing commas in multi-line constructs, and no comments (v0.1 does not
//! attach comments to the tree, so formatting drops them).

use crate::ast::*;

pub fn format_program(program: &Program) -> String {
    let mut out = String::new();
    for (i, item) in program.items.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        write_item(&mut out, item);
        out.push('\n');
    }
    out
}

fn write_item(out: &mut String, item: &Item) {
    for attr in &item.attrs {
        out.push_str("#[");
        out.push_str(&attr.name);
        if let Some(arg) = &attr.arg {
            out.push('(');
            out.push_str(arg);
            out.push(')');
        }
        out.push_str("]\n");
    }
    match &item.kind {
        ItemKind::Fn(f) => {
            out.push_str("fn ");
            out.push_str(&f.name);
            out.push('(');
            for (i, p) in f.params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&p.name);
                out.push_str(": ");
                write_type(out, &p.ty);
            }
            out.push(')');
            if let Some(ret) = &f.ret {
                out.push_str(" -> ");
                write_type(out, ret);
            }
            out.push(' ');
            write_block(out, &f.body, 0);
        }
        ItemKind::Struct(s) => {
            out.push_str("struct ");
            out.push_str(&s.name);
            out.push_str(" {\n");
            for f in &s.fields {
                out.push_str("    ");
                out.push_str(&f.name);
                out.push_str(": ");
                write_type(out, &f.ty);
                out.push_str(",\n");
            }
            out.push('}');
        }
        ItemKind::Enum(e) => {
            out.push_str("enum ");
            out.push_str(&e.name);
            out.push_str(" {\n");
            for v in &e.variants {
                out.push_str("    ");
                out.push_str(&v.name);
                if !v.fields.is_empty() {
                    out.push('(');
                    for (i, t) in v.fields.iter().enumerate() {
                        if i > 0 {
                            out.push_str(", ");
                        }
                        write_type(out, t);
                    }
                    out.push(')');
                }
                out.push_str(",\n");
            }
            out.push('}');
        }
        ItemKind::Use(u) => {
            out.push_str("use ");
            out.push_str(&u.module.join("."));
            if u.names.len() == 1 {
                out.push_str("::");
                out.push_str(&u.names[0]);
            } else if u.names.len() > 1 {
                out.push_str("::{");
                out.push_str(&u.names.join(", "));
                out.push('}');
            }
            out.push(';');
        }
        ItemKind::Const(c) => {
            out.push_str("const ");
            out.push_str(&c.name);
            out.push_str(": ");
            write_type(out, &c.ty);
            out.push_str(" = ");
            write_expr(out, &c.value, 0);
            out.push(';');
        }
        ItemKind::Mod(m) => {
            out.push_str("mod ");
            out.push_str(&m.name);
            out.push(';');
        }
    }
}

fn write_type(out: &mut String, ty: &TypeExpr) {
    for label in &ty.labels {
        out.push_str(match label.word {
            LabelWord::Secret => "secret ",
            LabelWord::Untrusted => "untrusted ",
            LabelWord::Public => "public ",
            LabelWord::Trusted => "trusted ",
        });
    }
    match &ty.kind {
        TypeKind::Unit => out.push_str("()"),
        TypeKind::Named(path) => write_type_path(out, path),
        TypeKind::Array { elem, len } => {
            out.push('[');
            write_type(out, elem);
            out.push_str("; ");
            match len {
                ArrayLen::Int(n) => out.push_str(&n.to_string()),
                ArrayLen::Name(n, _) => out.push_str(n),
            }
            out.push(']');
        }
        TypeKind::Tuple(ts) => {
            out.push('(');
            for (i, t) in ts.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_type(out, t);
            }
            out.push(')');
        }
        TypeKind::Error => out.push_str("/* error */"),
    }
}

fn write_type_path(out: &mut String, path: &Path) {
    for (i, seg) in path.segments.iter().enumerate() {
        if i > 0 {
            out.push_str("::");
        }
        out.push_str(&seg.name);
        if !seg.args.is_empty() {
            out.push('<');
            write_generic_args(out, &seg.args);
            out.push('>');
        }
    }
}

fn write_generic_args(out: &mut String, args: &[GenericArg]) {
    for (j, arg) in args.iter().enumerate() {
        if j > 0 {
            out.push_str(", ");
        }
        match arg {
            GenericArg::Type(t) => write_type(out, t),
            GenericArg::Int(n, _) => out.push_str(&n.to_string()),
            GenericArg::Str(s, _) => {
                out.push('"');
                push_escaped(out, s);
                out.push('"');
            }
        }
    }
}

fn write_path(out: &mut String, path: &Path) {
    for (i, seg) in path.segments.iter().enumerate() {
        if i > 0 {
            out.push_str("::");
        }
        out.push_str(&seg.name);
        if !seg.args.is_empty() {
            out.push_str("::<");
            write_generic_args(out, &seg.args);
            out.push('>');
        }
    }
}

fn write_block(out: &mut String, block: &Block, indent: usize) {
    out.push_str("{\n");
    let inner = indent + 4;
    for stmt in &block.stmts {
        pad(out, inner);
        write_stmt(out, stmt, inner);
        out.push('\n');
    }
    if let Some(tail) = &block.tail {
        pad(out, inner);
        write_expr(out, tail, inner);
        out.push('\n');
    }
    pad(out, indent);
    out.push('}');
}

fn write_stmt(out: &mut String, stmt: &Stmt, indent: usize) {
    match &stmt.kind {
        StmtKind::Let {
            mutable,
            pat,
            ty,
            value,
        } => {
            out.push_str("let ");
            if *mutable {
                out.push_str("mut ");
            }
            write_pat(out, pat);
            if let Some(ty) = ty {
                out.push_str(": ");
                write_type(out, ty);
            }
            out.push_str(" = ");
            write_expr(out, value, indent);
            out.push(';');
        }
        StmtKind::Assign { name, value, .. } => {
            out.push_str(name);
            out.push_str(" = ");
            write_expr(out, value, indent);
            out.push(';');
        }
        StmtKind::Expr(e) => {
            write_expr(out, e, indent);
            if !is_blocky(e) {
                out.push(';');
            }
        }
        StmtKind::Return(v) => {
            out.push_str("return");
            if let Some(v) = v {
                out.push(' ');
                write_expr(out, v, indent);
            }
            out.push(';');
        }
        StmtKind::While { cond, body } => {
            out.push_str("while ");
            write_expr(out, cond, indent);
            out.push(' ');
            write_block(out, body, indent);
        }
        StmtKind::For {
            name, iter, body, ..
        } => {
            out.push_str("for ");
            out.push_str(name);
            out.push_str(" in ");
            write_expr(out, iter, indent);
            out.push(' ');
            write_block(out, body, indent);
        }
    }
}

fn write_expr(out: &mut String, expr: &Expr, indent: usize) {
    match &expr.kind {
        ExprKind::Path(p) => write_path(out, p),
        ExprKind::Int { value, suffix } => {
            out.push_str(&value.to_string());
            if let Some(s) = suffix {
                out.push_str(s.as_str());
            }
        }
        ExprKind::String(s) => {
            out.push('"');
            push_escaped(out, s);
            out.push('"');
        }
        ExprKind::Bytes(b) => {
            out.push_str("b\"");
            for byte in b {
                if byte.is_ascii() && !matches!(byte, b'"' | b'\\') && *byte >= 0x20 {
                    out.push(*byte as char);
                } else {
                    out.push_str(&format!("\\x{byte:02x}"));
                }
            }
            out.push('"');
        }
        ExprKind::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        ExprKind::Unit => out.push_str("()"),
        ExprKind::Tuple(xs) => {
            out.push('(');
            for (i, e) in xs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr(out, e, indent);
            }
            out.push(')');
        }
        ExprKind::Array(xs) => {
            out.push('[');
            for (i, e) in xs.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr(out, e, indent);
            }
            out.push(']');
        }
        ExprKind::Repeat { value, len } => {
            out.push('[');
            write_expr(out, value, indent);
            out.push_str("; ");
            write_expr(out, len, indent);
            out.push(']');
        }
        ExprKind::Block(b) => write_block(out, b, indent),
        ExprKind::If {
            cond,
            then_branch,
            else_branch,
        } => {
            out.push_str("if ");
            write_expr(out, cond, indent);
            out.push(' ');
            write_block(out, then_branch, indent);
            if let Some(else_branch) = else_branch {
                out.push_str(" else ");
                write_expr(out, else_branch, indent);
            }
        }
        ExprKind::Match { scrutinee, arms } => {
            out.push_str("match ");
            write_expr(out, scrutinee, indent);
            out.push_str(" {\n");
            for arm in arms {
                pad(out, indent + 4);
                write_pat(out, &arm.pat);
                out.push_str(" => ");
                write_expr(out, &arm.body, indent + 4);
                out.push_str(",\n");
            }
            pad(out, indent);
            out.push('}');
        }
        ExprKind::Lambda { params, body } => {
            out.push('|');
            for (i, p) in params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&p.name);
                if let Some(ty) = &p.ty {
                    out.push_str(": ");
                    write_type(out, ty);
                }
            }
            out.push_str("| ");
            write_expr(out, body, indent);
        }
        ExprKind::Call { callee, args } => {
            write_expr(out, callee, indent);
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr(out, a, indent);
            }
            out.push(')');
        }
        ExprKind::Method {
            receiver,
            name,
            type_args,
            args,
            ..
        } => {
            write_expr(out, receiver, indent);
            out.push('.');
            out.push_str(name);
            if !type_args.is_empty() {
                out.push_str("::<");
                write_generic_args(out, type_args);
                out.push('>');
            }
            out.push('(');
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_expr(out, a, indent);
            }
            out.push(')');
        }
        ExprKind::Field { base, name, .. } => {
            write_expr(out, base, indent);
            out.push('.');
            out.push_str(name);
        }
        ExprKind::Index { base, index } => {
            write_expr(out, base, indent);
            out.push('[');
            write_expr(out, index, indent);
            out.push(']');
        }
        ExprKind::Try(e) => {
            write_expr(out, e, indent);
            out.push('?');
        }
        ExprKind::Unary { op, expr } => {
            out.push(match op {
                UnOp::Neg => '-',
                UnOp::Not => '!',
            });
            write_expr(out, expr, indent);
        }
        ExprKind::Binary { op, lhs, rhs } => {
            write_expr(out, lhs, indent);
            out.push(' ');
            out.push_str(op.as_str());
            out.push(' ');
            write_expr(out, rhs, indent);
        }
        ExprKind::Struct { path, fields } => {
            write_path(out, path);
            out.push_str(" { ");
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&f.name);
                out.push_str(": ");
                write_expr(out, &f.value, indent);
            }
            out.push_str(" }");
        }
        ExprKind::Error => out.push_str("/* error */"),
    }
}

fn write_pat(out: &mut String, pat: &Pattern) {
    match &pat.kind {
        PatKind::Wild => out.push('_'),
        PatKind::Binding { name, mutable } => {
            if *mutable {
                out.push_str("mut ");
            }
            out.push_str(name);
        }
        PatKind::LitInt(n) => out.push_str(&n.to_string()),
        PatKind::LitBool(b) => out.push_str(if *b { "true" } else { "false" }),
        PatKind::LitStr(s) => {
            out.push('"');
            push_escaped(out, s);
            out.push('"');
        }
        PatKind::Tuple(ps) => {
            out.push('(');
            for (i, p) in ps.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_pat(out, p);
            }
            out.push(')');
        }
        PatKind::Variant { path, args } => {
            write_path(out, path);
            if !args.is_empty() {
                out.push('(');
                for (i, p) in args.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    write_pat(out, p);
                }
                out.push(')');
            }
        }
        PatKind::Struct { path, fields } => {
            write_path(out, path);
            out.push_str(" { ");
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&f.name);
                out.push_str(": ");
                write_pat(out, &f.pat);
            }
            out.push_str(" }");
        }
    }
}

fn push_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
}

fn pad(out: &mut String, n: usize) {
    out.push_str(&" ".repeat(n));
}

fn is_blocky(expr: &Expr) -> bool {
    matches!(
        expr.kind,
        ExprKind::If { .. } | ExprKind::Match { .. } | ExprKind::Block(_)
    )
}
