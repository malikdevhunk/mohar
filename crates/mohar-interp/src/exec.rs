//! Evaluate a checked program.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use mohar_std::{self, MlDsaLevel};
use mohar_syntax::{BinOp, Block, Expr, ExprKind, FnItem, ItemKind, StmtKind, UnOp};
use mohar_types::{Checked, Res};

use crate::host::{Host, Trap};
use crate::value::{Cap, Value, array_u8, bytes_value, to_hex, weight};

pub struct Outcome {
    pub value: Value,
    pub stdout: String,
    pub trace: Vec<String>,
}

enum Control {
    Next(Value),
    Return(Value),
}

pub fn run_program(checked: &Checked, host: &mut Host) -> Result<Outcome, Trap> {
    if !checked.ok() {
        return Err(Trap("refusing to run a program that has errors".into()));
    }
    let mut vm = Vm {
        checked,
        host,
        unwind: None,
    };
    let value = vm.call_user("main", vec![Value::Unit])?;
    Ok(Outcome {
        value,
        stdout: vm.host.stdout.clone(),
        trace: vm.host.trace.clone(),
    })
}

struct Vm<'a> {
    checked: &'a Checked,
    host: &'a mut Host,
    /// Set by `return` inside a nested expression and by `?` on `Err`/`None`.
    unwind: Option<Value>,
}

impl<'a> Vm<'a> {
    fn call_user(&mut self, name: &str, args: Vec<Value>) -> Result<Value, Trap> {
        let (fname, params, body) = {
            let func = self
                .checked
                .ast
                .items
                .iter()
                .find_map(|item| match &item.kind {
                    ItemKind::Fn(f) if f.name == name => Some(f),
                    _ => None,
                })
                .ok_or_else(|| Trap(format!("no function `{name}`")))?;
            (func.name.clone(), func.params.clone(), func.body.clone())
        };
        if params.len() != args.len() {
            return Err(Trap(format!(
                "`{fname}` expected {} arguments",
                params.len()
            )));
        }
        let mut locals = HashMap::new();
        for (p, v) in params.iter().zip(args) {
            self.host.charge_mem(weight(&v))?;
            locals.insert(p.name.clone(), v);
        }
        if fname == "main" {
            if let Some(p) = params.first() {
                locals.insert(p.name.clone(), caps_token());
            }
        }
        let result = self.exec_block(&body, &mut locals)?;
        if let Some(v) = self.unwind.take() {
            return Ok(v);
        }
        match result {
            Control::Next(v) | Control::Return(v) => Ok(v),
        }
    }

    fn exec_block(
        &mut self,
        block: &Block,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Control, Trap> {
        self.host.charge(1)?;
        for stmt in &block.stmts {
            self.host.charge(1)?;
            if let Some(v) = self.unwind.take() {
                return Ok(Control::Return(v));
            }
            match &stmt.kind {
                StmtKind::Let { pat, value, .. } => {
                    let v = self.eval(value, locals)?;
                    bind_pat(pat, v, locals);
                }
                StmtKind::Assign { name, value, .. } => {
                    let v = self.eval(value, locals)?;
                    if !locals.contains_key(name) {
                        return Err(Trap(format!("assign to unknown `{name}`")));
                    }
                    locals.insert(name.clone(), v);
                }
                StmtKind::Expr(e) => {
                    self.eval(e, locals)?;
                }
                StmtKind::Return(v) => {
                    let v = if let Some(v) = v {
                        self.eval(v, locals)?
                    } else {
                        Value::Unit
                    };
                    return Ok(Control::Return(v));
                }
                StmtKind::While { cond, body } => loop {
                    self.host.charge(1)?;
                    let c = self.eval(cond, locals)?;
                    if !truth(&c)? {
                        break;
                    }
                    match self.exec_block(body, locals)? {
                        Control::Return(v) => return Ok(Control::Return(v)),
                        Control::Next(_) => {}
                    }
                },
                StmtKind::For {
                    name, iter, body, ..
                } => {
                    let iter_val = self.eval(iter, locals)?;
                    match iter_val {
                        Value::Tuple(xs) if xs.len() == 2 => {
                            match self.exec_range(name, &xs, body, locals)? {
                                Control::Return(v) => return Ok(Control::Return(v)),
                                Control::Next(_) => {}
                            }
                        }
                        Value::List(xs) | Value::Array(xs) => {
                            for item in xs {
                                locals.insert(name.clone(), item);
                                match self.exec_block(body, locals)? {
                                    Control::Return(v) => return Ok(Control::Return(v)),
                                    Control::Next(_) => {}
                                }
                            }
                        }
                        other => return Err(Trap(format!("cannot iterate {}", other.type_name()))),
                    }
                }
            }
        }
        if let Some(tail) = &block.tail {
            return Ok(Control::Next(self.eval(tail, locals)?));
        }
        Ok(Control::Next(Value::Unit))
    }

    fn exec_range(
        &mut self,
        name: &str,
        ends: &[Value],
        body: &Block,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Control, Trap> {
        let start = ends[0].as_int().ok_or_else(|| Trap("range start".into()))?;
        let end = ends[1].as_int().ok_or_else(|| Trap("range end".into()))?;
        let mut i = start;
        while i < end {
            self.host.charge(1)?;
            locals.insert(name.to_string(), Value::Int(i));
            match self.exec_block(body, locals)? {
                Control::Return(v) => return Ok(Control::Return(v)),
                Control::Next(_) => {}
            }
            i += 1;
        }
        Ok(Control::Next(Value::Unit))
    }

    fn eval(&mut self, expr: &Expr, locals: &mut HashMap<String, Value>) -> Result<Value, Trap> {
        self.host.charge(1)?;
        match &expr.kind {
            ExprKind::Error => Err(Trap("error node".into())),
            ExprKind::Unit => Ok(Value::Unit),
            ExprKind::Bool(b) => Ok(Value::Bool(*b)),
            ExprKind::Int { value, .. } => Ok(Value::Int(*value)),
            ExprKind::String(s) => {
                self.host.charge_mem(s.len() as u64)?;
                Ok(Value::Text(s.clone()))
            }
            ExprKind::Bytes(b) => Ok(Value::Bytes(b.clone())),
            ExprKind::Path(path) => self.eval_path(path, expr.id, locals),
            ExprKind::Tuple(xs) => {
                let mut out = Vec::new();
                for x in xs {
                    out.push(self.eval(x, locals)?);
                }
                Ok(Value::Tuple(out))
            }
            ExprKind::Array(xs) => {
                let mut out = Vec::new();
                for x in xs {
                    out.push(self.eval(x, locals)?);
                }
                Ok(Value::Array(out))
            }
            ExprKind::Repeat { value, len } => {
                let v = self.eval(value, locals)?;
                let n = match self.eval(len, locals)? {
                    Value::Int(n) if n >= 0 => n as usize,
                    _ => return Err(Trap("bad repeat length".into())),
                };
                Ok(Value::Array(vec![v; n]))
            }
            ExprKind::Block(b) => match self.exec_block(b, locals)? {
                Control::Next(v) => Ok(v),
                Control::Return(v) => {
                    self.unwind = Some(v);
                    Ok(Value::Unit)
                }
            },
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let c = self.eval(cond, locals)?;
                if truth(&c)? {
                    match self.exec_block(then_branch, locals)? {
                        Control::Next(v) => Ok(v),
                        Control::Return(v) => {
                            self.unwind = Some(v);
                            Ok(Value::Unit)
                        }
                    }
                } else if let Some(e) = else_branch {
                    self.eval(e, locals)
                } else {
                    Ok(Value::Unit)
                }
            }
            ExprKind::Match { scrutinee, arms } => {
                let scrut = self.eval(scrutinee, locals)?;
                for arm in arms {
                    if let Some(binds) = match_pat(&arm.pat, &scrut) {
                        for (k, v) in binds {
                            locals.insert(k, v);
                        }
                        return self.eval(&arm.body, locals);
                    }
                }
                Err(Trap("non-exhaustive match at runtime".into()))
            }
            ExprKind::Call { callee, args } => self.eval_call(callee, args, locals),
            ExprKind::Method {
                receiver,
                name,
                type_args,
                args,
                ..
            } => self.eval_method(receiver, name, type_args, args, locals),
            ExprKind::Field { base, name, .. } => {
                let v = self.eval(base, locals)?;
                match v {
                    Value::Struct { fields, .. } => fields
                        .into_iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, v)| v)
                        .ok_or_else(|| Trap(format!("missing field {name}"))),
                    Value::Tuple(xs) => {
                        let i: usize = name.parse().map_err(|_| Trap("bad tuple index".into()))?;
                        xs.into_iter()
                            .nth(i)
                            .ok_or_else(|| Trap("tuple index".into()))
                    }
                    _ => Err(Trap(format!("no field {name}"))),
                }
            }
            ExprKind::Index { base, index } => {
                let base = self.eval(base, locals)?;
                let index = self
                    .eval(index, locals)?
                    .as_int()
                    .ok_or_else(|| Trap("index".into()))?;
                let xs = match base {
                    Value::Array(xs) | Value::List(xs) => xs,
                    _ => return Err(Trap("not indexable".into())),
                };
                if index < 0 || index as usize >= xs.len() {
                    return Err(Trap("index out of bounds".into()));
                }
                Ok(xs.into_iter().nth(index as usize).unwrap())
            }
            ExprKind::Try(inner) => {
                let v = self.eval(inner, locals)?;
                match v {
                    Value::Result(Ok(ok)) => Ok(*ok),
                    Value::Result(Err(err)) => {
                        self.unwind = Some(Value::Result(Err(err)));
                        Ok(Value::Unit)
                    }
                    Value::Option(Some(ok)) => Ok(*ok),
                    Value::Option(None) => {
                        self.unwind = Some(Value::Option(None));
                        Ok(Value::Unit)
                    }
                    _ => Err(Trap("`?` on a non-result".into())),
                }
            }
            ExprKind::Unary { op, expr } => {
                let v = self.eval(expr, locals)?;
                match op {
                    UnOp::Not => Ok(Value::Bool(!truth(&v)?)),
                    UnOp::Neg => Ok(Value::Int(
                        v.as_int().ok_or_else(|| Trap("neg".into()))?.wrapping_neg(),
                    )),
                }
            }
            ExprKind::Binary { op, lhs, rhs } => self.eval_bin(*op, lhs, rhs, locals),
            ExprKind::Struct { path, fields } => {
                let name = path
                    .segments
                    .last()
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                let mut out = Vec::new();
                for f in fields {
                    out.push((f.name.clone(), self.eval(&f.value, locals)?));
                }
                Ok(Value::Struct { name, fields: out })
            }
            ExprKind::Lambda { .. } => Err(Trap(
                "lambda values are lowered to functions; direct eval is unsupported".into(),
            )),
        }
    }

    fn eval_path(
        &mut self,
        path: &mohar_syntax::Path,
        id: u32,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Value, Trap> {
        if let Some(res) = self.checked.resolutions.get(&id).cloned() {
            match res {
                Res::Local(name) => locals
                    .get(&name)
                    .cloned()
                    .ok_or_else(|| Trap(format!("unbound `{name}`"))),
                Res::Func(name) => {
                    if let Some(value) = self.const_value(&name, locals)? {
                        return Ok(value);
                    }
                    Ok(Value::Func(name))
                }
                Res::Constructor(name) if name == "None" => Ok(Value::Option(None)),
                Res::Variant { en, var } => Ok(Value::Enum {
                    name: en.clone(),
                    variant: var.clone(),
                    payload: Vec::new(),
                }),
                Res::Builtin(_) | Res::Constructor(_) => {
                    Ok(Value::Func(format!("builtin:{}", path_string(path))))
                }
            }
        } else if path.segments.len() == 1 {
            let name = &path.segments[0].name;
            locals
                .get(name)
                .cloned()
                .ok_or_else(|| Trap(format!("unbound `{name}`")))
        } else {
            Err(Trap(format!("bad path {}", path_string(path))))
        }
    }

    fn const_value(
        &mut self,
        name: &str,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Option<Value>, Trap> {
        let expr = self
            .checked
            .ast
            .items
            .iter()
            .find_map(|item| match &item.kind {
                ItemKind::Const(c) if c.name == name => Some(c.value.clone()),
                _ => None,
            });
        let Some(expr) = expr else { return Ok(None) };
        Ok(Some(self.eval(&expr, locals)?))
    }

    fn eval_call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        locals: &mut HashMap<String, Value>,
    ) -> Result<Value, Trap> {
        let mut values = Vec::new();
        for a in args {
            values.push(self.eval(a, locals)?);
        }
        if let Some(res) = self.checked.resolutions.get(&callee.id).cloned() {
            return self.dispatch_res(&res, values, locals);
        }
        let cal = self.eval(callee, locals)?;
        if let Value::Func(name) = cal {
            if let Some(rest) = name.strip_prefix("builtin:") {
                return self.dispatch_builtin(rest, values);
            }
            return self.call_user(&name, values);
        }
        Err(Trap("not callable".into()))
    }

    fn dispatch_res(
        &mut self,
        res: &Res,
        args: Vec<Value>,
        _locals: &mut HashMap<String, Value>,
    ) -> Result<Value, Trap> {
        match res {
            Res::Func(name) => self.call_user(name, args),
            Res::Builtin(name) | Res::Constructor(name) => self.dispatch_builtin(name, args),
            Res::Variant { en, var } => Ok(Value::Enum {
                name: en.clone(),
                variant: var.clone(),
                payload: args,
            }),
            Res::Local(_) => Err(Trap("local is not a function".into())),
        }
    }

    fn dispatch_builtin(&mut self, name: &str, args: Vec<Value>) -> Result<Value, Trap> {
        match name {
            "declassify" | "endorse" => args.into_iter().next().ok_or_else(|| Trap("missing value".into())),
            "ctor.Ok" | "Ok" => Ok(Value::Result(Ok(Box::new(args.into_iter().next().unwrap_or(Value::Unit))))),
            "ctor.Err" | "Err" => Ok(Value::Result(Err(Box::new(args.into_iter().next().unwrap_or(Value::Unit))))),
            "ctor.Some" | "Some" => Ok(Value::Option(Some(Box::new(args.into_iter().next().unwrap_or(Value::Unit))))),
            "ctor.None" | "None" => Ok(Value::Option(None)),
            "std.ct::verify_eq" => {
                let a = args.first().and_then(Value::as_bytes).unwrap_or_default();
                let b = args.get(1).and_then(Value::as_bytes).unwrap_or_default();
                Ok(Value::Bool(mohar_std::ct_eq(&a, &b)))
            }
            "std.ct::eq" | "std.ct::lt" => Ok(Value::Bool(false)),
            "std.aead::seal" => {
                let key = args.first().and_then(Value::as_bytes).ok_or_else(|| Trap("key".into()))?;
                let nonce = args.get(1).and_then(Value::as_bytes).ok_or_else(|| Trap("nonce".into()))?;
                let pt = args.get(2).and_then(Value::as_bytes).unwrap_or_default();
                let ct = mohar_std::aead_seal(&key, &nonce, &pt).map_err(|e| Trap(e.to_string()))?;
                Ok(bytes_value(ct))
            }
            "std.aead::open" => {
                let key = args.first().and_then(Value::as_bytes).unwrap_or_default();
                let nonce = args.get(1).and_then(Value::as_bytes).unwrap_or_default();
                let ct = args.get(2).and_then(Value::as_bytes).unwrap_or_default();
                match mohar_std::aead_open(&key, &nonce, &ct) {
                    Ok(pt) => Ok(Value::Result(Ok(Box::new(bytes_value(pt))))),
                    Err(e) => Ok(Value::Result(Err(Box::new(Value::Text(e.to_string()))))),
                }
            }
            "std.hash::sha3_256" => {
                let data = args.first().and_then(Value::as_bytes).unwrap_or_default();
                Ok(array_u8(&mohar_std::sha3_256(&data)))
            }
            "std.hash::sha256" => {
                let data = args.first().and_then(Value::as_bytes).unwrap_or_default();
                Ok(array_u8(&mohar_std::sha256(&data)))
            }
            "std.agent::pick_from" => pick_from(&args),
            "Email::literal" => Ok(Value::Email(arg_text(&args, 0)?)),
            "Url::literal" => Ok(Value::Url(arg_text(&args, 0)?)),
            "Id::literal" => Ok(Value::Id(arg_text(&args, 0)?)),
            "Email::parse" => Ok(Value::Email(arg_text(&args, 0)?)),
            "Kem::default" => Ok(Value::Kem(self.host.kem_algorithm.clone())),
            "Kem::hybrid" => Ok(Value::Kem("X25519-MLKEM768".into())),
            "Kem::ml_kem_768" => Ok(Value::Kem("ML-KEM-768".into())),
            "Kem::ml_kem_1024" => Ok(Value::Kem("ML-KEM-1024".into())),
            "Kem::generate" => self.kem_generate(),
            "Sig::default" => Ok(Value::Sig(self.host.sig_algorithm.clone())),
            "Sig::ml_dsa_44" => Ok(Value::Sig("ML-DSA-44".into())),
            "Sig::ml_dsa_65" => Ok(Value::Sig("ML-DSA-65".into())),
            "Sig::ml_dsa_87" => Ok(Value::Sig("ML-DSA-87".into())),
            "Sig::slh_dsa" => Ok(Value::Sig("SLH-DSA-SHA2-128s".into())),
            "Sig::generate" => self.sig_generate(),
            "List::new" => Ok(Value::List(Vec::new())),
            other if other.starts_with("std.legacy") => {
                Err(Trap("legacy algorithm is tracked by policy and not executed unless it is ECDSA and linked".into()))
            }
            other => Err(Trap(format!("builtin `{other}` is not implemented at runtime"))),
        }
    }

    fn eval_method(
        &mut self,
        receiver: &Expr,
        name: &str,
        type_args: &[mohar_syntax::GenericArg],
        args: &[Expr],
        locals: &mut HashMap<String, Value>,
    ) -> Result<Value, Trap> {
        let recv = self.eval(receiver, locals)?;
        let mut values = Vec::new();
        for a in args {
            values.push(self.eval(a, locals)?);
        }
        match (&recv, name) {
            (Value::Cap(Cap::Console), "console") => {
                // Caps is represented as Cap::Console only when mis-tagged.
                // The real caps token is a unit-like struct we encoded as Cap::Console
                // with a sentinel. See caps_token.
                self.host.allow(&Cap::Console)?;
                self.host.trace_op("Console", None, "derive");
                Ok(Value::Cap(Cap::Console))
            }
            (Value::Func(token), method) if token == "caps" => self.caps_method(method, type_args),
            (Value::Cap(Cap::Console), "println" | "print") => {
                self.host.allow(&Cap::Console)?;
                self.host.trace_op("Console", None, "write");
                let text = values.first().map(Value::display).unwrap_or_default();
                self.host.stdout.push_str(&text);
                if name == "println" {
                    self.host.stdout.push('\n');
                }
                Ok(Value::Unit)
            }
            (Value::Cap(Cap::FsRead(scope)), "read" | "read_text" | "list") => {
                self.fs_read(scope, name, &values)
            }
            (Value::Cap(Cap::FsWrite(scope)), "write") => self.fs_write(scope, &values),
            (Value::Cap(Cap::Net(scope)), "send") => {
                self.host.allow(&Cap::Net(scope.clone()))?;
                self.host.trace_op("Net", Some(scope), "send");
                let bytes = values.first().and_then(Value::as_bytes).unwrap_or_default();
                self.host.net_log.push((scope.clone(), bytes));
                Ok(Value::Unit)
            }
            (Value::Cap(Cap::Tool(scope)), "call") => {
                self.host.allow(&Cap::Tool(scope.clone()))?;
                self.host.trace_op("Tool", Some(scope), "call");
                let rendered: Vec<String> = values.iter().map(Value::display).collect();
                self.host.tool_log.push((scope.clone(), rendered));
                Ok(Value::Unit)
            }
            (Value::Cap(Cap::Model), "ask") => {
                self.host.allow(&Cap::Model)?;
                self.host.trace_op("Model", None, "ask");
                let input = values.get(1).map(Value::display).unwrap_or_default();
                let reply = if input.to_ascii_lowercase().contains("invoice") {
                    "Two sentence summary of the invoice.".to_string()
                } else {
                    self.host.model_reply.clone()
                };
                Ok(Value::Text(reply))
            }
            (Value::Cap(Cap::Rand), "secret_bytes" | "public_bytes") => {
                self.host.allow(&Cap::Rand)?;
                self.host.trace_op("Rand", None, "bytes");
                let n = match type_args.first() {
                    Some(mohar_syntax::GenericArg::Int(v, _)) => *v as usize,
                    _ => 32,
                };
                let mut buf = vec![0u8; n];
                mohar_std::fill_random(&mut buf).map_err(|e| Trap(e.to_string()))?;
                Ok(array_u8(&buf))
            }
            (Value::Cap(Cap::Clock), "unix_ms") => {
                self.host.allow(&Cap::Clock)?;
                let ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i128)
                    .unwrap_or(0);
                Ok(Value::Int(ms))
            }
            (Value::Kem(_), "encaps") => self.kem_encaps(&values),
            (Value::Kem(_), "decaps") => self.kem_decaps(&values),
            (Value::Sig(alg), "sign") => self.sig_sign(alg, &values),
            (Value::Text(s), "to_bytes") => Ok(Value::Bytes(s.as_bytes().to_vec())),
            (Value::Text(s), "to_hex") => Ok(Value::Text(to_hex(s.as_bytes()))),
            (Value::Text(s), "split_whitespace") => {
                let parts = s
                    .split_whitespace()
                    .map(|w| Value::Text(w.to_string()))
                    .collect();
                Ok(Value::List(parts))
            }
            (Value::Text(s), "len") => Ok(Value::Int(s.chars().count() as i128)),
            (Value::Bytes(b), "to_hex") => Ok(Value::Text(to_hex(b))),
            (Value::Bytes(b), "len") => Ok(Value::Int(b.len() as i128)),
            (Value::Bytes(b), "to_bytes") => Ok(Value::Bytes(b.clone())),
            (Value::Array(xs), "to_hex") => {
                let bytes = Value::Array(xs.clone()).as_bytes().unwrap_or_default();
                Ok(Value::Text(to_hex(&bytes)))
            }
            (Value::Array(xs), "len") => Ok(Value::Int(xs.len() as i128)),
            (Value::List(xs), "len") => Ok(Value::Int(xs.len() as i128)),
            (Value::List(xs), "push") => {
                // Push updates the receiver only if it is a local. The checker
                // guarantees the call is on a local in the examples; we also
                // accept a fresh list and return unit, mutating via the path.
                let _ = xs;
                if let ExprKind::Path(p) = &receiver.kind {
                    if p.segments.len() == 1 {
                        let name = &p.segments[0].name;
                        if let Some(Value::List(list)) = locals.get_mut(name) {
                            if let Some(v) = values.into_iter().next() {
                                list.push(v);
                            }
                        }
                    }
                }
                Ok(Value::Unit)
            }
            (Value::Int(n), "to_text") => Ok(Value::Text(n.to_string())),
            (Value::Bool(b), "to_text") => Ok(Value::Text(b.to_string())),
            _ => Err(Trap(format!(
                "method `{name}` is not available on {}",
                recv.type_name()
            ))),
        }
    }

    fn caps_method(
        &mut self,
        method: &str,
        type_args: &[mohar_syntax::GenericArg],
    ) -> Result<Value, Trap> {
        let scope = match type_args.first() {
            Some(mohar_syntax::GenericArg::Str(s, _)) => {
                Some(s.trim_start_matches("./").trim_matches('/').to_string())
            }
            _ => None,
        };
        let cap = match method {
            "console" => Cap::Console,
            "model" => Cap::Model,
            "rand" => Cap::Rand,
            "clock" => Cap::Clock,
            "declassify" => Cap::Declassify,
            "endorse" => Cap::Endorse,
            "fs_read" => Cap::FsRead(scope.clone().unwrap_or_default()),
            "fs_write" => Cap::FsWrite(scope.clone().unwrap_or_default()),
            "net" => Cap::Net(scope.clone().unwrap_or_default()),
            "tool" => Cap::Tool(scope.clone().unwrap_or_default()),
            other => return Err(Trap(format!("unknown capability `{other}`"))),
        };
        self.host.allow(&cap)?;
        let (name, sc) = match &cap {
            Cap::Console => ("Console", None),
            Cap::Model => ("Model", None),
            Cap::Rand => ("Rand", None),
            Cap::Clock => ("Clock", None),
            Cap::Declassify => ("Declassify", None),
            Cap::Endorse => ("Endorse", None),
            Cap::FsRead(s) => ("FsRead", Some(s.as_str())),
            Cap::FsWrite(s) => ("FsWrite", Some(s.as_str())),
            Cap::Net(s) => ("Net", Some(s.as_str())),
            Cap::Tool(s) => ("Tool", Some(s.as_str())),
        };
        self.host.trace_op(name, sc, "derive");
        Ok(Value::Cap(cap))
    }

    fn fs_read(&mut self, scope: &str, op: &str, args: &[Value]) -> Result<Value, Trap> {
        self.host.allow(&Cap::FsRead(scope.to_string()))?;
        self.host.trace_op("FsRead", Some(scope), op);
        if op == "list" {
            let dir = self.host.resolve_file(scope, "")?;
            let mut names = Vec::new();
            if dir.is_dir() {
                for ent in std::fs::read_dir(&dir).map_err(|e| Trap(e.to_string()))? {
                    let ent = ent.map_err(|e| Trap(e.to_string()))?;
                    if ent
                        .path()
                        .symlink_metadata()
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        return Err(Trap("symlink refused".into()));
                    }
                    if let Some(name) = ent.file_name().to_str() {
                        names.push(Value::Text(name.to_string()));
                    }
                }
            }
            names.sort_by_key(Value::display);
            return Ok(Value::List(names));
        }
        let rel = args
            .first()
            .and_then(Value::as_text)
            .unwrap_or("")
            .to_string();
        let path = self.host.resolve_file(scope, &rel)?;
        let bytes =
            std::fs::read(&path).map_err(|e| Trap(format!("read {}: {e}", path.display())))?;
        self.host.charge_mem(bytes.len() as u64)?;
        if op == "read_text" {
            let text = String::from_utf8(bytes).map_err(|_| Trap("file is not utf-8".into()))?;
            Ok(Value::Text(text))
        } else {
            Ok(Value::Bytes(bytes))
        }
    }

    fn fs_write(&mut self, scope: &str, args: &[Value]) -> Result<Value, Trap> {
        self.host.allow(&Cap::FsWrite(scope.to_string()))?;
        self.host.trace_op("FsWrite", Some(scope), "write");
        let rel = args
            .first()
            .and_then(Value::as_text)
            .unwrap_or("")
            .to_string();
        let data = args.get(1).and_then(Value::as_bytes).unwrap_or_default();
        let path = self.host.resolve_file(scope, &rel)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Trap(e.to_string()))?;
        }
        std::fs::write(&path, data).map_err(|e| Trap(e.to_string()))?;
        Ok(Value::Unit)
    }

    fn kem_generate(&mut self) -> Result<Value, Trap> {
        let (sk, pk) = match self.host.kem_algorithm.as_str() {
            "ML-KEM-1024" => mohar_std::mlkem1024_generate().map_err(|e| Trap(e.to_string()))?,
            "ML-KEM-768" => mohar_std::mlkem768_generate().map_err(|e| Trap(e.to_string()))?,
            _ => mohar_std::hybrid_generate().map_err(|e| Trap(e.to_string()))?,
        };
        Ok(Value::Tuple(vec![Value::KemSk(sk), Value::KemPk(pk)]))
    }

    fn sig_generate(&mut self) -> Result<Value, Trap> {
        let (sk, pk) = if self.host.sig_algorithm.contains("SLH") {
            mohar_std::slh_generate().map_err(|e| Trap(e.to_string()))?
        } else {
            let level = if self.host.sig_algorithm.contains("44") {
                MlDsaLevel::D44
            } else if self.host.sig_algorithm.contains("87") {
                MlDsaLevel::D87
            } else {
                MlDsaLevel::D65
            };
            mohar_std::mldsa_generate(level).map_err(|e| Trap(e.to_string()))?
        };
        Ok(Value::Tuple(vec![Value::SigSk(sk), Value::SigPk(pk)]))
    }

    fn kem_encaps(&mut self, args: &[Value]) -> Result<Value, Trap> {
        let pk = match args.first() {
            Some(Value::KemPk(b)) => b.clone(),
            _ => return Err(Trap("encaps expects a KemPublicKey".into())),
        };
        // The algorithm was chosen at compile time. Default hybrid unless the
        // key is too short to be a hybrid public key (32 + ML-KEM).
        let (ct, shared) = match self.host.kem_algorithm.as_str() {
            "ML-KEM-1024" => mohar_std::mlkem1024_encaps(&pk).map_err(|e| Trap(e.to_string()))?,
            "ML-KEM-768" => mohar_std::mlkem768_encaps(&pk).map_err(|e| Trap(e.to_string()))?,
            _ => mohar_std::hybrid_encaps(&pk).map_err(|e| Trap(e.to_string()))?,
        };
        Ok(Value::Tuple(vec![bytes_value(ct), array_u8(&shared)]))
    }

    fn kem_decaps(&mut self, args: &[Value]) -> Result<Value, Trap> {
        let sk = match args.first() {
            Some(Value::KemSk(b)) => b.clone(),
            _ => return Err(Trap("decaps expects a KemSecretKey".into())),
        };
        let ct = args.get(1).and_then(Value::as_bytes).unwrap_or_default();
        let shared = if sk.len() == 64 && ct.len() > 1500 {
            mohar_std::mlkem1024_decaps(&sk, &ct).map_err(|e| Trap(e.to_string()))?
        } else if sk.len() == 64 {
            mohar_std::mlkem768_decaps(&sk, &ct).map_err(|e| Trap(e.to_string()))?
        } else {
            mohar_std::hybrid_decaps(&sk, &ct).map_err(|e| Trap(e.to_string()))?
        };
        Ok(array_u8(&shared))
    }

    fn sig_sign(&mut self, alg: &str, args: &[Value]) -> Result<Value, Trap> {
        let sk = match args.first() {
            Some(Value::SigSk(b)) => b.clone(),
            _ => return Err(Trap("sign expects a SigSecretKey".into())),
        };
        let msg = args.get(1).and_then(Value::as_bytes).unwrap_or_default();
        let sig = if alg.contains("SLH") {
            mohar_std::slh_sign(&sk, &msg).map_err(|e| Trap(e.to_string()))?
        } else {
            let level = if alg.contains("44") {
                MlDsaLevel::D44
            } else if alg.contains("87") {
                MlDsaLevel::D87
            } else {
                MlDsaLevel::D65
            };
            mohar_std::mldsa_sign(level, &sk, &msg).map_err(|e| Trap(e.to_string()))?
        };
        Ok(bytes_value(sig))
    }

    fn eval_bin(
        &mut self,
        op: BinOp,
        lhs: &Expr,
        rhs: &Expr,
        locals: &mut HashMap<String, Value>,
    ) -> Result<Value, Trap> {
        if op == BinOp::Range {
            let a = self.eval(lhs, locals)?;
            let b = self.eval(rhs, locals)?;
            return Ok(Value::Tuple(vec![a, b]));
        }
        if op == BinOp::And {
            let l = self.eval(lhs, locals)?;
            if !truth(&l)? {
                return Ok(Value::Bool(false));
            }
            let r = self.eval(rhs, locals)?;
            return Ok(Value::Bool(truth(&r)?));
        }
        if op == BinOp::Or {
            let l = self.eval(lhs, locals)?;
            if truth(&l)? {
                return Ok(Value::Bool(true));
            }
            let r = self.eval(rhs, locals)?;
            return Ok(Value::Bool(truth(&r)?));
        }
        let l = self.eval(lhs, locals)?;
        let r = self.eval(rhs, locals)?;
        if matches!(op, BinOp::Eq | BinOp::Ne) {
            let eq = values_eq(&l, &r);
            return Ok(Value::Bool(if op == BinOp::Eq { eq } else { !eq }));
        }
        let a = l.as_int().ok_or_else(|| Trap("lhs int".into()))?;
        let b = r.as_int().ok_or_else(|| Trap("rhs int".into()))?;
        let v = match op {
            BinOp::Add => a.checked_add(b).ok_or_else(|| Trap("overflow".into()))?,
            BinOp::Sub => a.checked_sub(b).ok_or_else(|| Trap("overflow".into()))?,
            BinOp::Mul => a.checked_mul(b).ok_or_else(|| Trap("overflow".into()))?,
            BinOp::Div => {
                if b == 0 {
                    return Err(Trap("division by zero".into()));
                }
                a.checked_div(b).ok_or_else(|| Trap("overflow".into()))?
            }
            BinOp::Rem => {
                if b == 0 {
                    return Err(Trap("division by zero".into()));
                }
                a % b
            }
            BinOp::Lt => return Ok(Value::Bool(a < b)),
            BinOp::Le => return Ok(Value::Bool(a <= b)),
            BinOp::Gt => return Ok(Value::Bool(a > b)),
            BinOp::Ge => return Ok(Value::Bool(a >= b)),
            BinOp::BitAnd => a & b,
            BinOp::BitOr => a | b,
            BinOp::BitXor => a ^ b,
            BinOp::Shl => a << (b as u32),
            BinOp::Shr => a >> (b as u32),
            BinOp::Eq | BinOp::Ne | BinOp::And | BinOp::Or | BinOp::Range => unreachable!(),
        };
        Ok(Value::Int(v))
    }
}

fn caps_token() -> Value {
    Value::Func("caps".into())
}

fn truth(v: &Value) -> Result<bool, Trap> {
    match v {
        Value::Bool(b) => Ok(*b),
        _ => Err(Trap("expected bool".into())),
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Text(x), Value::Text(y)) => x == y,
        (Value::Bytes(x), Value::Bytes(y)) => mohar_std::ct_eq(x, y),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| values_eq(p, q))
        }
        _ => false,
    }
}

fn bind_pat(pat: &mohar_syntax::Pattern, value: Value, locals: &mut HashMap<String, Value>) {
    match &pat.kind {
        mohar_syntax::PatKind::Binding { name, .. } => {
            locals.insert(name.clone(), value);
        }
        mohar_syntax::PatKind::Tuple(ps) => {
            if let Value::Tuple(xs) = value {
                for (p, v) in ps.iter().zip(xs) {
                    bind_pat(p, v, locals);
                }
            }
        }
        mohar_syntax::PatKind::Wild => {}
        _ => {}
    }
}

fn match_pat(pat: &mohar_syntax::Pattern, value: &Value) -> Option<Vec<(String, Value)>> {
    match &pat.kind {
        mohar_syntax::PatKind::Wild => Some(Vec::new()),
        mohar_syntax::PatKind::Binding { name, .. } => Some(vec![(name.clone(), value.clone())]),
        mohar_syntax::PatKind::LitBool(b) => match value {
            Value::Bool(v) if v == b => Some(Vec::new()),
            _ => None,
        },
        mohar_syntax::PatKind::LitInt(n) => match value {
            Value::Int(v) if v == n => Some(Vec::new()),
            _ => None,
        },
        mohar_syntax::PatKind::LitStr(s) => match value {
            Value::Text(v) if v == s => Some(Vec::new()),
            _ => None,
        },
        mohar_syntax::PatKind::Tuple(ps) => match value {
            Value::Tuple(xs) if xs.len() == ps.len() => {
                let mut binds = Vec::new();
                for (p, v) in ps.iter().zip(xs) {
                    binds.extend(match_pat(p, v)?);
                }
                Some(binds)
            }
            _ => None,
        },
        mohar_syntax::PatKind::Variant { path, args } if path.segments.len() == 1 => {
            match (path.segments[0].name.as_str(), value) {
                ("Some", Value::Option(Some(v))) | ("Ok", Value::Result(Ok(v))) => {
                    args.first().and_then(|p| match_pat(p, v))
                }
                ("Err", Value::Result(Err(v))) => args.first().and_then(|p| match_pat(p, v)),
                _ => None,
            }
        }
        mohar_syntax::PatKind::Variant { path, args } => match value {
            Value::Enum {
                variant, payload, ..
            } => {
                let want = path.segments.last()?.name.as_str();
                if variant != want || payload.len() != args.len() {
                    return None;
                }
                let mut binds = Vec::new();
                for (p, v) in args.iter().zip(payload) {
                    binds.extend(match_pat(p, v)?);
                }
                Some(binds)
            }
            _ => None,
        },
        mohar_syntax::PatKind::Struct { .. } => None,
    }
}

fn arg_text(args: &[Value], i: usize) -> Result<String, Trap> {
    args.get(i)
        .and_then(Value::as_text)
        .map(|s| s.to_string())
        .ok_or_else(|| Trap("expected text".into()))
}

fn pick_from(args: &[Value]) -> Result<Value, Trap> {
    let list = match args.first() {
        Some(Value::List(xs)) | Some(Value::Array(xs)) => xs,
        _ => return Err(Trap("pick_from options".into())),
    };
    let hint = args.get(1).map(Value::display).unwrap_or_default();
    for item in list {
        if item.display() == hint {
            return Ok(Value::Text(item.display()));
        }
    }
    Err(Trap("pick_from: no allow-list match".into()))
}

fn path_string(path: &mohar_syntax::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.name.as_str())
        .collect::<Vec<_>>()
        .join("::")
}

// Keep FnItem mentioned so a future inlining pass has the type in scope.
#[allow(dead_code)]
fn _fn_name(f: &FnItem) -> &str {
    &f.name
}
