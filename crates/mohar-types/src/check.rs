//! The checker. One context walks a parsed module and records a type for
//! every expression, plus the authority, crypto and flow facts the seal needs.

use std::collections::{HashMap, HashSet};

use mohar_diag::{Code, Diagnostic, SourceFile, Span};
use mohar_syntax::{
    BinOp, Block, Expr, ExprKind, FnItem, GenericArg, ItemKind, LabelWord, PatKind, Path, Pattern,
    Program, Stmt, StmtKind, TypeExpr, TypeKind, UnOp,
};

use crate::label::{Conf, Integ, Label};
use crate::policy::{
    AuthorityEntry, CryptoPolicy, CryptoUse, FlowNote, FlowNoteKind, Grant, Origin, Profile,
};
use crate::ty::{BaseTy, IntKind, Ty, cap_subtype, normalize_scope};

/// What a name resolved to. The interpreter and the IR printer both read this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Res {
    Local(String),
    Func(String),
    Builtin(String),
    Variant { en: String, var: String },
    Constructor(String),
}

#[derive(Clone, Debug)]
pub struct Checked {
    pub ast: Program,
    pub types: HashMap<u32, Ty>,
    pub resolutions: HashMap<u32, Res>,
    pub diagnostics: Vec<Diagnostic>,
    pub profile: Profile,
    pub authority: Vec<AuthorityEntry>,
    pub crypto: Vec<CryptoUse>,
    pub flows: Vec<FlowNote>,
    pub has_main: bool,
}

impl Checked {
    pub fn ok(&self) -> bool {
        !self.diagnostics.iter().any(Diagnostic::is_error)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CheckOptions {
    pub policy: CryptoPolicy,
    pub grant: Option<Grant>,
}

pub fn check_source(file: &SourceFile, opts: &CheckOptions) -> Checked {
    let parsed = mohar_syntax::parse(file);
    let mut cx = Cx::new(file, opts, parsed.diagnostics);
    cx.check_program(&parsed.program);
    cx.finish(parsed.program)
}

struct FnRec {
    params: Vec<(String, Ty)>,
    ret: Ty,
    span: Span,
    direct_priv: bool,
    calls: Vec<String>,
}

#[derive(Clone)]
struct Bind {
    name: String,
    ty: Ty,
    mutable: bool,
    #[allow(dead_code)]
    span: Span,
}

struct Cx<'a> {
    file: &'a SourceFile,
    opts: &'a CheckOptions,
    diags: Vec<Diagnostic>,
    types: HashMap<u32, Ty>,
    resolutions: HashMap<u32, Res>,
    fns: HashMap<String, FnRec>,
    structs: HashMap<String, Vec<(String, Ty)>>,
    enums: HashMap<String, Vec<(String, Vec<Ty>)>>,
    consts: HashMap<String, (Ty, ConstVal)>,
    names: HashMap<String, Name>,
    scope: Vec<ScopeItem>,
    ret_ty: Ty,
    pc: Label,
    profile: Profile,
    current_fn: String,
    call_sites: Vec<CallSite>,
    cap_sites: Vec<CapSite>,
    crypto: Vec<CryptoUse>,
    flows: Vec<FlowNote>,
    saw_while: Vec<(String, Span)>,
}

#[derive(Clone)]
struct CallSite {
    span: Span,
    callee: String,
    untrusted_pc: bool,
}

struct CapSite {
    func: String,
    entry: AuthorityEntry,
}

enum ScopeItem {
    Bind(Bind),
    Barrier,
}

#[derive(Clone, Debug)]
enum ConstVal {
    Int(i128),
    #[allow(dead_code)]
    Str(String),
}

#[derive(Clone, Debug)]
enum Name {
    Module(&'static str),
    Builtin(&'static str),
    #[allow(dead_code)]
    Type(&'static str),
    Legacy(&'static str),
}

impl<'a> Cx<'a> {
    fn new(file: &'a SourceFile, opts: &'a CheckOptions, diags: Vec<Diagnostic>) -> Self {
        let mut names = HashMap::new();
        for t in [
            "Caps",
            "Console",
            "Model",
            "Rand",
            "Clock",
            "Declassify",
            "Endorse",
            "Email",
            "Url",
            "Id",
            "List",
            "Option",
            "Result",
            "Text",
            "Bytes",
            "Unit",
        ] {
            names.insert(
                t.to_string(),
                Name::Type(match t {
                    "Caps" => "Caps",
                    "Console" => "Console",
                    "Model" => "Model",
                    "Rand" => "Rand",
                    "Clock" => "Clock",
                    "Declassify" => "Declassify",
                    "Endorse" => "Endorse",
                    "Email" => "Email",
                    "Url" => "Url",
                    "Id" => "Id",
                    "List" => "List",
                    "Option" => "Option",
                    "Result" => "Result",
                    "Text" => "Text",
                    "Bytes" => "Bytes",
                    _ => "Unit",
                }),
            );
        }
        names.insert("Ok".into(), Name::Builtin("ctor.Ok"));
        names.insert("Err".into(), Name::Builtin("ctor.Err"));
        names.insert("Some".into(), Name::Builtin("ctor.Some"));
        names.insert("None".into(), Name::Builtin("ctor.None"));
        names.insert("declassify".into(), Name::Builtin("declassify"));
        names.insert("endorse".into(), Name::Builtin("endorse"));
        Self {
            file,
            opts,
            diags,
            types: HashMap::new(),
            resolutions: HashMap::new(),
            fns: HashMap::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
            consts: HashMap::new(),
            names,
            scope: Vec::new(),
            ret_ty: Ty::unit(),
            pc: Label::PUBLIC_TRUSTED,
            profile: Profile::Default,
            current_fn: String::new(),
            call_sites: Vec::new(),
            cap_sites: Vec::new(),
            crypto: Vec::new(),
            flows: Vec::new(),
            saw_while: Vec::new(),
        }
    }

    fn finish(mut self, ast: Program) -> Checked {
        self.propagate_privilege();
        self.check_plan_recursion();
        let reachable = self.reachable();
        let mut authority: Vec<AuthorityEntry> = self
            .cap_sites
            .into_iter()
            .filter(|c| reachable.contains(&c.func))
            .map(|c| c.entry)
            .collect();
        authority.sort_by(|a, b| (&a.cap, &a.scope).cmp(&(&b.cap, &b.scope)));
        authority.dedup_by(|a, b| a.cap == b.cap && a.scope == b.scope);
        Checked {
            has_main: self.fns.contains_key("main"),
            ast,
            types: self.types,
            resolutions: self.resolutions,
            diagnostics: self.diags,
            profile: self.profile,
            authority,
            crypto: self.crypto,
            flows: self.flows,
        }
    }

    fn check_program(&mut self, program: &Program) {
        for item in &program.items {
            if let ItemKind::Fn(f) = &item.kind {
                if f.name == "main" {
                    self.profile = profile_of(item);
                }
            }
        }
        for item in &program.items {
            match &item.kind {
                ItemKind::Struct(s) => {
                    let fields = s
                        .fields
                        .iter()
                        .map(|f| (f.name.clone(), self.lower_type(&f.ty)))
                        .collect();
                    self.structs.insert(s.name.clone(), fields);
                    self.names.insert(s.name.clone(), Name::Type("struct"));
                }
                ItemKind::Enum(e) => {
                    let variants = e
                        .variants
                        .iter()
                        .map(|v| {
                            (
                                v.name.clone(),
                                v.fields.iter().map(|t| self.lower_type(t)).collect(),
                            )
                        })
                        .collect();
                    self.enums.insert(e.name.clone(), variants);
                    self.names.insert(e.name.clone(), Name::Type("enum"));
                }
                _ => {}
            }
        }
        for item in &program.items {
            if let ItemKind::Use(u) = &item.kind {
                self.bind_use(&u.module, &u.names, u.span);
            }
        }
        for item in &program.items {
            if let ItemKind::Const(c) = &item.kind {
                let ty = self.lower_type(&c.ty);
                let val = self.eval_const(&c.value);
                self.consts.insert(c.name.clone(), (ty, val));
            }
        }
        for item in &program.items {
            if let ItemKind::Fn(f) = &item.kind {
                let params: Vec<(String, Ty)> = f
                    .params
                    .iter()
                    .map(|p| (p.name.clone(), self.lower_type(&p.ty)))
                    .collect();
                let ret = f
                    .ret
                    .as_ref()
                    .map(|t| self.lower_type(t))
                    .unwrap_or_else(Ty::unit);
                self.fns.insert(
                    f.name.clone(),
                    FnRec {
                        params,
                        ret,
                        span: f.name_span,
                        direct_priv: false,
                        calls: Vec::new(),
                    },
                );
            } else if let ItemKind::Mod(m) = &item.kind {
                self.error(
                    Code::E007,
                    m.name_span,
                    "v0.1 checks one file. Split modules are parsed and rejected here so the keyword is not silently ignored",
                );
            }
        }
        for item in &program.items {
            if let ItemKind::Fn(f) = &item.kind {
                self.check_fn(f);
            }
        }
    }

    fn check_fn(&mut self, f: &FnItem) {
        let rec = self.fns.get(&f.name).unwrap();
        let params = rec.params.clone();
        let ret = rec.ret.clone();
        self.current_fn = f.name.clone();
        self.ret_ty = ret.clone();
        self.pc = Label::PUBLIC_TRUSTED;
        self.scope.clear();
        for (name, ty) in &params {
            let mut ty = ty.clone();
            if ty.label.is_secret() {
                ty.secret_origin = Some(Origin {
                    span: f.name_span,
                    name: Some(name.clone()),
                });
            }
            if ty.label.is_untrusted() {
                ty.untrusted_origin = Some(Origin {
                    span: f.name_span,
                    name: Some(name.clone()),
                });
            }
            self.scope.push(ScopeItem::Bind(Bind {
                name: name.clone(),
                ty,
                mutable: false,
                span: f.name_span,
            }));
        }
        let got = self.check_block(&f.body, Some(&ret));
        self.flow_at(f.body.span, &got, &ret, Some("the function's return type"));
        if self.profile == Profile::Plan {
            // Non-recursive helpers are allowed. Recursion is rejected later
            // from the call graph; `while` is rejected at the statement.
        }
        self.current_fn.clear();
    }

    fn check_block(&mut self, block: &Block, expected: Option<&Ty>) -> Ty {
        let mark = self.scope.len();
        let saved_pc = self.pc;
        for stmt in &block.stmts {
            self.check_stmt(stmt);
        }
        let ends_with_return = block
            .stmts
            .last()
            .is_some_and(|s| matches!(s.kind, StmtKind::Return(_)));
        let ty = if let Some(tail) = &block.tail {
            let t = self.infer(tail, expected);
            t.under_pc(self.pc, tail.span)
        } else if ends_with_return {
            // A block that ends in `return` does not fall through. Its type
            // is the function's return type, which the `return` already checked.
            self.ret_ty.clone()
        } else {
            Ty::unit().under_pc(self.pc, block.span)
        };
        self.scope.truncate(mark);
        self.pc = saved_pc;
        self.types.insert(block.id, ty.clone());
        ty
    }

    fn check_stmt(&mut self, stmt: &Stmt) {
        match &stmt.kind {
            StmtKind::Let {
                mutable,
                pat,
                ty,
                value,
            } => {
                let bound = if let Some(ann) = ty {
                    let expected = self.lower_type(ann);
                    let got = self.infer(value, Some(&expected));
                    self.flow_at(value.span, &got, &expected, None);
                    expected
                } else {
                    let got = self.infer(value, None);
                    concretize(got)
                };
                self.bind_pat(pat, &bound, *mutable);
            }
            StmtKind::Assign {
                name,
                name_span,
                value,
            } => {
                let Some(existing) = self.lookup_bind(name).cloned() else {
                    self.error(Code::E002, *name_span, format!("unknown name `{name}`"));
                    return;
                };
                if self.crossed_barrier(name) {
                    self.error(
                        Code::E208,
                        *name_span,
                        "closures cannot capture variables in v0.1",
                    );
                    return;
                }
                if !existing.mutable {
                    self.error(Code::E003, *name_span, format!("`{name}` is not mutable"));
                }
                let got = self.infer(value, Some(&existing.ty));
                let got = got.under_pc(self.pc, value.span);
                self.flow_at(value.span, &got, &existing.ty, Some("the variable's type"));
            }
            StmtKind::Expr(e) => {
                self.infer(e, None);
            }
            StmtKind::Return(v) => {
                let ret = self.ret_ty.clone();
                if let Some(v) = v {
                    let got = self.infer(v, Some(&ret));
                    let got = got.under_pc(self.pc, v.span);
                    self.flow_at(v.span, &got, &ret, Some("the function's return type"));
                } else {
                    self.flow_at(
                        stmt.span,
                        &Ty::unit(),
                        &ret,
                        Some("the function's return type"),
                    );
                }
            }
            StmtKind::While { cond, body } => {
                if self.profile == Profile::Plan {
                    self.error(
                        Code::E211,
                        stmt.span,
                        "`while` is not allowed in a plan profile; use a bounded `for`",
                    );
                    self.saw_while.push((self.current_fn.clone(), stmt.span));
                }
                let c = self.infer(cond, Some(&Ty::bool()));
                self.secret_branch(&c, cond.span);
                let saved = self.pc;
                if c.label.is_untrusted() {
                    self.pc.integ = Integ::Untrusted;
                }
                self.check_block(body, None);
                self.pc = saved;
            }
            StmtKind::For {
                name,
                name_span,
                iter,
                body,
            } => {
                self.check_for(name, *name_span, iter, body);
            }
        }
    }

    fn check_for(&mut self, name: &str, name_span: Span, iter: &Expr, body: &Block) {
        if let ExprKind::Binary {
            op: BinOp::Range,
            lhs,
            rhs,
        } = &iter.kind
        {
            let a = self.infer(lhs, None);
            let b = self.infer(rhs, None);
            if a.label.is_secret() || b.label.is_secret() {
                self.error(
                    Code::E103,
                    iter.span,
                    "loop bound depends on a secret value",
                );
            }
            let kind = unify_int(&a, &b).unwrap_or(IntKind::I64);
            let mut var_ty = Ty::plain(BaseTy::Int(kind));
            var_ty.label = a.label.join(b.label);
            var_ty.label.conf = Conf::Public;
            if var_ty.label.is_untrusted() {
                var_ty.untrusted_origin = a.untrusted_origin.clone().or(b.untrusted_origin.clone());
            }
            let saved = self.pc;
            if var_ty.label.is_untrusted() {
                self.pc.integ = Integ::Untrusted;
            }
            self.scope.push(ScopeItem::Bind(Bind {
                name: name.to_string(),
                ty: var_ty,
                mutable: false,
                span: name_span,
            }));
            self.check_block(body, None);
            self.scope.pop();
            self.pc = saved;
            return;
        }
        let collection = self.infer(iter, None);
        if collection.label.is_secret() {
            self.error(
                Code::E103,
                iter.span,
                "loop bound depends on a secret value",
            );
        }
        let mut elem = match &collection.base {
            BaseTy::List(t) => (**t).clone(),
            BaseTy::Array(t, _) => (**t).clone(),
            BaseTy::Error => Ty::error(),
            _ => {
                self.error(
                    Code::E003,
                    iter.span,
                    "for-loop expects a range, list or array",
                );
                Ty::error()
            }
        };
        elem = elem.join_label(collection.label);
        if collection.label.is_untrusted() {
            elem.label.integ = Integ::Untrusted;
            elem.untrusted_origin = collection.untrusted_origin.clone();
        }
        let saved = self.pc;
        if collection.label.is_untrusted() {
            self.pc.integ = Integ::Untrusted;
        }
        self.scope.push(ScopeItem::Bind(Bind {
            name: name.to_string(),
            ty: elem,
            mutable: false,
            span: name_span,
        }));
        self.check_block(body, None);
        self.scope.pop();
        self.pc = saved;
    }

    fn infer(&mut self, expr: &Expr, expected: Option<&Ty>) -> Ty {
        let ty = self.infer_inner(expr, expected);
        self.types.insert(expr.id, ty.clone());
        ty
    }

    fn infer_inner(&mut self, expr: &Expr, expected: Option<&Ty>) -> Ty {
        match &expr.kind {
            ExprKind::Error => Ty::error(),
            ExprKind::Unit => Ty::unit(),
            ExprKind::Bool(_) => Ty::bool(),
            ExprKind::String(_) => Ty::text(),
            ExprKind::Bytes(_) => Ty::bytes(),
            ExprKind::Int { value, suffix } => self.int_lit(*value, *suffix, expected, expr.span),
            ExprKind::Path(path) => self.infer_path(path, expr.id, expected),
            ExprKind::Tuple(xs) => {
                let ts: Vec<Ty> = xs.iter().map(|x| self.infer(x, None)).collect();
                let label = ts
                    .iter()
                    .fold(Label::PUBLIC_TRUSTED, |a, t| a.join(t.label));
                let mut ty = Ty::new(BaseTy::Tuple(ts.clone()), label);
                ty = propagate(&ty, &ts);
                ty
            }
            ExprKind::Array(xs) => self.infer_array(xs, expected, expr.span),
            ExprKind::Repeat { value, len } => {
                let n = self.eval_const(len);
                let n = match n {
                    ConstVal::Int(v) if v >= 0 => v as u64,
                    _ => {
                        self.error(
                            Code::E003,
                            len.span,
                            "array length must be a constant integer",
                        );
                        0
                    }
                };
                let elem_expected = match expected {
                    Some(Ty {
                        base: BaseTy::Array(t, m),
                        ..
                    }) if *m == n => Some(t.as_ref()),
                    _ => None,
                };
                let elem = self.infer(value, elem_expected);
                Ty::new(BaseTy::Array(Box::new(elem.clone()), n), elem.label)
            }
            ExprKind::Block(b) => self.check_block(b, expected),
            ExprKind::If {
                cond,
                then_branch,
                else_branch,
            } => self.infer_if(cond, then_branch, else_branch.as_deref(), expected),
            ExprKind::Match { scrutinee, arms } => self.infer_match(scrutinee, arms, expected),
            ExprKind::Lambda { params, body } => {
                self.infer_lambda(params, body, expected, expr.span)
            }
            ExprKind::Call { callee, args } => self.infer_call(callee, args, expected, expr.span),
            ExprKind::Method {
                receiver,
                name,
                name_span,
                type_args,
                args,
            } => self.infer_method(
                receiver, name, *name_span, type_args, args, expected, expr.span,
            ),
            ExprKind::Field {
                base,
                name,
                name_span,
            } => self.infer_field(base, name, *name_span),
            ExprKind::Index { base, index } => self.infer_index(base, index),
            ExprKind::Try(inner) => self.infer_try(inner, expr.span),
            ExprKind::Unary { op, expr: inner } => self.infer_unary(*op, inner),
            ExprKind::Binary { op, lhs, rhs } => self.infer_binary(*op, lhs, rhs, expr.span),
            ExprKind::Struct { path, fields } => self.infer_struct(path, fields, expr.span),
        }
    }

    fn int_lit(
        &mut self,
        value: i128,
        suffix: Option<mohar_syntax::IntSuffix>,
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        if let Some(suf) = suffix {
            let kind = match suf {
                mohar_syntax::IntSuffix::U8 => IntKind::U8,
                mohar_syntax::IntSuffix::U16 => IntKind::U16,
                mohar_syntax::IntSuffix::U32 => IntKind::U32,
                mohar_syntax::IntSuffix::U64 => IntKind::U64,
                mohar_syntax::IntSuffix::I64 => IntKind::I64,
            };
            if !kind.fits(value) {
                self.error(
                    Code::E003,
                    span,
                    format!("literal does not fit in {}", kind.name()),
                );
            }
            return Ty::plain(BaseTy::Int(kind));
        }
        if let Some(Ty {
            base: BaseTy::Int(k),
            ..
        }) = expected
        {
            if !k.fits(value) {
                self.error(
                    Code::E003,
                    span,
                    format!("literal does not fit in {}", k.name()),
                );
            }
            return Ty::plain(BaseTy::Int(*k));
        }
        Ty::plain(BaseTy::IntLit(value))
    }

    fn infer_path(&mut self, path: &Path, id: u32, expected: Option<&Ty>) -> Ty {
        if path.segments.len() == 1 && path.segments[0].args.is_empty() {
            let name = &path.segments[0].name;
            if self.lookup_bind(name).is_some() {
                if self.crossed_barrier(name) {
                    self.error(Code::E208, path.span, "closures cannot capture variables in v0.1, and cannot capture capabilities at all");
                    return Ty::error();
                }
                let ty = self.lookup_bind(name).unwrap().ty.clone();
                self.resolutions.insert(id, Res::Local(name.clone()));
                return ty;
            }
            if let Some((ty, _)) = self.consts.get(name) {
                self.resolutions.insert(id, Res::Func(name.clone()));
                return ty.clone();
            }
            if self.fns.contains_key(name) {
                self.resolutions.insert(id, Res::Func(name.clone()));
                let rec = self.fns.get(name).unwrap();
                let ps: Vec<Ty> = rec.params.iter().map(|(_, t)| t.clone()).collect();
                return Ty::plain(BaseTy::Func(ps, Box::new(rec.ret.clone())));
            }
            if let Some(Name::Builtin(b)) = self.names.get(name).cloned() {
                self.resolutions.insert(id, Res::Builtin(b.to_string()));
                return self.builtin_value(b, expected, path.span);
            }
            if let Some(variants) = self.enums.get(name) {
                let _ = variants;
            }
            self.error(Code::E002, path.span, format!("unknown name `{name}`"));
            return Ty::error();
        }
        // Type::associated or Enum::Variant or module::item.
        if path.segments.len() >= 2 {
            let first = &path.segments[0].name;
            let second = &path.segments[1].name;
            if let Some(variants) = self.enums.get(first).cloned() {
                if let Some((_, fields)) = variants.iter().find(|(n, _)| n == second) {
                    self.resolutions.insert(
                        id,
                        Res::Variant {
                            en: first.clone(),
                            var: second.clone(),
                        },
                    );
                    if fields.is_empty() {
                        return Ty::plain(BaseTy::Enum(first.clone()));
                    }
                    // Constructor used as a value; the call site types the payload.
                    return Ty::plain(BaseTy::Func(
                        fields.clone(),
                        Box::new(Ty::plain(BaseTy::Enum(first.clone()))),
                    ));
                }
            }
            if let Some(Name::Module(m)) = self.names.get(first).cloned() {
                let full = format!("{m}::{second}");
                self.resolutions.insert(id, Res::Builtin(full.clone()));
                return Ty::plain(BaseTy::Func(Vec::new(), Box::new(Ty::unit())));
            }
            if let Some(Name::Legacy(m)) = self.names.get(first).cloned() {
                let full = format!("{m}::{second}");
                self.resolutions.insert(id, Res::Builtin(full));
                return Ty::plain(BaseTy::Func(Vec::new(), Box::new(Ty::unit())));
            }
            if self.names.contains_key(first)
                || self.structs.contains_key(first)
                || first == "List"
                || first == "Kem"
                || first == "Sig"
                || first == "Email"
                || first == "Url"
                || first == "Id"
            {
                let full = format!("{first}::{second}");
                self.resolutions.insert(id, Res::Builtin(full));
                return Ty::plain(BaseTy::Func(Vec::new(), Box::new(Ty::unit())));
            }
        }
        self.error(Code::E002, path.span, "unknown path");
        Ty::error()
    }

    fn builtin_value(&mut self, name: &str, expected: Option<&Ty>, span: Span) -> Ty {
        match name {
            "ctor.None" => match expected {
                Some(Ty {
                    base: BaseTy::Option(t),
                    label,
                    ..
                }) => Ty::new(BaseTy::Option(t.clone()), *label),
                _ => {
                    self.error(
                        Code::E003,
                        span,
                        "`None` needs a type annotation, for example `Option<i64>`",
                    );
                    Ty::error()
                }
            },
            "ctor.Ok" | "ctor.Err" | "ctor.Some" | "declassify" | "endorse" => {
                Ty::plain(BaseTy::Func(Vec::new(), Box::new(Ty::unit())))
            }
            _ => Ty::error(),
        }
    }

    fn infer_call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        // Path-sensitive calls: builtins, constructors, user functions, variants.
        if let ExprKind::Path(path) = &callee.kind {
            if let Some(ty) = self.call_path(path, callee.id, args, expected, span) {
                return ty;
            }
        }
        let fty = self.infer(callee, None);
        let BaseTy::Func(params, ret) = fty.base.clone() else {
            if fty.is_error() {
                return Ty::error();
            }
            self.error(Code::E003, callee.span, "this value is not callable");
            return Ty::error();
        };
        self.check_args(&params, args, span);
        (*ret).clone().under_pc(self.pc, span)
    }

    fn call_path(
        &mut self,
        path: &Path,
        callee_id: u32,
        args: &[Expr],
        expected: Option<&Ty>,
        span: Span,
    ) -> Option<Ty> {
        let segs: Vec<&str> = path.segments.iter().map(|s| s.name.as_str()).collect();
        if segs.len() == 1 {
            let name = segs[0];
            if let Some(b) = self.lookup_bind(name) {
                let _ = b;
                return None; // ordinary value call, handled by infer_call
            }
            if matches!(name, "Ok" | "Err" | "Some" | "None") {
                self.resolutions
                    .insert(callee_id, Res::Constructor(name.to_string()));
                return Some(self.call_ctor(name, args, expected, span));
            }
            if name == "declassify" || name == "endorse" {
                self.resolutions
                    .insert(callee_id, Res::Builtin(name.to_string()));
                return Some(self.call_downgrade(name, args, span));
            }
            if self.fns.contains_key(name) {
                self.resolutions
                    .insert(callee_id, Res::Func(name.to_string()));
                self.note_call(name, span);
                let rec = self.fns.get(name).unwrap();
                let params: Vec<Ty> = rec.params.iter().map(|(_, t)| t.clone()).collect();
                let ret = rec.ret.clone();
                if params.len() != args.len() {
                    self.error(
                        Code::E004,
                        span,
                        format!(
                            "`{name}` expects {} arguments, found {}",
                            params.len(),
                            args.len()
                        ),
                    );
                    return Some(Ty::error());
                }
                for (p, a) in params.iter().zip(args) {
                    let got = self.infer(a, Some(p));
                    self.flow_at(a.span, &got, p, Some(&format!("a parameter of `{name}`")));
                }
                return Some(ret.under_pc(self.pc, span));
            }
            if let Some(Name::Builtin(b)) = self.names.get(name).cloned() {
                self.resolutions
                    .insert(callee_id, Res::Builtin(b.to_string()));
                return Some(self.call_builtin(b, path, args, expected, span));
            }
        }
        if segs.len() == 2 {
            let (a, b) = (segs[0], segs[1]);
            if let Some(Name::Module(m)) = self.names.get(a).cloned() {
                let id = format!("{m}::{b}");
                self.resolutions.insert(callee_id, Res::Builtin(id.clone()));
                return Some(self.call_std(&id, args, expected, span));
            }
            if let Some(Name::Legacy(m)) = self.names.get(a).cloned() {
                let id = format!("{m}::{b}");
                self.resolutions.insert(callee_id, Res::Builtin(id.clone()));
                self.note_legacy(span, &id);
                return Some(self.call_legacy(&id, args, span));
            }
            if let Some(variants) = self.enums.get(a).cloned() {
                if let Some((_, fields)) = variants.iter().find(|(n, _)| n == b) {
                    self.resolutions.insert(
                        callee_id,
                        Res::Variant {
                            en: a.to_string(),
                            var: b.to_string(),
                        },
                    );
                    if fields.len() != args.len() {
                        self.error(
                            Code::E004,
                            span,
                            format!("variant `{a}::{b}` expects {} fields", fields.len()),
                        );
                        return Some(Ty::error());
                    }
                    for (f, arg) in fields.iter().zip(args) {
                        let got = self.infer(arg, Some(f));
                        self.flow_at(arg.span, &got, f, None);
                    }
                    return Some(Ty::plain(BaseTy::Enum(a.to_string())).under_pc(self.pc, span));
                }
            }
            let id = format!("{a}::{b}");
            self.resolutions.insert(callee_id, Res::Builtin(id.clone()));
            return Some(self.call_associated(&id, path, args, expected, span));
        }
        None
    }

    fn call_ctor(&mut self, name: &str, args: &[Expr], expected: Option<&Ty>, span: Span) -> Ty {
        match name {
            "Some" => {
                if args.len() != 1 {
                    self.error(Code::E004, span, "`Some` takes one argument");
                    return Ty::error();
                }
                let inner_expected = match expected {
                    Some(Ty {
                        base: BaseTy::Option(t),
                        ..
                    }) => Some(t.as_ref()),
                    _ => None,
                };
                let inner = self.infer(&args[0], inner_expected);
                Ty::new(BaseTy::Option(Box::new(inner.clone())), inner.label)
                    .under_pc(self.pc, span)
            }
            "None" => self.builtin_value("ctor.None", expected, span),
            "Ok" => {
                if args.len() != 1 {
                    self.error(Code::E004, span, "`Ok` takes one argument");
                    return Ty::error();
                }
                match expected {
                    Some(Ty {
                        base: BaseTy::Result(ok, err),
                        label,
                        ..
                    }) => {
                        let got = self.infer(&args[0], Some(ok));
                        self.flow_at(args[0].span, &got, ok, None);
                        Ty::new(BaseTy::Result(ok.clone(), err.clone()), *label)
                            .under_pc(self.pc, span)
                    }
                    _ => {
                        let got = self.infer(&args[0], None);
                        Ty::new(
                            BaseTy::Result(Box::new(got.clone()), Box::new(Ty::text())),
                            got.label,
                        )
                    }
                }
            }
            "Err" => {
                if args.len() != 1 {
                    self.error(Code::E004, span, "`Err` takes one argument");
                    return Ty::error();
                }
                match expected {
                    Some(Ty {
                        base: BaseTy::Result(ok, err),
                        label,
                        ..
                    }) => {
                        let got = self.infer(&args[0], Some(err));
                        self.flow_at(args[0].span, &got, err, None);
                        Ty::new(BaseTy::Result(ok.clone(), err.clone()), *label)
                    }
                    _ => {
                        let got = self.infer(&args[0], None);
                        Ty::new(
                            BaseTy::Result(Box::new(Ty::i64()), Box::new(got)),
                            Label::PUBLIC_TRUSTED,
                        )
                    }
                }
            }
            _ => Ty::error(),
        }
    }

    fn call_downgrade(&mut self, name: &str, args: &[Expr], span: Span) -> Ty {
        if args.len() != 2 {
            self.error(
                Code::E004,
                span,
                format!("`{name}` takes a value and a string reason"),
            );
            return Ty::error();
        }
        let cap_needed = if name == "declassify" {
            "Declassify"
        } else {
            "Endorse"
        };
        if !self.scope_has_cap(cap_needed) {
            let code = if name == "declassify" {
                Code::E204
            } else {
                Code::E205
            };
            self.error(
                code,
                span,
                format!("`{name}` needs a `{cap_needed}` capability in scope. Ask the host with `caps.{}()` and pass that value into this function", name),
            );
            return Ty::error();
        }
        let reason = match &args[1].kind {
            ExprKind::String(s) => s.clone(),
            _ => {
                self.error(
                    Code::E003,
                    args[1].span,
                    "the reason must be a string literal so it can be copied into the seal",
                );
                "<not a literal>".into()
            }
        };
        let got = self.infer(&args[0], None);
        let mut out = got.clone();
        if name == "declassify" {
            out.label.conf = Conf::Public;
            out.secret_origin = None;
            self.flows.push(FlowNote {
                kind: FlowNoteKind::Declassify,
                name: reason,
                span,
            });
            self.note_cap("Declassify", None, &["declassify"], span);
        } else {
            out.label.integ = Integ::Trusted;
            out.untrusted_origin = None;
            self.flows.push(FlowNote {
                kind: FlowNoteKind::Endorse,
                name: reason,
                span,
            });
            self.note_cap("Endorse", None, &["endorse"], span);
        }
        if self.pc.is_untrusted() {
            self.privileged_here(span, name);
        }
        out
    }

    fn call_std(&mut self, id: &str, args: &[Expr], expected: Option<&Ty>, span: Span) -> Ty {
        match id {
            "std.ct::verify_eq" => self.ct_verify(args, span),
            "std.ct::eq" | "std.ct::lt" => self.ct_cmp(id, args, span),
            "std.ct::select" => self.ct_select(args, span),
            "std.ct::zeroize" => {
                self.infer_args(args);
                Ty::unit()
            }
            "std.aead::seal" => self.aead_seal(args, span),
            "std.aead::open" => self.aead_open(args, span),
            "std.hash::sha3_256" | "std.hash::sha256" => self.hash_call(args, span),
            "std.hash::hkdf_sha3" => self.hkdf_call(args, span),
            "std.agent::pick_from" => self.pick_from(args, span),
            _ => {
                let _ = expected;
                self.error(
                    Code::E002,
                    span,
                    format!("unknown standard function `{id}`"),
                );
                Ty::error()
            }
        }
    }

    fn call_associated(
        &mut self,
        id: &str,
        path: &Path,
        args: &[Expr],
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        match id {
            "List::new" => {
                let elem = path
                    .segments
                    .first()
                    .and_then(|s| s.args.first())
                    .and_then(|a| match a {
                        GenericArg::Type(t) => Some(self.lower_type(t)),
                        _ => None,
                    })
                    .or_else(|| match expected {
                        Some(Ty {
                            base: BaseTy::List(t),
                            ..
                        }) => Some((**t).clone()),
                        _ => None,
                    });
                match elem {
                    Some(t) => Ty::plain(BaseTy::List(Box::new(t))),
                    None => Ty::plain(BaseTy::ListHole),
                }
            }
            "Kem::default" | "Kem::hybrid" | "Kem::ml_kem_768" | "Kem::ml_kem_1024" => {
                self.note_kem(id, span);
                Ty::plain(BaseTy::Kem)
            }
            "Kem::generate" => {
                self.note_kem("Kem::generate", span);
                self.require_rand_arg(args);
                let sk = Ty::new(BaseTy::KemSecret, Label::SECRET);
                let pk = Ty::plain(BaseTy::KemPublic);
                Ty::plain(BaseTy::Tuple(vec![sk, pk]))
            }
            "Sig::default" | "Sig::ml_dsa_44" | "Sig::ml_dsa_65" | "Sig::ml_dsa_87"
            | "Sig::slh_dsa" => {
                self.note_sig(id, span);
                Ty::plain(BaseTy::Sig)
            }
            "Sig::generate" => {
                self.note_sig("Sig::generate", span);
                self.require_rand_arg(args);
                Ty::plain(BaseTy::Tuple(vec![
                    Ty::new(BaseTy::SigSecret, Label::SECRET),
                    Ty::plain(BaseTy::SigPublic),
                ]))
            }
            "Email::literal" | "Url::literal" | "Id::literal" => self.smart_literal(id, args, span),
            "Email::parse" | "Url::parse" | "Id::parse" => self.smart_parse(id, args, span),
            _ => {
                let _ = expected;
                self.error(Code::E002, span, format!("unknown function `{id}`"));
                Ty::error()
            }
        }
    }

    fn call_legacy(&mut self, id: &str, args: &[Expr], span: Span) -> Ty {
        let _ = (id, span);
        self.infer_args(args);
        Ty::bytes()
    }

    fn call_builtin(
        &mut self,
        id: &str,
        _path: &Path,
        args: &[Expr],
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        self.call_std(id, args, expected, span)
    }

    #[allow(clippy::too_many_arguments)]
    fn infer_method(
        &mut self,
        receiver: &Expr,
        name: &str,
        name_span: Span,
        type_args: &[GenericArg],
        args: &[Expr],
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        let recv = self.infer(receiver, None);
        if recv.is_error() {
            return Ty::error();
        }
        match (&recv.base, name) {
            (BaseTy::Caps, "console") => self.derive_cap(
                "Console",
                None,
                &["write"],
                span,
                Ty::plain(BaseTy::Console),
            ),
            (BaseTy::Caps, "model") => {
                self.derive_cap("Model", None, &["ask"], span, Ty::plain(BaseTy::Model))
            }
            (BaseTy::Caps, "rand") => {
                self.derive_cap("Rand", None, &["bytes"], span, Ty::plain(BaseTy::Rand))
            }
            (BaseTy::Caps, "clock") => {
                self.derive_cap("Clock", None, &["read"], span, Ty::plain(BaseTy::Clock))
            }
            (BaseTy::Caps, "declassify") => self.derive_cap(
                "Declassify",
                None,
                &["declassify"],
                span,
                Ty::plain(BaseTy::Declassify),
            ),
            (BaseTy::Caps, "endorse") => self.derive_cap(
                "Endorse",
                None,
                &["endorse"],
                span,
                Ty::plain(BaseTy::Endorse),
            ),
            (BaseTy::Caps, "fs_read" | "fs_write" | "net" | "tool") => {
                self.derive_scoped(name, type_args, span)
            }
            (BaseTy::Console, "println" | "print") => self.sink_text(name, args, false, span),
            (BaseTy::FsRead(scope), "read") => {
                self.note_cap("FsRead", Some(scope.clone()), &["read"], span);
                self.check_path_arg(args, scope, span);
                let mut t = Ty::bytes();
                t.label.integ = Integ::Untrusted;
                t.untrusted_origin = Some(Origin {
                    span,
                    name: Some("file contents".into()),
                });
                t
            }
            (BaseTy::FsRead(scope), "read_text") => {
                self.note_cap("FsRead", Some(scope.clone()), &["read"], span);
                self.check_path_arg(args, scope, span);
                let mut t = Ty::text();
                t.label.integ = Integ::Untrusted;
                t.untrusted_origin = Some(Origin {
                    span,
                    name: Some("file contents".into()),
                });
                t
            }
            (BaseTy::FsRead(scope), "list") => {
                self.note_cap("FsRead", Some(scope.clone()), &["list"], span);
                // Directory entries are treated as metadata of the capability.
                Ty::plain(BaseTy::List(Box::new(Ty::text())))
            }
            (BaseTy::FsWrite(scope), "write") => {
                self.privileged_here(span, "FsWrite.write");
                self.note_cap("FsWrite", Some(scope.clone()), &["write"], span);
                if args.len() != 2 {
                    self.error(Code::E004, span, "`write` takes a path and bytes");
                    return Ty::error();
                }
                self.check_one_path(&args[0], scope);
                let data = self.infer(&args[1], Some(&Ty::bytes()));
                self.flow_at(args[1].span, &data, &Ty::bytes(), Some("FsWrite.write"));
                Ty::unit()
            }
            (BaseTy::Net(scope), "send") => {
                self.privileged_here(span, "Net.send");
                self.note_cap("Net", Some(scope.clone()), &["send"], span);
                if let Some(a) = args.first() {
                    let got = self.infer(a, Some(&Ty::bytes()));
                    self.flow_at(a.span, &got, &Ty::bytes(), Some("Net.send"));
                }
                Ty::unit()
            }
            (BaseTy::Net(scope), "recv") => {
                self.note_cap("Net", Some(scope.clone()), &["recv"], span);
                let mut t = Ty::bytes();
                t.label.integ = Integ::Untrusted;
                t
            }
            (BaseTy::Tool(scope), "call") => self.tool_call(scope, args, span),
            (BaseTy::Model, "ask") => self.model_ask(args, span),
            (BaseTy::Rand, "secret_bytes") => self.rand_bytes(type_args, true, span),
            (BaseTy::Rand, "public_bytes") => self.rand_bytes(type_args, false, span),
            (BaseTy::Clock, "unix_ms") => {
                self.note_cap("Clock", None, &["read"], span);
                Ty::i64()
            }
            (BaseTy::Kem, "encaps") => self.kem_encaps(args, span),
            (BaseTy::Kem, "decaps") => self.kem_decaps(args, span),
            (BaseTy::Sig, "sign") => self.sig_sign(args, span),
            (BaseTy::Sig, "verify") => {
                self.infer_args(args);
                Ty::bool()
            }
            (BaseTy::Text, "to_bytes") => carry(&recv, BaseTy::Bytes).under_pc(self.pc, span),
            (BaseTy::Text, "split_whitespace") => {
                carry(&recv, BaseTy::List(Box::new(carry(&recv, BaseTy::Text))))
            }
            (BaseTy::Text, "len")
            | (BaseTy::Bytes, "len")
            | (BaseTy::List(_), "len")
            | (BaseTy::Array(_, _), "len")
            | (BaseTy::ListHole, "len") => self.len_of(&recv),
            (BaseTy::Bytes, "to_hex") | (BaseTy::Array(_, _), "to_hex") => {
                carry(&recv, BaseTy::Text)
            }
            (BaseTy::Int(_), "to_text")
            | (BaseTy::IntLit(_), "to_text")
            | (BaseTy::Bool, "to_text") => carry(&recv, BaseTy::Text),
            (BaseTy::List(_), "push") | (BaseTy::ListHole, "push") => {
                self.list_push(receiver, &recv, args, elem_if(&recv), span)
            }
            (BaseTy::List(elem), "get") => {
                if let Some(i) = args.first() {
                    let idx = self.infer(i, None);
                    if idx.label.is_secret() {
                        self.error(Code::E102, i.span, "secret value used as an index");
                    }
                    let mut t = (**elem).clone();
                    if idx.label.is_untrusted() {
                        t.label.integ = Integ::Untrusted;
                    }
                    return Ty::plain(BaseTy::Option(Box::new(t)));
                }
                Ty::error()
            }
            (BaseTy::KemPublic, "to_bytes") | (BaseTy::Bytes, "to_bytes") => {
                Ty::new(BaseTy::Bytes, recv.label)
            }
            _ => {
                let _ = (name_span, expected);
                self.error(
                    Code::E003,
                    name_span,
                    format!("no method `{name}` on `{}`", recv.render()),
                );
                Ty::error()
            }
        }
    }

    fn derive_cap(
        &mut self,
        cap: &str,
        scope: Option<String>,
        ops: &[&str],
        span: Span,
        ty: Ty,
    ) -> Ty {
        self.note_cap(cap, scope, ops, span);
        ty
    }

    fn derive_scoped(&mut self, name: &str, type_args: &[GenericArg], span: Span) -> Ty {
        let raw = match type_args.first() {
            Some(GenericArg::Str(s, _)) => s.clone(),
            Some(_) => {
                self.error(
                    Code::E203,
                    span,
                    "capability scope must be a string literal",
                );
                return Ty::error();
            }
            None => {
                self.error(
                    Code::E004,
                    span,
                    "this capability needs a scope, written `::<\"...\">()`",
                );
                return Ty::error();
            }
        };
        if self.profile.is_sealed() && !matches!(type_args.first(), Some(GenericArg::Str(_, _))) {
            self.error(
                Code::E203,
                span,
                "sealed and plan profiles require a constant scope",
            );
        }
        let scope = match normalize_scope(&raw) {
            Ok(s) => s,
            Err(msg) => {
                self.error(Code::E206, span, msg);
                return Ty::error();
            }
        };
        let (cap, ty) = match name {
            "fs_read" => ("FsRead", Ty::plain(BaseTy::FsRead(scope.clone()))),
            "fs_write" => ("FsWrite", Ty::plain(BaseTy::FsWrite(scope.clone()))),
            "net" => ("Net", Ty::plain(BaseTy::Net(scope.clone()))),
            "tool" => ("Tool", Ty::plain(BaseTy::Tool(scope.clone()))),
            _ => return Ty::error(),
        };
        if let Some(grant) = &self.opts.grant {
            if !grant.covers_cap(cap, Some(&scope)) {
                self.error(
                    Code::E209,
                    span,
                    format!("`{cap}<\"{scope}\">` is outside the host grant"),
                );
            }
        }
        let ops: &[&str] = match cap {
            "FsRead" => &["read", "list"],
            "FsWrite" => &["write"],
            "Net" => &["send", "recv"],
            _ => &["call"],
        };
        self.note_cap(cap, Some(scope), ops, span);
        ty
    }

    fn sink_text(&mut self, name: &str, args: &[Expr], privileged: bool, span: Span) -> Ty {
        if privileged {
            self.privileged_here(span, name);
        }
        self.note_cap("Console", None, &["write"], span);
        if let Some(a) = args.first() {
            let got = self.infer(a, None);
            let got = match &got.base {
                BaseTy::Text => got,
                BaseTy::Int(_) | BaseTy::IntLit(_) | BaseTy::Bool => {
                    Ty::new(BaseTy::Text, got.label)
                }
                _ => {
                    let coerced = Ty::text();
                    self.flow_at(a.span, &got, &coerced, Some("Console.println"));
                    got
                }
            };
            let public_text = Ty::text();
            self.flow_at(a.span, &got, &public_text, Some("`Console.println`"));
        }
        Ty::unit()
    }

    fn check_path_arg(&mut self, args: &[Expr], scope: &str, span: Span) {
        if args.len() != 1 {
            self.error(Code::E004, span, "expected a path argument");
            return;
        }
        self.check_one_path(&args[0], scope);
    }

    fn check_one_path(&mut self, arg: &Expr, _scope: &str) {
        let got = self.infer(arg, Some(&Ty::text()));
        // A path may be untrusted; the runtime confines it to the scope.
        // It must not be secret: the path would otherwise steer a public lookup.
        if got.label.is_secret() {
            self.flow_at(arg.span, &got, &Ty::text(), Some("a filesystem path"));
        }
        if let ExprKind::String(s) = &arg.kind {
            if normalize_scope_file(s).is_err() {
                self.error(
                    Code::E206,
                    arg.span,
                    "path escapes its scope (`..` or an absolute path)",
                );
            }
        }
    }

    fn tool_call(&mut self, scope: &str, args: &[Expr], span: Span) -> Ty {
        self.privileged_here(span, "Tool.call");
        self.note_cap("Tool", Some(scope.to_string()), &["call"], span);
        if scope == "mail.send" {
            if args.len() != 2 {
                self.error(
                    Code::E004,
                    span,
                    "`mail.send` takes a trusted recipient and a body",
                );
                return Ty::error();
            }
            let to = self.infer(&args[0], Some(&Ty::plain(BaseTy::Email)));
            let trusted_email = Ty::plain(BaseTy::Email);
            self.flow_at(
                args[0].span,
                &to,
                &trusted_email,
                Some("trusted parameter `to` of `mail.send`"),
            );
            let body = self.infer(&args[1], None);
            if body.label.is_secret() {
                self.flow_at(args[1].span, &body, &Ty::text(), Some("`mail.send` body"));
            }
            return Ty::unit();
        }
        if let Some(a) = args.first() {
            let got = self.infer(a, Some(&Ty::text()));
            self.flow_at(a.span, &got, &Ty::text(), Some("Tool.call"));
        }
        Ty::unit()
    }

    fn model_ask(&mut self, args: &[Expr], span: Span) -> Ty {
        self.note_cap("Model", None, &["ask"], span);
        if args.len() != 2 {
            self.error(Code::E004, span, "`ask` takes a prompt and an input");
            return Ty::error();
        }
        let prompt = self.infer(&args[0], Some(&Ty::text()));
        let prompt = prompt.under_pc(self.pc, args[0].span);
        self.flow_at(
            args[0].span,
            &prompt,
            &Ty::text(),
            Some("the trusted prompt of `model.ask`"),
        );
        let input = self.infer(&args[1], None);
        if input.label.is_secret() {
            self.flow_at(args[1].span, &input, &Ty::text(), Some("`model.ask`"));
        }
        let mut out = Ty::text();
        out.label.integ = Integ::Untrusted;
        out.label.conf = input.label.conf;
        out.untrusted_origin = Some(Origin {
            span,
            name: Some("model output".into()),
        });
        if input.label.is_secret() {
            out.secret_origin = input.secret_origin.clone();
        }
        out
    }

    fn rand_bytes(&mut self, type_args: &[GenericArg], secret: bool, span: Span) -> Ty {
        self.note_cap("Rand", None, &["bytes"], span);
        let n = match type_args.first() {
            Some(GenericArg::Int(v, _)) => *v as u64,
            _ => {
                self.error(
                    Code::E004,
                    span,
                    "expected a constant length, as in `secret_bytes::<32>()`",
                );
                0
            }
        };
        let elem = Ty::plain(BaseTy::Int(IntKind::U8));
        let mut ty = Ty::plain(BaseTy::Array(Box::new(elem), n));
        if secret {
            ty.label.conf = Conf::Secret;
            ty.secret_origin = Some(Origin {
                span,
                name: Some("rand.secret_bytes".into()),
            });
        }
        ty
    }

    fn kem_encaps(&mut self, args: &[Expr], span: Span) -> Ty {
        self.infer_args(args);
        self.flows.push(FlowNote {
            kind: FlowNoteKind::TrustedDeclassifier,
            name: "kem::encaps".into(),
            span,
        });
        let shared = Ty::new(
            BaseTy::Array(Box::new(Ty::plain(BaseTy::Int(IntKind::U8))), 32),
            Label::SECRET,
        );
        Ty::plain(BaseTy::Tuple(vec![Ty::bytes(), shared]))
    }

    fn kem_decaps(&mut self, args: &[Expr], span: Span) -> Ty {
        let _ = span;
        self.infer_args(args);
        Ty::new(
            BaseTy::Array(Box::new(Ty::plain(BaseTy::Int(IntKind::U8))), 32),
            Label::SECRET,
        )
    }

    fn sig_sign(&mut self, args: &[Expr], span: Span) -> Ty {
        self.infer_args(args);
        self.flows.push(FlowNote {
            kind: FlowNoteKind::TrustedDeclassifier,
            name: "sig::sign".into(),
            span,
        });
        Ty::bytes()
    }

    fn len_of(&self, recv: &Ty) -> Ty {
        let mut t = Ty::u64();
        if recv.label.is_secret() {
            t.label.conf = Conf::Secret;
            t.secret_origin = recv.secret_origin.clone();
        }
        // Lengths are a public size channel for integrity. See the limits note.
        t
    }

    fn list_push(
        &mut self,
        receiver: &Expr,
        recv: &Ty,
        args: &[Expr],
        elem: Option<Ty>,
        span: Span,
    ) -> Ty {
        if args.len() != 1 {
            self.error(Code::E004, span, "`push` takes one value");
            return Ty::error();
        }
        let got = self.infer(&args[0], elem.as_ref());
        if let Some(elem) = elem {
            self.flow_at(args[0].span, &got, &elem, None);
        } else if let ExprKind::Path(p) = &receiver.kind {
            if p.segments.len() == 1 {
                let name = &p.segments[0].name;
                self.refine_list(name, &got);
            }
        }
        let _ = recv;
        Ty::unit()
    }

    fn refine_list(&mut self, name: &str, elem: &Ty) {
        for item in self.scope.iter_mut().rev() {
            if let ScopeItem::Bind(b) = item {
                if b.name == name && matches!(b.ty.base, BaseTy::ListHole) {
                    b.ty.base = BaseTy::List(Box::new(elem.clone()));
                    return;
                }
            }
        }
    }

    fn ct_verify(&mut self, args: &[Expr], span: Span) -> Ty {
        if args.len() != 2 {
            self.error(Code::E004, span, "`verify_eq` takes two arrays");
            return Ty::error();
        }
        let a = self.infer(&args[0], None);
        let b = self.infer(&args[1], None);
        if !same_width(&a, &b) {
            self.error(
                Code::E003,
                span,
                "`verify_eq` needs two byte arrays of the same length",
            );
        }
        self.flows.push(FlowNote {
            kind: FlowNoteKind::TrustedDeclassifier,
            name: "ct::verify_eq".into(),
            span,
        });
        Ty::bool()
    }

    fn ct_cmp(&mut self, _id: &str, args: &[Expr], span: Span) -> Ty {
        self.infer_args(args);
        let mut t = Ty::bool();
        t.label.conf = Conf::Secret;
        t.secret_origin = Some(Origin {
            span,
            name: Some("ct comparison".into()),
        });
        t
    }

    fn ct_select(&mut self, args: &[Expr], span: Span) -> Ty {
        if args.len() != 3 {
            self.error(
                Code::E004,
                span,
                "`select` takes a condition and two values",
            );
            return Ty::error();
        }
        let c = self.infer(&args[0], None);
        let a = self.infer(&args[1], None);
        let b = self.infer(&args[2], None);
        let label = c.label.join(a.label).join(b.label);
        let mut t = a.clone().with_label(label);
        if c.label.is_secret() {
            t.label.conf = Conf::Secret;
        }
        t = propagate(&t, &[c, a, b]);
        let _ = span;
        t
    }

    fn aead_seal(&mut self, args: &[Expr], span: Span) -> Ty {
        self.infer_args(args);
        self.flows.push(FlowNote {
            kind: FlowNoteKind::TrustedDeclassifier,
            name: "aead::seal".into(),
            span,
        });
        self.note_crypto(span, "ChaCha20-Poly1305", true, "aead::seal");
        Ty::bytes()
    }

    fn aead_open(&mut self, args: &[Expr], span: Span) -> Ty {
        let _ = span;
        self.infer_args(args);
        let inner = Ty::new(BaseTy::Bytes, Label::SECRET);
        Ty::plain(BaseTy::Result(Box::new(inner), Box::new(Ty::text())))
    }

    fn hash_call(&mut self, args: &[Expr], span: Span) -> Ty {
        let t = if let Some(a) = args.first() {
            let got = self.infer(a, Some(&Ty::bytes()));
            let mut out = Ty::plain(BaseTy::Array(
                Box::new(Ty::plain(BaseTy::Int(IntKind::U8))),
                32,
            ));
            out.label = got.label;
            out.secret_origin = got.secret_origin.clone();
            out.untrusted_origin = got.untrusted_origin.clone();
            out
        } else {
            Ty::error()
        };
        self.note_crypto(span, "SHA3-256", true, "hash");
        let _ = span;
        t
    }

    fn hkdf_call(&mut self, args: &[Expr], span: Span) -> Ty {
        self.infer_args(args);
        self.note_crypto(span, "HKDF-SHA3-256", true, "hash::hkdf_sha3");
        Ty::new(
            BaseTy::Array(Box::new(Ty::plain(BaseTy::Int(IntKind::U8))), 32),
            Label::SECRET,
        )
    }

    fn pick_from(&mut self, args: &[Expr], span: Span) -> Ty {
        if args.len() != 2 {
            self.error(
                Code::E004,
                span,
                "`pick_from` takes an allow-list and a hint",
            );
            return Ty::error();
        }
        if !is_literal_list(&args[0]) {
            self.error(
                Code::E003,
                args[0].span,
                "`pick_from` options must be a list literal written in the program",
            );
        }
        self.infer(&args[0], None);
        self.infer(&args[1], None);
        self.flows.push(FlowNote {
            kind: FlowNoteKind::TrustedEndorser,
            name: "agent::pick_from".into(),
            span,
        });
        Ty::text()
    }

    fn smart_literal(&mut self, id: &str, args: &[Expr], span: Span) -> Ty {
        if args.len() != 1 {
            self.error(Code::E004, span, "expected one string literal");
            return Ty::error();
        }
        match &args[0].kind {
            ExprKind::String(s) => {
                if id.starts_with("Email") && !looks_like_email(s) {
                    self.error(Code::E003, args[0].span, "not a plausible email address");
                }
            }
            _ => self.error(
                Code::E003,
                args[0].span,
                "smart constructors take a string literal from the program",
            ),
        }
        let base = if id.starts_with("Email") {
            BaseTy::Email
        } else if id.starts_with("Url") {
            BaseTy::Url
        } else {
            BaseTy::Id
        };
        Ty::plain(base)
    }

    fn smart_parse(&mut self, id: &str, args: &[Expr], span: Span) -> Ty {
        let got = if let Some(a) = args.first() {
            self.infer(a, Some(&Ty::text()))
        } else {
            Ty::text()
        };
        let base = if id.starts_with("Email") {
            BaseTy::Email
        } else if id.starts_with("Url") {
            BaseTy::Url
        } else {
            BaseTy::Id
        };
        let mut t = Ty::new(base, got.label);
        t.untrusted_origin = got.untrusted_origin.clone();
        t.secret_origin = got.secret_origin.clone();
        let _ = span;
        t
    }

    fn infer_if(
        &mut self,
        cond: &Expr,
        then_b: &Block,
        else_b: Option<&Expr>,
        expected: Option<&Ty>,
    ) -> Ty {
        let c = self.infer(cond, Some(&Ty::bool()));
        self.secret_branch(&c, cond.span);
        let saved = self.pc;
        if c.label.is_untrusted() {
            self.pc.integ = Integ::Untrusted;
        }
        let t = self.check_block(then_b, expected);
        let e = if let Some(else_b) = else_b {
            self.infer(else_b, expected.or(Some(&t)))
        } else {
            Ty::unit()
        };
        self.pc = saved;
        if else_b.is_none() {
            return Ty::unit();
        }
        let mut label = t.label.join(e.label);
        if c.label.is_untrusted() {
            label.integ = Integ::Untrusted;
        }
        let mut out = t.clone().with_label(label);
        if c.label.is_untrusted() {
            out.untrusted_origin = c.untrusted_origin.clone().or(out.untrusted_origin);
        }
        out = propagate(&out, &[t, e]);
        out
    }

    fn infer_match(
        &mut self,
        scrut: &Expr,
        arms: &[mohar_syntax::Arm],
        expected: Option<&Ty>,
    ) -> Ty {
        let scrut_ty = self.infer(scrut, None);
        self.secret_branch(&scrut_ty, scrut.span);
        if arms.is_empty() {
            self.error(Code::E006, scrut.span, "match has no arms");
            return Ty::error();
        }
        let saved = self.pc;
        if scrut_ty.label.is_untrusted() {
            self.pc.integ = Integ::Untrusted;
        }
        let mut acc: Option<Ty> = None;
        for arm in arms {
            let mark = self.scope.len();
            self.bind_pattern(&arm.pat, &scrut_ty);
            let t = self.infer(&arm.body, expected.or(acc.as_ref()));
            self.scope.truncate(mark);
            acc = Some(match acc {
                None => t,
                Some(prev) => {
                    let label = prev.label.join(t.label);
                    let mut out = prev.with_label(label);
                    out = propagate(&out, std::slice::from_ref(&t));
                    out
                }
            });
        }
        self.pc = saved;
        self.check_exhaust(&scrut_ty, arms, scrut.span);
        let mut out = acc.unwrap_or_else(Ty::error);
        if scrut_ty.label.is_untrusted() {
            out.label.integ = Integ::Untrusted;
            out.untrusted_origin = scrut_ty.untrusted_origin.clone().or(out.untrusted_origin);
        }
        out
    }

    fn infer_lambda(
        &mut self,
        params: &[mohar_syntax::LambdaParam],
        body: &Expr,
        expected: Option<&Ty>,
        span: Span,
    ) -> Ty {
        let expected_params: Option<Vec<Ty>> = match expected {
            Some(Ty {
                base: BaseTy::Func(ps, _),
                ..
            }) => Some(ps.clone()),
            _ => None,
        };
        self.scope.push(ScopeItem::Barrier);
        let mut pty = Vec::new();
        for (i, p) in params.iter().enumerate() {
            let ty = if let Some(ann) = &p.ty {
                self.lower_type(ann)
            } else if let Some(eps) = &expected_params {
                eps.get(i).cloned().unwrap_or_else(|| {
                    self.error(Code::E003, p.span, "lambda parameter needs a type");
                    Ty::error()
                })
            } else {
                self.error(Code::E003, p.span, "lambda parameter needs a type");
                Ty::error()
            };
            pty.push(ty.clone());
            self.scope.push(ScopeItem::Bind(Bind {
                name: p.name.clone(),
                ty,
                mutable: false,
                span: p.span,
            }));
        }
        let expected_ret = match expected {
            Some(Ty {
                base: BaseTy::Func(_, r),
                ..
            }) => Some(r.as_ref()),
            _ => None,
        };
        let ret = self.infer(body, expected_ret);
        // Drop params and the barrier.
        for _ in params {
            self.scope.pop();
        }
        self.scope.pop();
        let _ = span;
        Ty::plain(BaseTy::Func(pty, Box::new(ret)))
    }

    fn infer_field(&mut self, base: &Expr, name: &str, name_span: Span) -> Ty {
        let recv = self.infer(base, None);
        let BaseTy::Struct(sn) = &recv.base else {
            self.error(
                Code::E003,
                name_span,
                format!("`{}` has no field `{name}`", recv.render()),
            );
            return Ty::error();
        };
        let Some(fields) = self.structs.get(sn).cloned() else {
            return Ty::error();
        };
        let Some((_, fty)) = fields.iter().find(|(n, _)| n == name) else {
            self.error(
                Code::E003,
                name_span,
                format!("struct `{sn}` has no field `{name}`"),
            );
            return Ty::error();
        };
        let mut t = fty.clone();
        t.label = t.label.join(recv.label);
        t = propagate(&t, &[recv]);
        t
    }

    fn infer_index(&mut self, base: &Expr, index: &Expr) -> Ty {
        let recv = self.infer(base, None);
        let idx = self.infer(index, None);
        if idx.label.is_secret() {
            self.error(Code::E102, index.span, "secret value used as an index");
        }
        if matches!(&recv.base, BaseTy::Text) && recv.label.is_secret() {
            self.error(
                Code::E102,
                index.span,
                "indexing a secret Text is rejected; it is neither a byte index nor a scalar index",
            );
        }
        let mut elem = match &recv.base {
            BaseTy::Array(t, _) | BaseTy::List(t) => (**t).clone(),
            BaseTy::Error => return Ty::error(),
            _ => {
                self.error(
                    Code::E003,
                    base.span,
                    "only arrays and lists can be indexed",
                );
                return Ty::error();
            }
        };
        elem.label = elem.label.join(recv.label);
        if idx.label.is_untrusted() {
            elem.label.integ = Integ::Untrusted;
        }
        elem
    }

    fn infer_try(&mut self, inner: &Expr, span: Span) -> Ty {
        let got = self.infer(inner, None);
        match &got.base {
            BaseTy::Result(ok, err) => {
                if let BaseTy::Result(_, fret) = &self.ret_ty.base {
                    if fret.render() != err.render() && !fret.is_error() {
                        self.error(
                            Code::E003,
                            span,
                            "the error type of `?` does not match the function's Result",
                        );
                    }
                } else if !matches!(self.ret_ty.base, BaseTy::Error) {
                    self.error(
                        Code::E003,
                        span,
                        "`?` on a Result requires the function to return a Result",
                    );
                }
                ok.as_ref().clone()
            }
            BaseTy::Option(ok) => {
                if !matches!(self.ret_ty.base, BaseTy::Option(_) | BaseTy::Error) {
                    self.error(
                        Code::E003,
                        span,
                        "`?` on an Option requires the function to return an Option",
                    );
                }
                ok.as_ref().clone()
            }
            BaseTy::Error => Ty::error(),
            _ => {
                self.error(Code::E003, span, "`?` expects a Result or an Option");
                Ty::error()
            }
        }
    }

    fn infer_unary(&mut self, op: UnOp, inner: &Expr) -> Ty {
        let t = self.infer(inner, None);
        match op {
            UnOp::Not => {
                if !matches!(t.base, BaseTy::Bool | BaseTy::Error) {
                    self.error(Code::E003, inner.span, "`!` expects a bool");
                }
                t
            }
            UnOp::Neg => {
                if t.label.is_secret() {
                    // Negation of a secret integer is a constant-time bitwise op. Fine.
                }
                match t.base {
                    BaseTy::Int(IntKind::I64) | BaseTy::IntLit(_) | BaseTy::Error => t,
                    BaseTy::Int(_) => {
                        self.error(Code::E003, inner.span, "unary minus needs a signed integer");
                        Ty::error()
                    }
                    _ => {
                        self.error(Code::E003, inner.span, "unary minus expects an integer");
                        Ty::error()
                    }
                }
            }
        }
    }

    fn infer_binary(&mut self, op: BinOp, lhs: &Expr, rhs: &Expr, span: Span) -> Ty {
        if matches!(op, BinOp::And | BinOp::Or) {
            let l = self.infer(lhs, Some(&Ty::bool()));
            if l.label.is_secret() {
                self.error(
                    Code::E101,
                    span,
                    "short-circuit boolean operator depends on a secret value",
                );
            }
            let saved = self.pc;
            if l.label.is_untrusted() {
                self.pc.integ = Integ::Untrusted;
            }
            let r = self.infer(rhs, Some(&Ty::bool()));
            self.pc = saved;
            if r.label.is_secret() {
                self.error(
                    Code::E101,
                    span,
                    "short-circuit boolean operator depends on a secret value",
                );
            }
            let mut t = Ty::bool().with_label(l.label.join(r.label));
            t = propagate(&t, &[l, r]);
            return t.under_pc(self.pc, span);
        }
        let l = self.infer(lhs, None);
        let r = self.infer(rhs, None);
        if matches!(op, BinOp::Div | BinOp::Rem) && (l.label.is_secret() || r.label.is_secret()) {
            self.error(
                Code::E104,
                span,
                "division or remainder on a secret value is variable-time",
            );
            return Ty::error();
        }
        if matches!(op, BinOp::Shl | BinOp::Shr) && r.label.is_secret() {
            self.error(Code::E104, span, "a secret shift amount is variable-time");
            return Ty::error();
        }
        if matches!(
            op,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge
        ) {
            if (matches!(l.base, BaseTy::Text | BaseTy::Bytes) || matches!(r.base, BaseTy::Text))
                && (l.label.is_secret() || r.label.is_secret())
            {
                self.error(
                    Code::E104,
                    span,
                    "comparing secret text is variable-time; compare bytes with `std.ct`",
                );
                return Ty::error();
            }
            let mut t = Ty::bool().with_label(l.label.join(r.label));
            t = propagate(&t, &[l, r]);
            return t;
        }
        if op == BinOp::Range {
            if l.label.is_secret() || r.label.is_secret() {
                self.error(Code::E103, span, "loop bound depends on a secret value");
            }
            return Ty::plain(BaseTy::Tuple(vec![l, r]));
        }
        let kind = match unify_int(&l, &r) {
            Some(k) => k,
            None => {
                if !l.is_error() && !r.is_error() {
                    self.error(
                        Code::E003,
                        span,
                        format!(
                            "cannot apply `{}` to `{}` and `{}`",
                            op.as_str(),
                            l.render(),
                            r.render()
                        ),
                    );
                }
                return Ty::error();
            }
        };
        let mut t = Ty::new(BaseTy::Int(kind), l.label.join(r.label));
        t = propagate(&t, &[l, r]);
        t
    }

    fn infer_array(&mut self, xs: &[Expr], expected: Option<&Ty>, span: Span) -> Ty {
        if xs.is_empty() {
            if let Some(Ty {
                base: BaseTy::Array(t, n),
                ..
            }) = expected
            {
                return Ty::plain(BaseTy::Array(t.clone(), *n));
            }
            if let Some(Ty {
                base: BaseTy::List(t),
                ..
            }) = expected
            {
                return Ty::plain(BaseTy::List(t.clone()));
            }
            self.error(Code::E003, span, "an empty array needs a type annotation");
            return Ty::error();
        }
        let elem_expected = match expected {
            Some(Ty {
                base: BaseTy::Array(t, _),
                ..
            })
            | Some(Ty {
                base: BaseTy::List(t),
                ..
            }) => Some(t.as_ref()),
            _ => None,
        };
        let mut elems = Vec::new();
        for x in xs {
            elems.push(self.infer(x, elem_expected));
        }
        let label = elems
            .iter()
            .fold(Label::PUBLIC_TRUSTED, |a, t| a.join(t.label));
        let elem = elems[0].clone().with_label(label);
        if let Some(Ty {
            base: BaseTy::List(_),
            ..
        }) = expected
        {
            return Ty::new(BaseTy::List(Box::new(elem)), label);
        }
        Ty::new(BaseTy::Array(Box::new(elem), xs.len() as u64), label)
    }

    fn infer_struct(
        &mut self,
        path: &Path,
        fields: &[mohar_syntax::StructFieldInit],
        span: Span,
    ) -> Ty {
        let Some(name) = path.segments.first().map(|s| s.name.clone()) else {
            return Ty::error();
        };
        if matches!(
            name.as_str(),
            "Console"
                | "Caps"
                | "FsRead"
                | "Net"
                | "Tool"
                | "Rand"
                | "Model"
                | "Declassify"
                | "Endorse"
        ) {
            self.error(
                Code::E201,
                span,
                format!("capability `{name}` has no constructor; derive it from `caps`"),
            );
            return Ty::error();
        }
        let Some(def) = self.structs.get(&name).cloned() else {
            self.error(Code::E003, span, format!("unknown struct `{name}`"));
            return Ty::error();
        };
        let mut label = Label::PUBLIC_TRUSTED;
        let mut parts = Vec::new();
        for (fname, fty) in &def {
            let Some(init) = fields.iter().find(|f| &f.name == fname) else {
                self.error(Code::E003, span, format!("missing field `{fname}`"));
                continue;
            };
            let got = self.infer(&init.value, Some(fty));
            self.flow_at(init.span, &got, fty, None);
            label = label.join(got.label).join(fty.label);
            parts.push(got);
        }
        let mut t = Ty::new(BaseTy::Struct(name), label);
        t = propagate(&t, &parts);
        t.under_pc(self.pc, span)
    }

    fn secret_branch(&mut self, cond: &Ty, span: Span) {
        if cond.label.is_secret() {
            self.diags.push(
                Diagnostic::error(Code::E101, "branch condition depends on a secret value")
                    .with_primary(span, "")
                    .with_help("use std.ct::select or std.ct::verify_eq; secret-dependent branches leak timing"),
            );
        }
    }

    fn flow_at(&mut self, span: Span, from: &Ty, to: &Ty, sink: Option<&str>) {
        if from.is_error() || to.is_error() {
            return;
        }
        let from = concretize_toward(from.clone(), to);
        if !labels_ok(&from, to) {
            if from.label.is_secret() && !to.label.is_secret() {
                let sink_name = sink.unwrap_or("a public slot");
                let mut d = Diagnostic::error(
                    Code::E105,
                    format!("secret value flows to public sink {sink_name}"),
                )
                .with_primary(span, "");
                if let Some(origin) = &from.secret_origin {
                    let (line, _) = self.file.line_col(origin.span.start);
                    let who = origin.name.clone().unwrap_or_else(|| "the value".into());
                    d = d
                        .with_secondary(origin.span, "created secret here")
                        .with_note(format!("`{who}` created at line {line} as `secret`"));
                }
                d = d.with_help("encrypt it, or request the `Declassify` capability and say why");
                self.diags.push(d);
                return;
            }
            if from.label.is_untrusted() && !to.label.is_untrusted() {
                let sink_name = sink.unwrap_or("a trusted slot");
                let mut d = Diagnostic::error(
                    Code::E301,
                    format!("untrusted value flows into trusted parameter of {sink_name}"),
                )
                .with_primary(span, "");
                if let Some(origin) = &from.untrusted_origin {
                    d = d.with_secondary(origin.span, "untrusted from here");
                    if let Some(name) = &origin.name {
                        let (line, _) = self.file.line_col(origin.span.start);
                        d = d.with_note(format!("`{name}` is untrusted (line {line})"));
                    }
                }
                d = d.with_help("pick from an allow-list with `agent::pick_from`, or request `Endorse` and say why");
                self.diags.push(d);
                return;
            }
        }
        if !base_compatible(&from, to) {
            // Scope widening has its own code.
            if matches!(
                (&from.base, &to.base),
                (BaseTy::FsRead(_), BaseTy::FsRead(_))
                    | (BaseTy::FsWrite(_), BaseTy::FsWrite(_))
                    | (BaseTy::Net(_), BaseTy::Net(_))
                    | (BaseTy::Tool(_), BaseTy::Tool(_))
            ) {
                self.error(
                    Code::E202,
                    span,
                    format!(
                        "capability `{}` is not a subtype of `{}`; scopes only get narrower",
                        from.render(),
                        to.render()
                    ),
                );
                return;
            }
            self.error(
                Code::E003,
                span,
                format!("expected `{}`, found `{}`", to.render(), from.render()),
            );
        }
    }

    fn lower_type(&mut self, ty: &TypeExpr) -> Ty {
        let mut label = Label::PUBLIC_TRUSTED;
        let mut secret_origin = None;
        let mut untrusted_origin = None;
        for lab in &ty.labels {
            match lab.word {
                LabelWord::Secret => {
                    label.conf = Conf::Secret;
                    secret_origin = Some(Origin {
                        span: lab.span,
                        name: None,
                    });
                }
                LabelWord::Untrusted => {
                    label.integ = Integ::Untrusted;
                    untrusted_origin = Some(Origin {
                        span: lab.span,
                        name: None,
                    });
                }
                LabelWord::Public | LabelWord::Trusted => {}
            }
        }
        let base = match &ty.kind {
            TypeKind::Error => BaseTy::Error,
            TypeKind::Unit => BaseTy::Unit,
            TypeKind::Tuple(ts) => BaseTy::Tuple(ts.iter().map(|t| self.lower_type(t)).collect()),
            TypeKind::Array { elem, len } => {
                let n = match len {
                    mohar_syntax::ArrayLen::Int(v) => *v as u64,
                    mohar_syntax::ArrayLen::Name(n, span) => match self.consts.get(n) {
                        Some((_, ConstVal::Int(v))) if *v >= 0 => *v as u64,
                        _ => {
                            self.error(
                                Code::E003,
                                *span,
                                format!("`{n}` is not an integer constant"),
                            );
                            0
                        }
                    },
                };
                BaseTy::Array(Box::new(self.lower_type(elem)), n)
            }
            TypeKind::Named(path) => self.named_type(path),
        };
        let mut t = Ty::new(base, label);
        t.secret_origin = secret_origin;
        t.untrusted_origin = untrusted_origin;
        t
    }

    fn named_type(&mut self, path: &Path) -> BaseTy {
        let name = path.segments.first().map(|s| s.name.as_str()).unwrap_or("");
        let args = path
            .segments
            .first()
            .map(|s| s.args.as_slice())
            .unwrap_or(&[]);
        match name {
            "bool" => BaseTy::Bool,
            "u8" => BaseTy::Int(IntKind::U8),
            "u16" => BaseTy::Int(IntKind::U16),
            "u32" => BaseTy::Int(IntKind::U32),
            "u64" => BaseTy::Int(IntKind::U64),
            "i64" => BaseTy::Int(IntKind::I64),
            "Text" => BaseTy::Text,
            "Bytes" => BaseTy::Bytes,
            "Unit" => BaseTy::Unit,
            "Caps" => BaseTy::Caps,
            "Console" => BaseTy::Console,
            "Model" => BaseTy::Model,
            "Rand" => BaseTy::Rand,
            "Clock" => BaseTy::Clock,
            "Declassify" => BaseTy::Declassify,
            "Endorse" => BaseTy::Endorse,
            "Email" => BaseTy::Email,
            "Url" => BaseTy::Url,
            "Id" => BaseTy::Id,
            "Kem" => BaseTy::Kem,
            "KemPublicKey" => BaseTy::KemPublic,
            "KemSecretKey" => BaseTy::KemSecret,
            "Sig" => BaseTy::Sig,
            "SigPublicKey" => BaseTy::SigPublic,
            "SigSecretKey" => BaseTy::SigSecret,
            "List" => BaseTy::List(Box::new(self.one_type_arg(args))),
            "Option" => BaseTy::Option(Box::new(self.one_type_arg(args))),
            "Result" => {
                let t = args
                    .first()
                    .and_then(arg_type)
                    .map(|t| self.lower_type(t))
                    .unwrap_or_else(Ty::error);
                let e = args
                    .get(1)
                    .and_then(arg_type)
                    .map(|t| self.lower_type(t))
                    .unwrap_or_else(Ty::error);
                BaseTy::Result(Box::new(t), Box::new(e))
            }
            "FsRead" | "FsWrite" | "Net" | "Tool" => {
                let raw = match args.first() {
                    Some(GenericArg::Str(s, _)) => s.clone(),
                    _ => {
                        self.error(
                            Code::E003,
                            path.span,
                            "capability scope must be a string literal",
                        );
                        return BaseTy::Error;
                    }
                };
                match normalize_scope(&raw) {
                    Ok(s) => match name {
                        "FsRead" => BaseTy::FsRead(s),
                        "FsWrite" => BaseTy::FsWrite(s),
                        "Net" => BaseTy::Net(s),
                        _ => BaseTy::Tool(s),
                    },
                    Err(msg) => {
                        self.error(Code::E206, path.span, msg);
                        BaseTy::Error
                    }
                }
            }
            other if self.structs.contains_key(other) => BaseTy::Struct(other.to_string()),
            other if self.enums.contains_key(other) => BaseTy::Enum(other.to_string()),
            other => {
                self.error(Code::E002, path.span, format!("unknown type `{other}`"));
                BaseTy::Error
            }
        }
    }

    fn one_type_arg(&mut self, args: &[GenericArg]) -> Ty {
        args.first()
            .and_then(arg_type)
            .map(|t| self.lower_type(t))
            .unwrap_or_else(Ty::error)
    }

    fn bind_pat(&mut self, pat: &Pattern, ty: &Ty, mutable: bool) {
        match &pat.kind {
            PatKind::Wild => {}
            PatKind::Binding { name, mutable: m } => {
                let mut ty = ty.clone();
                if ty.label.is_secret() {
                    ty.secret_origin = Some(Origin {
                        span: pat.span,
                        name: Some(name.clone()),
                    });
                }
                if ty.label.is_untrusted() {
                    ty.untrusted_origin = Some(Origin {
                        span: pat.span,
                        name: Some(name.clone()),
                    });
                }
                self.scope.push(ScopeItem::Bind(Bind {
                    name: name.clone(),
                    ty,
                    mutable: mutable || *m,
                    span: pat.span,
                }));
            }
            PatKind::Tuple(ps) => {
                if let BaseTy::Tuple(ts) = &ty.base {
                    for (p, t) in ps.iter().zip(ts) {
                        self.bind_pat(p, t, false);
                    }
                } else if !ty.is_error() {
                    self.error(Code::E003, pat.span, "tuple pattern on a non-tuple");
                }
            }
            _ => {
                self.bind_pattern(pat, ty);
            }
        }
    }

    fn bind_pattern(&mut self, pat: &Pattern, ty: &Ty) {
        match &pat.kind {
            PatKind::Wild | PatKind::LitBool(_) | PatKind::LitInt(_) | PatKind::LitStr(_) => {}
            PatKind::Binding { name, mutable } => {
                self.scope.push(ScopeItem::Bind(Bind {
                    name: name.clone(),
                    ty: ty.clone(),
                    mutable: *mutable,
                    span: pat.span,
                }));
            }
            PatKind::Tuple(ps) => {
                if let BaseTy::Tuple(ts) = &ty.base {
                    for (p, t) in ps.iter().zip(ts) {
                        self.bind_pattern(p, t);
                    }
                }
            }
            PatKind::Variant { path, args } => {
                if path.segments.len() == 1 {
                    let ctor = path.segments[0].name.as_str();
                    let inner = match (&ty.base, ctor) {
                        (BaseTy::Option(t), "Some") => Some(t.as_ref().clone()),
                        (BaseTy::Result(t, _), "Ok") => Some(t.as_ref().clone()),
                        (BaseTy::Result(_, e), "Err") => Some(e.as_ref().clone()),
                        _ => None,
                    };
                    if let Some(inner) = inner {
                        if let Some(p) = args.first() {
                            let mut inner = inner;
                            inner.label = inner.label.join(ty.label);
                            self.bind_pattern(p, &inner);
                        }
                        return;
                    }
                }
                let en = path.segments.first().map(|s| s.name.as_str()).unwrap_or("");
                let var = path.segments.get(1).map(|s| s.name.as_str()).unwrap_or("");
                if let Some(variants) = self.enums.get(en).cloned() {
                    if let Some((_, fields)) = variants.iter().find(|(n, _)| n == var) {
                        for (p, f) in args.iter().zip(fields) {
                            let mut ft = f.clone();
                            ft.label = ft.label.join(ty.label);
                            self.bind_pattern(p, &ft);
                        }
                    }
                }
            }
            PatKind::Struct { path, fields } => {
                let name = path
                    .segments
                    .first()
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                if let Some(def) = self.structs.get(&name).cloned() {
                    for fp in fields {
                        if let Some((_, fty)) = def.iter().find(|(n, _)| n == &fp.name) {
                            self.bind_pattern(&fp.pat, fty);
                        }
                    }
                }
            }
        }
    }

    fn check_exhaust(&mut self, ty: &Ty, arms: &[mohar_syntax::Arm], span: Span) {
        let wild = arms.iter().any(|a| matches!(a.pat.kind, PatKind::Wild));
        if wild {
            return;
        }
        if let BaseTy::Enum(name) = &ty.base {
            if let Some(variants) = self.enums.get(name) {
                let mut seen = HashSet::new();
                for arm in arms {
                    if let PatKind::Variant { path, .. } = &arm.pat.kind {
                        if let Some(v) = path.segments.last() {
                            seen.insert(v.name.clone());
                        }
                    }
                }
                for (v, _) in variants {
                    if !seen.contains(v) {
                        self.error(
                            Code::E006,
                            span,
                            format!("non-exhaustive match, missing variant `{v}`"),
                        );
                        return;
                    }
                }
            }
        }
    }

    fn bind_use(&mut self, module: &[String], names: &[String], span: Span) {
        let path = module.join(".");
        let known = match path.as_str() {
            "std.ct" => Some("std.ct"),
            "std.aead" => Some("std.aead"),
            "std.hash" => Some("std.hash"),
            "std.pq" => Some("std.pq"),
            "std.agent" => Some("std.agent"),
            "std.legacy" => Some("std.legacy"),
            _ => None,
        };
        let Some(canon) = known else {
            self.error(Code::E002, span, format!("unknown module `{path}`"));
            return;
        };
        if canon == "std.legacy" || names.iter().any(|n| n == "ecdsa_p256" || n == "rsa_pss") {
            self.note_legacy(span, "use");
        }
        if names.is_empty() {
            let bind = module.last().cloned().unwrap_or_default();
            self.names.insert(bind, Name::Module(canon));
            return;
        }
        for n in names {
            if canon == "std.legacy" {
                let id: &'static str = match n.as_str() {
                    "ecdsa_p256" => "std.legacy.ecdsa_p256",
                    "rsa_pss" => "std.legacy.rsa_pss",
                    _ => "std.legacy",
                };
                self.names.insert(n.clone(), Name::Legacy(id));
            } else if canon == "std.pq" {
                self.names.insert(n.clone(), Name::Type("pq"));
            } else {
                self.names.insert(n.clone(), Name::Module(canon));
            }
        }
    }

    fn note_legacy(&mut self, span: Span, _id: &str) {
        let policy = &self.opts.policy;
        if policy.kind == crate::policy::PolicyKind::PqOnly || !policy.legacy_allowed() {
            self.diags.push(
                Diagnostic::error(Code::E402, "legacy algorithm is rejected by the crypto policy")
                    .with_primary(span, "")
                    .with_help("remove the legacy use, or choose a policy other than `pq-only` before the cutoff date"),
            );
            return;
        }
        self.diags.push(
            Diagnostic::warning(
                Code::Q101,
                "ECDSA P-256 is quantum-vulnerable (NIST IR 8547: deprecate 2030, disallow 2035)",
            )
            .with_primary(span, "")
            .with_note(format!(
                "allowed until {} by mohar.toml; remove or migrate before then",
                policy.allow_legacy_until
            )),
        );
        self.note_crypto(span, "ECDSA-P256", false, "std.legacy::ecdsa_p256");
    }

    fn note_kem(&mut self, id: &str, span: Span) {
        let alg = match id {
            "Kem::ml_kem_768" => "ML-KEM-768",
            "Kem::ml_kem_1024" => "ML-KEM-1024",
            "Kem::hybrid" => "X25519-MLKEM768",
            "Kem::default" => self.opts.policy.default_kem(),
            _ => self.opts.policy.default_kem(),
        };
        if self.opts.policy.kind == crate::policy::PolicyKind::PqOnly && alg == "X25519-MLKEM768" {
            self.error(
                Code::E401,
                span,
                "hybrid X25519+ML-KEM is outside the `pq-only` policy",
            );
            return;
        }
        let safe = alg != "X25519";
        self.note_crypto(span, alg, safe, id);
    }

    fn note_sig(&mut self, id: &str, span: Span) {
        let alg = match id {
            "Sig::ml_dsa_44" => "ML-DSA-44",
            "Sig::ml_dsa_87" => "ML-DSA-87",
            "Sig::slh_dsa" => "SLH-DSA-SHA2-128s",
            _ => "ML-DSA-65",
        };
        self.note_crypto(span, alg, true, id);
    }

    fn note_crypto(&mut self, span: Span, algorithm: &str, quantum_safe: bool, site: &str) {
        self.crypto.push(CryptoUse {
            span,
            algorithm: algorithm.to_string(),
            quantum_safe,
            site: site.to_string(),
        });
    }

    fn note_cap(&mut self, cap: &str, scope: Option<String>, ops: &[&str], span: Span) {
        self.cap_sites.push(CapSite {
            func: self.current_fn.clone(),
            entry: AuthorityEntry {
                cap: cap.to_string(),
                scope,
                ops: ops.iter().map(|s| (*s).to_string()).collect(),
                span,
            },
        });
    }

    fn note_call(&mut self, callee: &str, span: Span) {
        if let Some(rec) = self.fns.get_mut(&self.current_fn) {
            rec.calls.push(callee.to_string());
        }
        self.call_sites.push(CallSite {
            span,
            callee: callee.to_string(),
            untrusted_pc: self.pc.is_untrusted(),
        });
    }

    fn privileged_here(&mut self, span: Span, what: &str) {
        if self.pc.is_untrusted() {
            self.diags.push(
                Diagnostic::error(
                    Code::E302,
                    format!("untrusted control flow reaches trusted sink `{what}`"),
                )
                .with_primary(span, "")
                .with_help("a branch on untrusted input taints the program counter; do not call a trusted sink inside it"),
            );
        }
        if let Some(rec) = self.fns.get_mut(&self.current_fn) {
            rec.direct_priv = true;
        }
    }

    fn propagate_privilege(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            let snapshot: Vec<(String, bool, Vec<String>)> = self
                .fns
                .iter()
                .map(|(n, r)| (n.clone(), r.direct_priv, r.calls.clone()))
                .collect();
            for (name, direct, calls) in &snapshot {
                if *direct {
                    continue;
                }
                let privy = calls
                    .iter()
                    .any(|c| self.fns.get(c).is_some_and(|f| f.direct_priv));
                if privy {
                    if let Some(rec) = self.fns.get_mut(name) {
                        rec.direct_priv = true;
                        changed = true;
                    }
                }
            }
        }
        let sites = self.call_sites.clone();
        for site in sites {
            if site.untrusted_pc && self.fns.get(&site.callee).is_some_and(|f| f.direct_priv) {
                self.diags.push(
                    Diagnostic::error(
                        Code::E302,
                        format!(
                            "untrusted control flow calls `{}`, which reaches a trusted sink",
                            site.callee
                        ),
                    )
                    .with_primary(site.span, ""),
                );
            }
        }
    }

    fn check_plan_recursion(&mut self) {
        if self.profile != Profile::Plan {
            return;
        }
        let mut stack = Vec::new();
        let mut seen = HashSet::new();
        self.walk_rec("main", &mut stack, &mut seen);
    }

    fn walk_rec(&mut self, name: &str, stack: &mut Vec<String>, seen: &mut HashSet<String>) {
        if stack.iter().any(|s| s == name) {
            let span = self.fns.get(name).map(|f| f.span).unwrap_or(Span::DUMMY);
            self.error(
                Code::E210,
                span,
                format!("`{name}` recurses, which a plan profile forbids"),
            );
            return;
        }
        if !seen.insert(name.to_string()) && !stack.is_empty() {
            return;
        }
        stack.push(name.to_string());
        let calls = self
            .fns
            .get(name)
            .map(|f| f.calls.clone())
            .unwrap_or_default();
        for c in calls {
            if self.fns.contains_key(&c) {
                self.walk_rec(&c, stack, seen);
            }
        }
        stack.pop();
    }

    fn reachable(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut stack = vec!["main".to_string()];
        while let Some(n) = stack.pop() {
            if !out.insert(n.clone()) {
                continue;
            }
            if let Some(f) = self.fns.get(&n) {
                for c in &f.calls {
                    stack.push(c.clone());
                }
            }
        }
        out
    }

    fn lookup_bind(&self, name: &str) -> Option<&Bind> {
        for item in self.scope.iter().rev() {
            if let ScopeItem::Bind(b) = item {
                if b.name == name {
                    return Some(b);
                }
            }
        }
        None
    }

    fn crossed_barrier(&self, name: &str) -> bool {
        let mut crossed = false;
        for item in self.scope.iter().rev() {
            match item {
                ScopeItem::Barrier => crossed = true,
                ScopeItem::Bind(b) if b.name == name => return crossed,
                _ => {}
            }
        }
        false
    }

    fn scope_has_cap(&self, cap: &str) -> bool {
        self.scope.iter().any(|item| match item {
            ScopeItem::Bind(b) => {
                matches!(
                    (&b.ty.base, cap),
                    (BaseTy::Declassify, "Declassify") | (BaseTy::Endorse, "Endorse")
                )
            }
            ScopeItem::Barrier => false,
        })
    }

    fn require_rand_arg(&mut self, args: &[Expr]) {
        if let Some(a) = args.first() {
            let got = self.infer(a, Some(&Ty::plain(BaseTy::Rand)));
            self.flow_at(a.span, &got, &Ty::plain(BaseTy::Rand), Some("Rand"));
        }
    }

    fn infer_args(&mut self, args: &[Expr]) {
        for a in args {
            self.infer(a, None);
        }
    }

    fn check_args(&mut self, params: &[Ty], args: &[Expr], span: Span) {
        if params.len() != args.len() {
            self.error(
                Code::E004,
                span,
                format!("expected {} arguments, found {}", params.len(), args.len()),
            );
            return;
        }
        for (p, a) in params.iter().zip(args) {
            let got = self.infer(a, Some(p));
            self.flow_at(a.span, &got, p, None);
        }
    }

    fn eval_const(&mut self, expr: &Expr) -> ConstVal {
        match &expr.kind {
            ExprKind::Int { value, .. } => ConstVal::Int(*value),
            ExprKind::String(s) => ConstVal::Str(s.clone()),
            ExprKind::Path(p) if p.segments.len() == 1 => {
                let name = &p.segments[0].name;
                self.consts
                    .get(name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or(ConstVal::Int(0))
            }
            ExprKind::Unary {
                op: UnOp::Neg,
                expr,
            } => match self.eval_const(expr) {
                ConstVal::Int(v) => ConstVal::Int(v.saturating_neg()),
                other => other,
            },
            ExprKind::Binary { op, lhs, rhs } => {
                let ConstVal::Int(a) = self.eval_const(lhs) else {
                    return ConstVal::Int(0);
                };
                let ConstVal::Int(b) = self.eval_const(rhs) else {
                    return ConstVal::Int(0);
                };
                let v = match op {
                    BinOp::Add => a.saturating_add(b),
                    BinOp::Sub => a.saturating_sub(b),
                    BinOp::Mul => a.saturating_mul(b),
                    _ => 0,
                };
                ConstVal::Int(v)
            }
            _ => ConstVal::Int(0),
        }
    }

    fn error(&mut self, code: Code, span: Span, message: impl Into<String>) {
        self.diags
            .push(Diagnostic::error(code, message).with_primary(span, ""));
    }
}

fn profile_of(item: &mohar_syntax::Item) -> Profile {
    for attr in &item.attrs {
        if attr.name == "profile" {
            if let Some(arg) = &attr.arg {
                if let Some(p) = Profile::parse(arg) {
                    return p;
                }
            }
        }
    }
    Profile::Default
}

fn arg_type(arg: &GenericArg) -> Option<&TypeExpr> {
    match arg {
        GenericArg::Type(t) => Some(t),
        _ => None,
    }
}

fn concretize(mut ty: Ty) -> Ty {
    if let BaseTy::IntLit(v) = ty.base {
        let kind = if IntKind::I64.fits(v) {
            IntKind::I64
        } else {
            IntKind::U64
        };
        ty.base = BaseTy::Int(kind);
    }
    ty
}

fn concretize_toward(mut from: Ty, to: &Ty) -> Ty {
    if let BaseTy::IntLit(v) = from.base {
        if let BaseTy::Int(k) = to.base {
            if k.fits(v) {
                from.base = BaseTy::Int(k);
            }
        } else if IntKind::I64.fits(v) {
            from.base = BaseTy::Int(IntKind::I64);
        }
    }
    from
}

fn unify_int(a: &Ty, b: &Ty) -> Option<IntKind> {
    match (&a.base, &b.base) {
        (BaseTy::Int(k), BaseTy::Int(k2)) if k == k2 => Some(*k),
        (BaseTy::Int(k), BaseTy::IntLit(v)) | (BaseTy::IntLit(v), BaseTy::Int(k)) if k.fits(*v) => {
            Some(*k)
        }
        (BaseTy::IntLit(v), BaseTy::IntLit(w)) => {
            if IntKind::I64.fits(*v) && IntKind::I64.fits(*w) {
                Some(IntKind::I64)
            } else if IntKind::U64.fits(*v) && IntKind::U64.fits(*w) {
                Some(IntKind::U64)
            } else {
                None
            }
        }
        (BaseTy::Error, _) | (_, BaseTy::Error) => Some(IntKind::I64),
        _ => None,
    }
}

fn labels_ok(from: &Ty, to: &Ty) -> bool {
    from.label.flows_to(to.label)
}

fn base_compatible(from: &Ty, to: &Ty) -> bool {
    use BaseTy::*;
    match (&from.base, &to.base) {
        (Error, _) | (_, Error) => true,
        (Int(k), Int(k2)) => k == k2,
        (IntLit(v), Int(k)) => k.fits(*v),
        (Array(a, n), Array(b, m)) => n == m && base_compatible(a, b) && a.label.flows_to(b.label),
        (List(a), List(b)) => base_compatible(a, b) && a.label.flows_to(b.label),
        (Option(a), Option(b)) => base_compatible(a, b),
        (Result(a, e), Result(b, f)) => base_compatible(a, b) && base_compatible(e, f),
        (Tuple(a), Tuple(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|(x, y)| base_compatible(x, y) && x.label.flows_to(y.label))
        }
        (FsRead(_), FsRead(_))
        | (FsWrite(_), FsWrite(_))
        | (Net(_), Net(_))
        | (Tool(_), Tool(_)) => cap_subtype(&from.base, &to.base),
        (a, b) => a == b,
    }
}

fn propagate(result: &Ty, parts: &[Ty]) -> Ty {
    let mut result = result.clone();
    if result.label.is_secret() && result.secret_origin.is_none() {
        result.secret_origin = parts.iter().find_map(|t| t.secret_origin.clone());
    }
    if result.label.is_untrusted() && result.untrusted_origin.is_none() {
        result.untrusted_origin = parts.iter().find_map(|t| t.untrusted_origin.clone());
    }
    result
}

fn same_width(a: &Ty, b: &Ty) -> bool {
    match (&a.base, &b.base) {
        (BaseTy::Array(_, n), BaseTy::Array(_, m)) => n == m,
        (BaseTy::Bytes, BaseTy::Bytes) => true,
        (BaseTy::Array(_, _), BaseTy::Bytes) | (BaseTy::Bytes, BaseTy::Array(_, _)) => true,
        _ => false,
    }
}

fn elem_if(ty: &Ty) -> Option<Ty> {
    match &ty.base {
        BaseTy::List(t) => Some((**t).clone()),
        _ => None,
    }
}

fn is_literal_list(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Array(xs) => xs.iter().all(|x| matches!(x.kind, ExprKind::String(_))),
        _ => false,
    }
}

fn carry(recv: &Ty, base: BaseTy) -> Ty {
    let mut t = Ty::new(base, recv.label);
    t.secret_origin = recv.secret_origin.clone();
    t.untrusted_origin = recv.untrusted_origin.clone();
    t
}

fn looks_like_email(s: &str) -> bool {
    let Some((local, host)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty() && host.contains('.') && !s.contains(' ')
}

fn normalize_scope_file(path: &str) -> Result<(), ()> {
    if path.starts_with('/') || path.contains("..") {
        Err(())
    } else {
        Ok(())
    }
}

// Silence a warning if a constructor helper is only used through paths.
#[allow(dead_code)]
fn _label_names(c: Conf, i: Integ) -> Label {
    Label::new(c, i)
}
