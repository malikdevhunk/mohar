//! Types: a base type plus a label, and the scope carried by a capability.

use mohar_diag::Span;

use crate::label::{Conf, Integ, Label};
use crate::policy::Origin;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IntKind {
    U8,
    U16,
    U32,
    U64,
    I64,
}

impl IntKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I64 => "i64",
        }
    }

    pub fn fits(self, value: i128) -> bool {
        match self {
            Self::U8 => (0..=u8::MAX as i128).contains(&value),
            Self::U16 => (0..=u16::MAX as i128).contains(&value),
            Self::U32 => (0..=u32::MAX as i128).contains(&value),
            Self::U64 => (0..=u64::MAX as i128).contains(&value),
            Self::I64 => (i64::MIN as i128..=i64::MAX as i128).contains(&value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseTy {
    Error,
    Unit,
    Bool,
    Int(IntKind),
    /// An integer literal not yet constrained by a suffix or an expected type.
    IntLit(i128),
    Text,
    Bytes,
    Array(Box<Ty>, u64),
    List(Box<Ty>),
    /// `List::new()` before the element type is known.
    ListHole,
    Option(Box<Ty>),
    Result(Box<Ty>, Box<Ty>),
    Tuple(Vec<Ty>),
    Struct(String),
    Enum(String),
    Func(Vec<Ty>, Box<Ty>),
    Caps,
    Console,
    Model,
    Rand,
    Clock,
    Declassify,
    Endorse,
    FsRead(String),
    FsWrite(String),
    Net(String),
    Tool(String),
    Email,
    Url,
    Id,
    Kem,
    KemPublic,
    KemSecret,
    Sig,
    SigPublic,
    SigSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ty {
    pub base: BaseTy,
    pub label: Label,
    pub secret_origin: Option<Origin>,
    pub untrusted_origin: Option<Origin>,
}

impl Ty {
    pub fn new(base: BaseTy, label: Label) -> Self {
        Self {
            base,
            label,
            secret_origin: None,
            untrusted_origin: None,
        }
    }

    pub fn plain(base: BaseTy) -> Self {
        Self::new(base, Label::PUBLIC_TRUSTED)
    }

    pub fn error() -> Self {
        Self::plain(BaseTy::Error)
    }

    pub fn unit() -> Self {
        Self::plain(BaseTy::Unit)
    }

    pub fn bool() -> Self {
        Self::plain(BaseTy::Bool)
    }

    pub fn text() -> Self {
        Self::plain(BaseTy::Text)
    }

    pub fn bytes() -> Self {
        Self::plain(BaseTy::Bytes)
    }

    pub fn i64() -> Self {
        Self::plain(BaseTy::Int(IntKind::I64))
    }

    pub fn u64() -> Self {
        Self::plain(BaseTy::Int(IntKind::U64))
    }

    pub fn is_error(&self) -> bool {
        matches!(self.base, BaseTy::Error)
    }

    pub fn with_label(mut self, label: Label) -> Self {
        self.label = label;
        self
    }

    pub fn with_secret_origin(mut self, origin: Origin) -> Self {
        if self.label.is_secret() && self.secret_origin.is_none() {
            self.secret_origin = Some(origin);
        }
        self
    }

    pub fn with_untrusted_origin(mut self, origin: Origin) -> Self {
        if self.label.is_untrusted() && self.untrusted_origin.is_none() {
            self.untrusted_origin = Some(origin);
        }
        self
    }

    pub fn join_label(mut self, other: Label) -> Self {
        self.label = self.label.join(other);
        self
    }

    pub fn join_pc(self, pc: Label) -> Self {
        let label = self.label.join(Label::new(Conf::Public, pc.integ));
        // A secret program counter does not arise in v0.1: secret branches are rejected.
        let _ = pc.conf;
        self.with_label(label)
    }

    /// Confidentiality and integrity of a value that was produced under `pc`.
    pub fn under_pc(mut self, pc: Label, span: Span) -> Self {
        if pc.is_untrusted() {
            self.label.integ = Integ::Untrusted;
            if self.untrusted_origin.is_none() {
                self.untrusted_origin = Some(Origin { span, name: None });
            }
        }
        self
    }

    pub fn render(&self) -> String {
        if self.is_error() {
            return "<error>".to_string();
        }
        let base = render_base(&self.base);
        match (self.label.conf, self.label.integ) {
            (Conf::Public, Integ::Trusted) => base,
            (Conf::Secret, Integ::Trusted) => format!("secret {base}"),
            (Conf::Public, Integ::Untrusted) => format!("untrusted {base}"),
            (Conf::Secret, Integ::Untrusted) => format!("secret untrusted {base}"),
        }
    }

    pub fn is_capability(&self) -> bool {
        matches!(
            self.base,
            BaseTy::Caps
                | BaseTy::Console
                | BaseTy::Model
                | BaseTy::Rand
                | BaseTy::Clock
                | BaseTy::Declassify
                | BaseTy::Endorse
                | BaseTy::FsRead(_)
                | BaseTy::FsWrite(_)
                | BaseTy::Net(_)
                | BaseTy::Tool(_)
        )
    }
}

fn render_base(base: &BaseTy) -> String {
    match base {
        BaseTy::Error => "<error>".into(),
        BaseTy::Unit => "Unit".into(),
        BaseTy::Bool => "bool".into(),
        BaseTy::Int(k) => k.name().into(),
        BaseTy::IntLit(_) => "integer".into(),
        BaseTy::Text => "Text".into(),
        BaseTy::Bytes => "Bytes".into(),
        BaseTy::Array(t, n) => format!("[{}; {n}]", t.render()),
        BaseTy::List(t) => format!("List<{}>", t.render()),
        BaseTy::ListHole => "List<_>".into(),
        BaseTy::Option(t) => format!("Option<{}>", t.render()),
        BaseTy::Result(t, e) => format!("Result<{}, {}>", t.render(), e.render()),
        BaseTy::Tuple(ts) => {
            let inner: Vec<_> = ts.iter().map(Ty::render).collect();
            format!("({})", inner.join(", "))
        }
        BaseTy::Struct(n) | BaseTy::Enum(n) => n.clone(),
        BaseTy::Func(ps, r) => {
            let ps: Vec<_> = ps.iter().map(Ty::render).collect();
            format!("fn({}) -> {}", ps.join(", "), r.render())
        }
        BaseTy::Caps => "Caps".into(),
        BaseTy::Console => "Console".into(),
        BaseTy::Model => "Model".into(),
        BaseTy::Rand => "Rand".into(),
        BaseTy::Clock => "Clock".into(),
        BaseTy::Declassify => "Declassify".into(),
        BaseTy::Endorse => "Endorse".into(),
        BaseTy::FsRead(s) => format!("FsRead<\"{s}\">"),
        BaseTy::FsWrite(s) => format!("FsWrite<\"{s}\">"),
        BaseTy::Net(s) => format!("Net<\"{s}\">"),
        BaseTy::Tool(s) => format!("Tool<\"{s}\">"),
        BaseTy::Email => "Email".into(),
        BaseTy::Url => "Url".into(),
        BaseTy::Id => "Id".into(),
        BaseTy::Kem => "Kem".into(),
        BaseTy::KemPublic => "KemPublicKey".into(),
        BaseTy::KemSecret => "KemSecretKey".into(),
        BaseTy::Sig => "Sig".into(),
        BaseTy::SigPublic => "SigPublicKey".into(),
        BaseTy::SigSecret => "SigSecretKey".into(),
    }
}

/// Normalise a scope string: drop a leading `./`, reject `..` and absolute paths.
pub fn normalize_scope(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Err("scope is empty");
    }
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err("absolute scopes are outside the sandbox");
    }
    if raw
        .split(['/', '\\'])
        .any(|p| p == ".." || p.is_empty() && raw.contains("//"))
    {
        // empty component from a trailing slash is tolerated below; `..` is not.
    }
    if raw.split('/').any(|p| p == "..") {
        return Err("scope contains `..`");
    }
    let trimmed = raw.trim_matches('/');
    if trimmed.is_empty() {
        return Err("scope is empty");
    }
    Ok(trimmed.to_string())
}

/// `child` is the same path as `parent` or a directory inside it.
pub fn path_narrows(child: &str, parent: &str) -> bool {
    child == parent || child.starts_with(&format!("{parent}/"))
}

/// Host scopes narrow by a dotted suffix, with an exact port.
pub fn host_narrows(child: &str, parent: &str) -> bool {
    let Some((ch, cp)) = split_host(child) else {
        return child == parent;
    };
    let Some((ph, pp)) = split_host(parent) else {
        return child == parent;
    };
    if cp != pp {
        return false;
    }
    ch == ph || ch.ends_with(&format!(".{ph}"))
}

fn split_host(scope: &str) -> Option<(&str, &str)> {
    let (host, port) = scope.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

/// Capability subtyping. Narrow scopes are subtypes of wider ones:
/// `FsRead<"a/b"> <: FsRead<"a">`. Tool names are equal or not at all.
pub fn cap_subtype(from: &BaseTy, to: &BaseTy) -> bool {
    match (from, to) {
        (BaseTy::FsRead(a), BaseTy::FsRead(b)) => path_narrows(a, b),
        (BaseTy::FsWrite(a), BaseTy::FsWrite(b)) => path_narrows(a, b),
        (BaseTy::Net(a), BaseTy::Net(b)) => host_narrows(a, b) || a == b,
        (BaseTy::Tool(a), BaseTy::Tool(b)) => a == b,
        (a, b) => a == b,
    }
}
