//! Abstract syntax tree.
//!
//! Node identifiers are unique within one parse and are how the type checker
//! hangs inferred types off the tree without rebuilding it.

use mohar_diag::Span;

pub type NodeId = u32;

#[derive(Clone, Debug)]
pub struct Program {
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: NodeId,
    pub attrs: Vec<Attr>,
    pub kind: ItemKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Attr {
    pub name: String,
    pub arg: Option<String>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ItemKind {
    Fn(FnItem),
    Struct(StructItem),
    Enum(EnumItem),
    Use(UseItem),
    Const(ConstItem),
    Mod(ModItem),
}

#[derive(Clone, Debug)]
pub struct FnItem {
    pub name: String,
    pub name_span: Span,
    pub params: Vec<Param>,
    pub ret: Option<TypeExpr>,
    pub body: Block,
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    pub ty: TypeExpr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StructItem {
    pub name: String,
    pub name_span: Span,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: TypeExpr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct EnumItem {
    pub name: String,
    pub name_span: Span,
    pub variants: Vec<Variant>,
}

#[derive(Clone, Debug)]
pub struct Variant {
    pub name: String,
    pub fields: Vec<TypeExpr>,
    pub span: Span,
}

/// `use std.pq::{Kem, Sig}` or `use std.ct`.
///
/// `module` is the dotted prefix (`["std", "pq"]`). `names` lists the imported
/// items. An empty `names` means "bind the last module segment itself"
/// (`use std.ct` binds `ct`).
#[derive(Clone, Debug)]
pub struct UseItem {
    pub module: Vec<String>,
    pub names: Vec<String>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ConstItem {
    pub name: String,
    pub name_span: Span,
    pub ty: TypeExpr,
    pub value: Expr,
}

#[derive(Clone, Debug)]
pub struct ModItem {
    pub name: String,
    pub name_span: Span,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub id: NodeId,
    pub stmts: Vec<Stmt>,
    pub tail: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Stmt {
    pub id: NodeId,
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum StmtKind {
    Let {
        mutable: bool,
        pat: Pattern,
        ty: Option<TypeExpr>,
        value: Expr,
    },
    Assign {
        name: String,
        name_span: Span,
        value: Expr,
    },
    Expr(Expr),
    Return(Option<Expr>),
    While {
        cond: Expr,
        body: Box<Block>,
    },
    For {
        name: String,
        name_span: Span,
        iter: Expr,
        body: Box<Block>,
    },
}

#[derive(Clone, Debug)]
pub struct Expr {
    pub id: NodeId,
    pub kind: ExprKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum ExprKind {
    Path(Path),
    Int {
        value: i128,
        suffix: Option<crate::IntSuffix>,
    },
    String(String),
    Bytes(Vec<u8>),
    Bool(bool),
    Unit,
    Tuple(Vec<Expr>),
    Array(Vec<Expr>),
    Repeat {
        value: Box<Expr>,
        len: Box<Expr>,
    },
    Block(Box<Block>),
    If {
        cond: Box<Expr>,
        then_branch: Box<Block>,
        else_branch: Option<Box<Expr>>,
    },
    Match {
        scrutinee: Box<Expr>,
        arms: Vec<Arm>,
    },
    Lambda {
        params: Vec<LambdaParam>,
        body: Box<Expr>,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    Method {
        receiver: Box<Expr>,
        name: String,
        name_span: Span,
        type_args: Vec<GenericArg>,
        args: Vec<Expr>,
    },
    Field {
        base: Box<Expr>,
        name: String,
        name_span: Span,
    },
    Index {
        base: Box<Expr>,
        index: Box<Expr>,
    },
    Try(Box<Expr>),
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Struct {
        path: Path,
        fields: Vec<StructFieldInit>,
    },
    Error,
}

#[derive(Clone, Debug)]
pub struct Arm {
    pub pat: Pattern,
    pub body: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct LambdaParam {
    pub name: String,
    pub ty: Option<TypeExpr>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct StructFieldInit {
    pub name: String,
    pub value: Expr,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub id: NodeId,
    pub kind: PatKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum PatKind {
    Wild,
    Binding { name: String, mutable: bool },
    LitInt(i128),
    LitBool(bool),
    LitStr(String),
    Tuple(Vec<Pattern>),
    Variant { path: Path, args: Vec<Pattern> },
    Struct { path: Path, fields: Vec<FieldPat> },
}

#[derive(Clone, Debug)]
pub struct FieldPat {
    pub name: String,
    pub pat: Pattern,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Path {
    pub segments: Vec<PathSeg>,
    pub span: Span,
}

impl Path {
    pub fn names(&self) -> Vec<&str> {
        self.segments.iter().map(|s| s.name.as_str()).collect()
    }

    pub fn is_ident(&self, name: &str) -> bool {
        self.segments.len() == 1
            && self.segments[0].name == name
            && self.segments[0].args.is_empty()
    }
}

#[derive(Clone, Debug)]
pub struct PathSeg {
    pub name: String,
    pub args: Vec<GenericArg>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum GenericArg {
    Type(TypeExpr),
    Int(u128, Span),
    Str(String, Span),
}

#[derive(Clone, Debug)]
pub struct TypeExpr {
    pub id: NodeId,
    pub labels: Vec<LabelTok>,
    pub kind: TypeKind,
    pub span: Span,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelWord {
    Secret,
    Untrusted,
    Public,
    Trusted,
}

#[derive(Clone, Debug)]
pub struct LabelTok {
    pub word: LabelWord,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum TypeKind {
    Unit,
    Named(Path),
    Array { elem: Box<TypeExpr>, len: ArrayLen },
    Tuple(Vec<TypeExpr>),
    Error,
}

#[derive(Clone, Debug)]
pub enum ArrayLen {
    Int(u128),
    Name(String, Span),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Range,
}

impl BinOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
            Self::BitAnd => "&",
            Self::BitOr => "|",
            Self::BitXor => "^",
            Self::Shl => "<<",
            Self::Shr => ">>",
            Self::Range => "..",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
}

impl Expr {
    pub fn error(id: NodeId, span: Span) -> Self {
        Self {
            id,
            kind: ExprKind::Error,
            span,
        }
    }
}
