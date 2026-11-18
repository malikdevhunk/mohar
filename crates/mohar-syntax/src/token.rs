//! Tokens produced by the lexer.

use mohar_diag::Span;

/// Optional integer suffix, as in `1u8` or `32u64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntSuffix {
    U8,
    U16,
    U32,
    U64,
    I64,
}

impl IntSuffix {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I64 => "i64",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenKind {
    Ident(String),
    Int(u128, Option<IntSuffix>),
    String(String),
    Bytes(Vec<u8>),
    Fn,
    Let,
    Mut,
    If,
    Else,
    Match,
    For,
    In,
    While,
    Return,
    Use,
    Struct,
    Enum,
    Const,
    True,
    False,
    Secret,
    Untrusted,
    Public,
    Trusted,
    Mod,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Colon,
    Semi,
    Dot,
    Question,
    Arrow,
    FatArrow,
    ColonColon,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    Amp,
    Pipe,
    Caret,
    Shl,
    Shr,
    Eq,
    DotDot,
    Hash,
    Eof,
}

impl TokenKind {
    pub fn keyword(ident: &str) -> Option<TokenKind> {
        Some(match ident {
            "fn" => Self::Fn,
            "let" => Self::Let,
            "mut" => Self::Mut,
            "if" => Self::If,
            "else" => Self::Else,
            "match" => Self::Match,
            "for" => Self::For,
            "in" => Self::In,
            "while" => Self::While,
            "return" => Self::Return,
            "use" => Self::Use,
            "struct" => Self::Struct,
            "enum" => Self::Enum,
            "const" => Self::Const,
            "true" => Self::True,
            "false" => Self::False,
            "secret" => Self::Secret,
            "untrusted" => Self::Untrusted,
            "public" => Self::Public,
            "trusted" => Self::Trusted,
            "mod" => Self::Mod,
            _ => return None,
        })
    }

    pub fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }
}
