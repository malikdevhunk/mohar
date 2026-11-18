//! Hand-written UTF-8 lexer.
//!
//! The scan never uses a regex. On a bad byte it records a diagnostic and
//! continues, so one stray character does not hide the rest of the file.

use mohar_diag::{Code, Diagnostic, SourceFile, Span};

use crate::token::{IntSuffix, Token, TokenKind};

pub struct LexOutput {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn lex(file: &SourceFile) -> LexOutput {
    let mut lx = Lexer {
        src: file.source.as_str(),
        bytes: file.source.as_bytes(),
        pos: 0,
        tokens: Vec::new(),
        diagnostics: Vec::new(),
    };
    lx.skip_shebang();
    while !lx.eof() {
        lx.skip_ws_and_comments();
        if lx.eof() {
            break;
        }
        lx.next_token();
    }
    lx.tokens.push(Token {
        kind: TokenKind::Eof,
        span: Span::new(lx.pos as u32, lx.pos as u32),
    });
    LexOutput {
        tokens: lx.tokens,
        diagnostics: lx.diagnostics,
    }
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Lexer<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, off: usize) -> Option<u8> {
        self.bytes.get(self.pos + off).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn span_from(&self, start: usize) -> Span {
        Span::new(start as u32, self.pos as u32)
    }

    fn push(&mut self, kind: TokenKind, start: usize) {
        self.tokens.push(Token {
            kind,
            span: self.span_from(start),
        });
    }

    fn error(&mut self, start: usize, message: impl Into<String>) {
        let span = self.span_from(start);
        self.diagnostics
            .push(Diagnostic::error(Code::E001, message).with_primary(span, ""));
    }

    fn skip_shebang(&mut self) {
        if self.pos == 0 && self.peek() == Some(b'#') && self.peek_at(1) == Some(b'!') {
            while let Some(b) = self.peek() {
                self.bump();
                if b == b'\n' {
                    break;
                }
            }
        }
    }

    fn skip_ws_and_comments(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\n' | b'\r') => {
                    self.bump();
                }
                Some(b'/') if self.peek_at(1) == Some(b'/') => {
                    while let Some(b) = self.peek() {
                        if b == b'\n' {
                            break;
                        }
                        self.bump();
                    }
                }
                Some(b'/') if self.peek_at(1) == Some(b'*') => {
                    let start = self.pos;
                    self.bump();
                    self.bump();
                    let mut closed = false;
                    while let Some(b) = self.peek() {
                        if b == b'*' && self.peek_at(1) == Some(b'/') {
                            self.bump();
                            self.bump();
                            closed = true;
                            break;
                        }
                        self.bump();
                    }
                    if !closed {
                        self.error(start, "unterminated block comment");
                    }
                }
                _ => break,
            }
        }
    }

    fn next_token(&mut self) {
        let start = self.pos;
        let Some(b) = self.bump() else {
            return;
        };
        match b {
            b'(' => self.push(TokenKind::LParen, start),
            b')' => self.push(TokenKind::RParen, start),
            b'{' => self.push(TokenKind::LBrace, start),
            b'}' => self.push(TokenKind::RBrace, start),
            b'[' => self.push(TokenKind::LBracket, start),
            b']' => self.push(TokenKind::RBracket, start),
            b',' => self.push(TokenKind::Comma, start),
            b';' => self.push(TokenKind::Semi, start),
            b'?' => self.push(TokenKind::Question, start),
            b'@' => {
                self.error(start, "unexpected `@`");
            }
            b'#' => self.push(TokenKind::Hash, start),
            b'+' => self.push(TokenKind::Plus, start),
            b'*' => self.push(TokenKind::Star, start),
            b'%' => self.push(TokenKind::Percent, start),
            b'^' => self.push(TokenKind::Caret, start),
            b'~' => {
                self.error(start, "unexpected `~`");
            }
            b'-' => {
                if self.peek() == Some(b'>') {
                    self.bump();
                    self.push(TokenKind::Arrow, start);
                } else {
                    self.push(TokenKind::Minus, start);
                }
            }
            b'.' => {
                if self.peek() == Some(b'.') {
                    self.bump();
                    self.push(TokenKind::DotDot, start);
                } else {
                    self.push(TokenKind::Dot, start);
                }
            }
            b':' => {
                if self.peek() == Some(b':') {
                    self.bump();
                    self.push(TokenKind::ColonColon, start);
                } else {
                    self.push(TokenKind::Colon, start);
                }
            }
            b'=' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    self.push(TokenKind::EqEq, start);
                } else if self.peek() == Some(b'>') {
                    self.bump();
                    self.push(TokenKind::FatArrow, start);
                } else {
                    self.push(TokenKind::Eq, start);
                }
            }
            b'!' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    self.push(TokenKind::NotEq, start);
                } else {
                    self.push(TokenKind::Bang, start);
                }
            }
            b'<' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    self.push(TokenKind::Le, start);
                } else if self.peek() == Some(b'<') {
                    self.bump();
                    self.push(TokenKind::Shl, start);
                } else {
                    self.push(TokenKind::Lt, start);
                }
            }
            b'>' => {
                if self.peek() == Some(b'=') {
                    self.bump();
                    self.push(TokenKind::Ge, start);
                } else if self.peek() == Some(b'>') {
                    self.bump();
                    self.push(TokenKind::Shr, start);
                } else {
                    self.push(TokenKind::Gt, start);
                }
            }
            b'&' => {
                if self.peek() == Some(b'&') {
                    self.bump();
                    self.push(TokenKind::AndAnd, start);
                } else {
                    self.push(TokenKind::Amp, start);
                }
            }
            b'|' => {
                if self.peek() == Some(b'|') {
                    self.bump();
                    self.push(TokenKind::OrOr, start);
                } else {
                    self.push(TokenKind::Pipe, start);
                }
            }
            b'/' => self.push(TokenKind::Slash, start),
            b'"' => self.string(start, false),
            b'b' if self.peek() == Some(b'"') => {
                self.bump();
                self.string(start, true);
            }
            b'0'..=b'9' => self.number(start),
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => self.ident(start),
            b if b >= 0x80 => self.unicode_ident(start),
            other => {
                let ch = self.src[start..].chars().next().unwrap_or('?');
                let _ = other;
                self.error(start, format!("unexpected character `{ch}`"));
            }
        }
    }

    fn ident(&mut self, start: usize) {
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
        ) {
            self.bump();
        }
        // A non-ascii continuation (letters) is accepted so names can be Unicode.
        while let Some(ch) = self.rest_char() {
            if ch.is_alphanumeric() || ch == '_' {
                self.bump_char(ch);
            } else {
                break;
            }
        }
        let text = &self.src[start..self.pos];
        if let Some(kw) = TokenKind::keyword(text) {
            self.push(kw, start);
        } else {
            self.push(TokenKind::Ident(text.to_string()), start);
        }
    }

    fn unicode_ident(&mut self, start: usize) {
        // We already consumed the first byte. Rewind and read a char.
        self.pos = start;
        let Some(ch) = self.rest_char() else {
            return;
        };
        if !(ch.is_alphabetic() || ch == '_') {
            self.bump_char(ch);
            self.error(start, format!("unexpected character `{ch}`"));
            return;
        }
        self.bump_char(ch);
        self.ident(start);
    }

    fn rest_char(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    fn bump_char(&mut self, ch: char) {
        self.pos += ch.len_utf8();
    }

    fn number(&mut self, start: usize) {
        // First digit already consumed.
        let (radix, digits_start) = if self.src.as_bytes()[start] == b'0' {
            match self.peek() {
                Some(b'x' | b'X') => {
                    self.bump();
                    (16, self.pos)
                }
                Some(b'b' | b'B') => {
                    self.bump();
                    (2, self.pos)
                }
                _ => (10, start),
            }
        } else {
            (10, start)
        };
        while let Some(b) = self.peek() {
            if b == b'_' || digit_value(b, radix).is_some() {
                self.bump();
            } else {
                break;
            }
        }
        let raw: String = self.src[digits_start..self.pos]
            .chars()
            .filter(|c| *c != '_')
            .collect();
        if raw.is_empty() {
            self.error(start, "number is missing digits");
            self.push(TokenKind::Int(0, None), start);
            return;
        }
        let value = match u128::from_str_radix(&raw, radix) {
            Ok(v) => v,
            Err(_) => {
                self.error(start, "integer literal does not fit in 128 bits");
                0
            }
        };
        let suffix = self.maybe_suffix();
        self.push(TokenKind::Int(value, suffix), start);
    }

    fn maybe_suffix(&mut self) -> Option<IntSuffix> {
        let save = self.pos;
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'A'..=b'Z')) {
            return None;
        }
        let start = self.pos;
        while matches!(self.peek(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')) {
            self.bump();
        }
        let text = &self.src[start..self.pos];
        let suffix = match text {
            "u8" => Some(IntSuffix::U8),
            "u16" => Some(IntSuffix::U16),
            "u32" => Some(IntSuffix::U32),
            "u64" => Some(IntSuffix::U64),
            "i64" => Some(IntSuffix::I64),
            _ => None,
        };
        if suffix.is_none() {
            self.pos = save;
        }
        suffix
    }

    fn string(&mut self, start: usize, is_bytes: bool) {
        // Opening quote already consumed. For byte strings both `b` and `"` are.
        let mut out_str = String::new();
        let mut out_bytes: Vec<u8> = Vec::new();
        let mut closed = false;
        while let Some(b) = self.peek() {
            if b == b'"' {
                self.bump();
                closed = true;
                break;
            }
            if b == b'\n' || b == b'\r' {
                break;
            }
            if b == b'\\' {
                self.bump();
                let Some(esc) = self.bump() else { break };
                let decoded = match esc {
                    b'n' => Some('\n'),
                    b'r' => Some('\r'),
                    b't' => Some('\t'),
                    b'0' => Some('\0'),
                    b'\\' => Some('\\'),
                    b'"' => Some('"'),
                    b'u' => self.unicode_escape(),
                    b'x' => self.hex_escape(),
                    other => {
                        let ch = other as char;
                        self.error(
                            self.pos.saturating_sub(1),
                            format!("unknown string escape `\\{ch}`"),
                        );
                        Some('?')
                    }
                };
                if let Some(ch) = decoded {
                    self.push_decoded(ch, is_bytes, &mut out_str, &mut out_bytes, start);
                }
            } else {
                let ch = match self.rest_char() {
                    Some(ch) => ch,
                    None => break,
                };
                self.bump_char(ch);
                self.push_decoded(ch, is_bytes, &mut out_str, &mut out_bytes, start);
            }
        }
        if !closed {
            self.error(start, "unterminated string literal");
        }
        if is_bytes {
            self.push(TokenKind::Bytes(out_bytes), start);
        } else {
            self.push(TokenKind::String(out_str), start);
        }
    }

    fn push_decoded(
        &mut self,
        ch: char,
        is_bytes: bool,
        out_str: &mut String,
        out_bytes: &mut Vec<u8>,
        start: usize,
    ) {
        if is_bytes {
            if ch.is_ascii() {
                out_bytes.push(ch as u8);
            } else {
                self.error(start, "byte string cannot contain a non-ascii character");
            }
        } else {
            out_str.push(ch);
        }
    }

    fn hex_escape(&mut self) -> Option<char> {
        let start = self.pos.saturating_sub(2);
        let mut hex = String::new();
        for _ in 0..2 {
            match self.peek() {
                Some(b @ (b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) => {
                    hex.push(b as char);
                    self.bump();
                }
                _ => {
                    self.error(start, "hex escape must be two digits, like `\\x0a`");
                    return None;
                }
            }
        }
        u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
    }

    fn unicode_escape(&mut self) -> Option<char> {
        // `\u` already consumed. Expect `{ hex }`.
        let start = self.pos.saturating_sub(2);
        if self.peek() != Some(b'{') {
            self.error(start, "unicode escape must look like `\\u{...}`");
            return None;
        }
        self.bump();
        let hex_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) {
            self.bump();
        }
        let hex = &self.src[hex_start..self.pos];
        if self.peek() != Some(b'}') || hex.is_empty() {
            self.error(start, "unterminated unicode escape");
            if self.peek() == Some(b'}') {
                self.bump();
            }
            return None;
        }
        self.bump();
        match u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
            Some(ch) => Some(ch),
            None => {
                self.error(start, "invalid unicode scalar in string escape");
                None
            }
        }
    }
}

fn digit_value(b: u8, radix: u32) -> Option<u32> {
    let v = match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => return None,
    } as u32;
    if v < radix { Some(v) } else { None }
}
