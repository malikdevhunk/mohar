//! Recursive-descent parser with Pratt expressions.
//!
//! A syntax error becomes an `E001` diagnostic and a placeholder node. The
//! parser keeps going so one mistake does not swallow the rest of the file.

use mohar_diag::{Code, Diagnostic, SourceFile, Span};

use crate::ast::*;
use crate::lexer::lex;
use crate::token::{Token, TokenKind};

pub struct ParseOutput {
    pub program: Program,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse(file: &SourceFile) -> ParseOutput {
    let lexed = lex(file);
    let mut parser = Parser {
        tokens: lexed.tokens,
        pos: 0,
        diagnostics: lexed.diagnostics,
        next_id: 1,
        pending_gt: false,
        last_end: 0,
        allow_struct: true,
    };
    let program = parser.parse_program();
    ParseOutput {
        program,
        diagnostics: parser.diagnostics,
    }
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    diagnostics: Vec<Diagnostic>,
    next_id: NodeId,
    /// A `>>` was split, and one `>` is still waiting to be read.
    pending_gt: bool,
    last_end: u32,
    /// Struct literals are suppressed where `{` starts a block instead
    /// (the condition of `if`/`while`, the scrutinee of `match`, a `for` iterator).
    allow_struct: bool,
}

impl Parser {
    fn fresh(&mut self) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn current(&self) -> Token {
        if self.pending_gt {
            let span = self.tokens[self.pos.saturating_sub(1)].span;
            return Token {
                kind: TokenKind::Gt,
                span: Span::new(span.end.saturating_sub(1), span.end),
            };
        }
        self.tokens[self.pos].clone()
    }

    fn upcoming(&self, n: usize) -> TokenKind {
        // Lookahead ignores a split `>`. Callers use it for `::` `<`, never across `>>`.
        self.tokens
            .get(self.pos + n)
            .map(|t| t.kind.clone())
            .unwrap_or(TokenKind::Eof)
    }

    fn is(&self, kind: TokenKind) -> bool {
        std::mem::discriminant(&self.current().kind) == std::mem::discriminant(&kind)
    }

    fn bump(&mut self) -> Token {
        if self.pending_gt {
            self.pending_gt = false;
            let span = self.tokens[self.pos.saturating_sub(1)].span;
            self.last_end = span.end;
            return Token {
                kind: TokenKind::Gt,
                span: Span::new(span.end.saturating_sub(1), span.end),
            };
        }
        let tok = self.tokens[self.pos].clone();
        self.last_end = tok.span.end;
        if !matches!(tok.kind, TokenKind::Eof) {
            self.pos += 1;
        }
        tok
    }

    fn eat(&mut self, kind: TokenKind) -> bool {
        if self.is(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn eat_gt(&mut self) -> bool {
        if self.pending_gt {
            self.pending_gt = false;
            return true;
        }
        if self.is(TokenKind::Shr) {
            self.bump();
            self.pending_gt = true;
            return true;
        }
        self.eat(TokenKind::Gt)
    }

    fn is_gt(&self) -> bool {
        self.pending_gt || self.is(TokenKind::Gt) || self.is(TokenKind::Shr)
    }

    fn error_at(&mut self, span: Span, message: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::error(Code::E001, message).with_primary(span, ""));
    }

    fn error_here(&mut self, message: impl Into<String>) {
        let span = self.current().span;
        self.error_at(span, message);
    }

    fn expect(&mut self, kind: TokenKind, what: &str) -> bool {
        if self.eat(kind) {
            true
        } else {
            self.error_here(format!("expected {what}"));
            false
        }
    }

    fn expect_ident(&mut self) -> (String, Span) {
        let tok = self.current();
        if let TokenKind::Ident(name) = tok.kind {
            self.bump();
            (name, tok.span)
        } else {
            self.error_here("expected a name");
            ("_".to_string(), tok.span)
        }
    }

    fn span_start(&self) -> u32 {
        self.current().span.start
    }

    fn span_to(&self, start: u32) -> Span {
        Span::new(start, self.last_end.max(start))
    }

    fn parse_program(&mut self) -> Program {
        let start = self.span_start();
        let mut items = Vec::new();
        while !self.is(TokenKind::Eof) {
            if self.eat(TokenKind::Semi) {
                continue;
            }
            let before = (self.pos, self.pending_gt);
            match self.parse_item() {
                Some(item) => items.push(item),
                None => {
                    if (self.pos, self.pending_gt) == before {
                        self.bump();
                    }
                    self.skip_to_item();
                }
            }
        }
        Program {
            items,
            span: self.span_to(start),
        }
    }

    fn skip_to_item(&mut self) {
        let mut depth = 0i32;
        while !self.is(TokenKind::Eof) {
            if depth == 0 && self.at_item_start() {
                return;
            }
            if self.is(TokenKind::LBrace) {
                self.bump();
                depth += 1;
                continue;
            }
            if self.is(TokenKind::RBrace) {
                if depth == 0 {
                    return;
                }
                self.bump();
                depth -= 1;
                continue;
            }
            if depth == 0 && self.is(TokenKind::Semi) {
                self.bump();
                return;
            }
            self.bump();
        }
    }

    fn at_item_start(&self) -> bool {
        self.is(TokenKind::Fn)
            || self.is(TokenKind::Struct)
            || self.is(TokenKind::Enum)
            || self.is(TokenKind::Use)
            || self.is(TokenKind::Const)
            || self.is(TokenKind::Mod)
            || self.is(TokenKind::Hash)
    }

    fn parse_item(&mut self) -> Option<Item> {
        let start = self.span_start();
        let attrs = self.parse_attrs();
        let id = self.fresh();
        let kind = if self.is(TokenKind::Fn) {
            ItemKind::Fn(self.parse_fn())
        } else if self.is(TokenKind::Struct) {
            ItemKind::Struct(self.parse_struct())
        } else if self.is(TokenKind::Enum) {
            ItemKind::Enum(self.parse_enum())
        } else if self.is(TokenKind::Use) {
            ItemKind::Use(self.parse_use())
        } else if self.is(TokenKind::Const) {
            ItemKind::Const(self.parse_const())
        } else if self.is(TokenKind::Mod) {
            ItemKind::Mod(self.parse_mod())
        } else {
            if attrs.is_empty() {
                self.error_here("expected a function, struct, enum, use, const or mod");
            } else {
                self.error_here("expected an item after the attribute");
            }
            return None;
        };
        Some(Item {
            id,
            attrs,
            kind,
            span: self.span_to(start),
        })
    }

    fn parse_attrs(&mut self) -> Vec<Attr> {
        let mut attrs = Vec::new();
        while self.is(TokenKind::Hash) {
            let start = self.span_start();
            self.bump();
            self.expect(TokenKind::LBracket, "`[`");
            let (name, _) = self.expect_ident();
            let arg = if self.eat(TokenKind::LParen) {
                let (arg, _) = self.expect_ident();
                self.expect(TokenKind::RParen, "`)`");
                Some(arg)
            } else {
                None
            };
            self.expect(TokenKind::RBracket, "`]`");
            attrs.push(Attr {
                name,
                arg,
                span: self.span_to(start),
            });
        }
        attrs
    }

    fn parse_fn(&mut self) -> FnItem {
        self.expect(TokenKind::Fn, "`fn`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::LParen, "`(`");
        let mut params = Vec::new();
        if !self.is(TokenKind::RParen) {
            loop {
                let pstart = self.span_start();
                let (pname, _) = self.expect_ident();
                self.expect(TokenKind::Colon, "`:`");
                let ty = self.parse_type();
                params.push(Param {
                    name: pname,
                    ty,
                    span: self.span_to(pstart),
                });
                if !self.eat(TokenKind::Comma) {
                    break;
                }
                if self.is(TokenKind::RParen) {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen, "`)`");
        let ret = if self.eat(TokenKind::Arrow) {
            Some(self.parse_type())
        } else {
            None
        };
        let body = self.parse_block();
        FnItem {
            name,
            name_span,
            params,
            ret,
            body,
        }
    }

    fn parse_struct(&mut self) -> StructItem {
        self.expect(TokenKind::Struct, "`struct`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::LBrace, "`{`");
        let mut fields = Vec::new();
        while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
            let start = self.span_start();
            let (fname, _) = self.expect_ident();
            self.expect(TokenKind::Colon, "`:`");
            let ty = self.parse_type();
            fields.push(Field {
                name: fname,
                ty,
                span: self.span_to(start),
            });
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "`}`");
        StructItem {
            name,
            name_span,
            fields,
        }
    }

    fn parse_enum(&mut self) -> EnumItem {
        self.expect(TokenKind::Enum, "`enum`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::LBrace, "`{`");
        let mut variants = Vec::new();
        while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
            let start = self.span_start();
            let (vname, _) = self.expect_ident();
            let mut fields = Vec::new();
            if self.eat(TokenKind::LParen) {
                if !self.is(TokenKind::RParen) {
                    loop {
                        fields.push(self.parse_type());
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                        if self.is(TokenKind::RParen) {
                            break;
                        }
                    }
                }
                self.expect(TokenKind::RParen, "`)`");
            }
            variants.push(Variant {
                name: vname,
                fields,
                span: self.span_to(start),
            });
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "`}`");
        EnumItem {
            name,
            name_span,
            variants,
        }
    }

    fn parse_use(&mut self) -> UseItem {
        let start = self.span_start();
        self.expect(TokenKind::Use, "`use`");
        let mut module = Vec::new();
        let (first, _) = self.expect_ident();
        module.push(first);
        loop {
            if self.eat(TokenKind::Dot) {
                let (name, _) = self.expect_ident();
                module.push(name);
                continue;
            }
            break;
        }
        let names = if self.eat(TokenKind::ColonColon) {
            if self.eat(TokenKind::LBrace) {
                let mut names = Vec::new();
                if !self.is(TokenKind::RBrace) {
                    loop {
                        let (name, _) = self.expect_ident();
                        names.push(name);
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                        if self.is(TokenKind::RBrace) {
                            break;
                        }
                    }
                }
                self.expect(TokenKind::RBrace, "`}`");
                names
            } else {
                let (name, _) = self.expect_ident();
                vec![name]
            }
        } else {
            Vec::new()
        };
        self.expect(TokenKind::Semi, "`;`");
        UseItem {
            module,
            names,
            span: self.span_to(start),
        }
    }

    fn parse_const(&mut self) -> ConstItem {
        self.expect(TokenKind::Const, "`const`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::Colon, "`:`");
        let ty = self.parse_type();
        self.expect(TokenKind::Eq, "`=`");
        let value = self.parse_expr();
        self.expect(TokenKind::Semi, "`;`");
        ConstItem {
            name,
            name_span,
            ty,
            value,
        }
    }

    fn parse_mod(&mut self) -> ModItem {
        self.expect(TokenKind::Mod, "`mod`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::Semi, "`;`");
        ModItem { name, name_span }
    }

    fn parse_block(&mut self) -> Block {
        let start = self.span_start();
        if !self.expect(TokenKind::LBrace, "`{`") {
            return Block {
                id: self.fresh(),
                stmts: Vec::new(),
                tail: None,
                span: self.span_to(start),
            };
        }
        let saved_struct = self.allow_struct;
        self.allow_struct = true;
        let mut stmts = Vec::new();
        let mut tail = None;
        while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
            let before = (self.pos, self.pending_gt);
            if self.is(TokenKind::Let) {
                stmts.push(self.parse_let());
            } else if self.is(TokenKind::While) {
                stmts.push(self.parse_while());
            } else if self.is(TokenKind::For) {
                stmts.push(self.parse_for());
            } else if self.is(TokenKind::Return) {
                stmts.push(self.parse_return());
            } else if self.is_assign_start() {
                stmts.push(self.parse_assign());
            } else {
                let expr = self.parse_expr();
                if self.eat(TokenKind::Semi) {
                    let span = expr.span;
                    stmts.push(Stmt {
                        id: self.fresh(),
                        kind: StmtKind::Expr(expr),
                        span,
                    });
                } else if self.is(TokenKind::RBrace) {
                    tail = Some(expr);
                    break;
                } else if is_blocky(&expr) {
                    let span = expr.span;
                    stmts.push(Stmt {
                        id: self.fresh(),
                        kind: StmtKind::Expr(expr),
                        span,
                    });
                } else {
                    self.error_here("expected `;` after this expression");
                    let span = expr.span;
                    stmts.push(Stmt {
                        id: self.fresh(),
                        kind: StmtKind::Expr(expr),
                        span,
                    });
                    if (self.pos, self.pending_gt) == before {
                        break;
                    }
                }
            }
            if (self.pos, self.pending_gt) == before {
                self.error_here("could not parse the next statement");
                self.bump();
            }
        }
        self.expect(TokenKind::RBrace, "`}`");
        self.allow_struct = saved_struct;
        Block {
            id: self.fresh(),
            stmts,
            tail,
            span: self.span_to(start),
        }
    }

    fn is_assign_start(&self) -> bool {
        matches!(self.current().kind, TokenKind::Ident(_))
            && matches!(self.upcoming(1), TokenKind::Eq)
    }

    fn parse_let(&mut self) -> Stmt {
        let start = self.span_start();
        self.expect(TokenKind::Let, "`let`");
        let mutable = self.eat(TokenKind::Mut);
        let mut pat = self.parse_pattern();
        if mutable {
            match &mut pat.kind {
                PatKind::Binding { mutable, .. } => *mutable = true,
                _ => self.error_at(pat.span, "`mut` only applies to a name"),
            }
        }
        let ty = if self.eat(TokenKind::Colon) {
            Some(self.parse_type())
        } else {
            None
        };
        self.expect(TokenKind::Eq, "`=`");
        let value = self.parse_expr();
        self.expect(TokenKind::Semi, "`;`");
        Stmt {
            id: self.fresh(),
            kind: StmtKind::Let {
                mutable,
                pat,
                ty,
                value,
            },
            span: self.span_to(start),
        }
    }

    fn parse_assign(&mut self) -> Stmt {
        let start = self.span_start();
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::Eq, "`=`");
        let value = self.parse_expr();
        self.expect(TokenKind::Semi, "`;`");
        Stmt {
            id: self.fresh(),
            kind: StmtKind::Assign {
                name,
                name_span,
                value,
            },
            span: self.span_to(start),
        }
    }

    fn parse_while(&mut self) -> Stmt {
        let start = self.span_start();
        self.expect(TokenKind::While, "`while`");
        let cond = self.parse_expr_no_struct();
        let body = self.parse_block();
        Stmt {
            id: self.fresh(),
            kind: StmtKind::While {
                cond,
                body: Box::new(body),
            },
            span: self.span_to(start),
        }
    }

    fn parse_for(&mut self) -> Stmt {
        let start = self.span_start();
        self.expect(TokenKind::For, "`for`");
        let (name, name_span) = self.expect_ident();
        self.expect(TokenKind::In, "`in`");
        let iter = self.parse_expr_no_struct();
        let body = self.parse_block();
        Stmt {
            id: self.fresh(),
            kind: StmtKind::For {
                name,
                name_span,
                iter,
                body: Box::new(body),
            },
            span: self.span_to(start),
        }
    }

    fn parse_return(&mut self) -> Stmt {
        let start = self.span_start();
        self.expect(TokenKind::Return, "`return`");
        let value = if self.is(TokenKind::Semi) || self.is(TokenKind::RBrace) {
            None
        } else {
            Some(self.parse_expr())
        };
        self.expect(TokenKind::Semi, "`;`");
        Stmt {
            id: self.fresh(),
            kind: StmtKind::Return(value),
            span: self.span_to(start),
        }
    }

    fn parse_type(&mut self) -> TypeExpr {
        let start = self.span_start();
        let mut labels = Vec::new();
        loop {
            let word = if self.is(TokenKind::Secret) {
                LabelWord::Secret
            } else if self.is(TokenKind::Untrusted) {
                LabelWord::Untrusted
            } else if self.is(TokenKind::Public) {
                LabelWord::Public
            } else if self.is(TokenKind::Trusted) {
                LabelWord::Trusted
            } else {
                break;
            };
            let span = self.bump().span;
            labels.push(LabelTok { word, span });
        }
        let (kind, _) = self.parse_type_kind();
        TypeExpr {
            id: self.fresh(),
            labels,
            kind,
            span: self.span_to(start),
        }
    }

    fn parse_type_kind(&mut self) -> (TypeKind, Span) {
        let start = self.span_start();
        if self.eat(TokenKind::LParen) {
            if self.eat(TokenKind::RParen) {
                return (TypeKind::Unit, self.span_to(start));
            }
            let mut types = vec![self.parse_type()];
            let mut comma = false;
            while self.eat(TokenKind::Comma) {
                comma = true;
                if self.is(TokenKind::RParen) {
                    break;
                }
                types.push(self.parse_type());
            }
            self.expect(TokenKind::RParen, "`)`");
            if !comma && types.len() == 1 {
                let t = types.pop().unwrap();
                return (t.kind, t.span);
            }
            return (TypeKind::Tuple(types), self.span_to(start));
        }
        if self.eat(TokenKind::LBracket) {
            let elem = Box::new(self.parse_type());
            self.expect(TokenKind::Semi, "`;`");
            let len = if let TokenKind::Int(v, _) = self.current().kind {
                self.bump();
                ArrayLen::Int(v)
            } else if let TokenKind::Ident(name) = self.current().kind.clone() {
                let span = self.bump().span;
                ArrayLen::Name(name, span)
            } else {
                self.error_here("expected an array length");
                ArrayLen::Int(0)
            };
            self.expect(TokenKind::RBracket, "`]`");
            return (TypeKind::Array { elem, len }, self.span_to(start));
        }
        if matches!(self.current().kind, TokenKind::Ident(_)) {
            let path = self.parse_path_type();
            return (TypeKind::Named(path), self.span_to(start));
        }
        self.error_here("expected a type");
        (TypeKind::Error, self.span_to(start))
    }

    fn parse_path_type(&mut self) -> Path {
        let start = self.span_start();
        let mut segments = Vec::new();
        loop {
            let (name, span) = self.expect_ident();
            segments.push(PathSeg {
                name,
                args: Vec::new(),
                span,
            });
            // Look at the raw next token so a type argument `<` is not confused
            // with a split `>>`.
            if !self.pending_gt && self.is(TokenKind::ColonColon) {
                let after = self.upcoming(1).clone();
                if matches!(after, TokenKind::Ident(_)) {
                    self.bump();
                    continue;
                }
            }
            break;
        }
        if self.is(TokenKind::Lt) || self.is(TokenKind::Shr) {
            let args = self.parse_generic_args();
            if let Some(last) = segments.last_mut() {
                last.args = args;
                last.span = self.span_to(last.span.start);
            }
        }
        Path {
            segments,
            span: self.span_to(start),
        }
    }

    fn parse_path_expr(&mut self) -> Path {
        let start = self.span_start();
        let mut segments = Vec::new();
        loop {
            let (name, span) = self.expect_ident();
            let mut seg = PathSeg {
                name,
                args: Vec::new(),
                span,
            };
            if !self.pending_gt
                && self.is(TokenKind::ColonColon)
                && matches!(self.upcoming(1), TokenKind::Lt)
            {
                self.bump(); // ::
                seg.args = self.parse_generic_args();
                seg.span = self.span_to(seg.span.start);
            }
            segments.push(seg);
            if !self.pending_gt
                && self.is(TokenKind::ColonColon)
                && matches!(self.upcoming(1), TokenKind::Ident(_))
            {
                self.bump();
                continue;
            }
            break;
        }
        Path {
            segments,
            span: self.span_to(start),
        }
    }

    fn parse_generic_args(&mut self) -> Vec<GenericArg> {
        if !self.eat(TokenKind::Lt) && !self.is(TokenKind::Shr) && !self.pending_gt {
            // `>>` begins with a `>` via eat_gt, but the opener must be `<`.
            self.error_here("expected `<`");
            return Vec::new();
        }
        // `eat(Lt)` above. Shr is not a valid opener.
        if self.is_gt() {
            self.eat_gt();
            return Vec::new();
        }
        let mut args = Vec::new();
        loop {
            args.push(self.parse_generic_arg());
            if self.eat(TokenKind::Comma) {
                if self.is_gt() {
                    self.eat_gt();
                    break;
                }
                continue;
            }
            if !self.eat_gt() {
                self.error_here("expected `>` after type arguments");
            }
            break;
        }
        args
    }

    fn parse_generic_arg(&mut self) -> GenericArg {
        match self.current().kind.clone() {
            TokenKind::String(s) => {
                let span = self.bump().span;
                GenericArg::Str(s, span)
            }
            TokenKind::Int(v, _) => {
                let span = self.bump().span;
                GenericArg::Int(v, span)
            }
            _ => GenericArg::Type(self.parse_type()),
        }
    }

    fn parse_expr(&mut self) -> Expr {
        self.parse_prec(0)
    }

    /// Expression in a position where a following `{` belongs to the surrounding
    /// construct (`if`, `while`, `match`, `for`) rather than a struct literal.
    fn parse_expr_no_struct(&mut self) -> Expr {
        let saved = self.allow_struct;
        self.allow_struct = false;
        let expr = self.parse_expr();
        self.allow_struct = saved;
        expr
    }

    fn parse_prec(&mut self, min: u8) -> Expr {
        let mut left = self.parse_unary();
        while let Some((prec, op)) = infix_op(&self.current().kind) {
            if prec < min {
                break;
            }
            self.bump();
            let right = self.parse_prec(prec + 1);
            let span = left.span.merge(right.span);
            left = Expr {
                id: self.fresh(),
                kind: ExprKind::Binary {
                    op,
                    lhs: Box::new(left),
                    rhs: Box::new(right),
                },
                span,
            };
        }
        left
    }

    fn parse_unary(&mut self) -> Expr {
        let start = self.span_start();
        if self.eat(TokenKind::Bang) {
            let expr = self.parse_unary();
            let span = self.span_to(start).merge(expr.span);
            return Expr {
                id: self.fresh(),
                kind: ExprKind::Unary {
                    op: UnOp::Not,
                    expr: Box::new(expr),
                },
                span,
            };
        }
        if self.is(TokenKind::Minus) {
            // Negative numeric literal, so `-1` is one constant rather than a
            // unary operator the const evaluator has to special-case.
            if let TokenKind::Int(v, suffix) = self.upcoming(1) {
                self.bump();
                self.bump();
                let value = match i128::try_from(v) {
                    Ok(n) => n.checked_neg().unwrap_or_else(|| {
                        self.error_at(self.span_to(start), "integer literal does not fit in i64");
                        0
                    }),
                    Err(_) => {
                        self.error_at(self.span_to(start), "integer literal does not fit in i64");
                        0
                    }
                };
                return Expr {
                    id: self.fresh(),
                    kind: ExprKind::Int { value, suffix },
                    span: self.span_to(start),
                };
            }
            self.bump();
            let expr = self.parse_unary();
            let span = self.span_to(start).merge(expr.span);
            return Expr {
                id: self.fresh(),
                kind: ExprKind::Unary {
                    op: UnOp::Neg,
                    expr: Box::new(expr),
                },
                span,
            };
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Expr {
        let mut expr = self.parse_primary();
        loop {
            if self.eat(TokenKind::Dot) {
                let (name, name_span) = self.expect_ident();
                let mut type_args = Vec::new();
                if !self.pending_gt
                    && self.is(TokenKind::ColonColon)
                    && matches!(self.upcoming(1), TokenKind::Lt)
                {
                    self.bump();
                    type_args = self.parse_generic_args();
                }
                if self.is(TokenKind::LParen) {
                    let args = self.parse_call_args();
                    let span = expr.span.merge(self.span_to(name_span.start));
                    expr = Expr {
                        id: self.fresh(),
                        kind: ExprKind::Method {
                            receiver: Box::new(expr),
                            name,
                            name_span,
                            type_args,
                            args,
                        },
                        span,
                    };
                } else {
                    if !type_args.is_empty() {
                        self.error_here("a field access cannot take type arguments");
                    }
                    let span = expr.span.merge(name_span);
                    expr = Expr {
                        id: self.fresh(),
                        kind: ExprKind::Field {
                            base: Box::new(expr),
                            name,
                            name_span,
                        },
                        span,
                    };
                }
            } else if self.is(TokenKind::LParen) {
                let args = self.parse_call_args();
                let end = args.last().map(|a| a.span.end).unwrap_or(self.last_end);
                let span = Span::new(expr.span.start, end.max(self.last_end));
                expr = Expr {
                    id: self.fresh(),
                    kind: ExprKind::Call {
                        callee: Box::new(expr),
                        args,
                    },
                    span,
                };
            } else if self.eat(TokenKind::LBracket) {
                let index = self.parse_expr();
                self.expect(TokenKind::RBracket, "`]`");
                let span = expr.span.merge(self.span_to(index.span.start));
                expr = Expr {
                    id: self.fresh(),
                    kind: ExprKind::Index {
                        base: Box::new(expr),
                        index: Box::new(index),
                    },
                    span,
                };
            } else if self.eat(TokenKind::Question) {
                let span = expr.span.merge(self.span_to(expr.span.start));
                expr = Expr {
                    id: self.fresh(),
                    kind: ExprKind::Try(Box::new(expr)),
                    span,
                };
            } else {
                break;
            }
        }
        expr
    }

    fn parse_call_args(&mut self) -> Vec<Expr> {
        self.expect(TokenKind::LParen, "`(`");
        let mut args = Vec::new();
        if !self.is(TokenKind::RParen) {
            loop {
                args.push(self.parse_expr());
                if !self.eat(TokenKind::Comma) {
                    break;
                }
                if self.is(TokenKind::RParen) {
                    break;
                }
            }
        }
        self.expect(TokenKind::RParen, "`)`");
        args
    }

    fn parse_primary(&mut self) -> Expr {
        let start = self.span_start();
        let tok = self.current();
        match tok.kind {
            TokenKind::Int(value, suffix) => {
                self.bump();
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Int {
                        value: fit_i128(value),
                        suffix,
                    },
                    span: tok.span,
                }
            }
            TokenKind::String(s) => {
                self.bump();
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::String(s),
                    span: tok.span,
                }
            }
            TokenKind::Bytes(b) => {
                self.bump();
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Bytes(b),
                    span: tok.span,
                }
            }
            TokenKind::True => {
                self.bump();
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Bool(true),
                    span: tok.span,
                }
            }
            TokenKind::False => {
                self.bump();
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Bool(false),
                    span: tok.span,
                }
            }
            TokenKind::If => self.parse_if(),
            TokenKind::Match => self.parse_match(),
            TokenKind::Pipe => self.parse_lambda(),
            TokenKind::LParen => self.parse_paren(),
            TokenKind::LBrace => {
                let block = self.parse_block();
                let span = block.span;
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Block(Box::new(block)),
                    span,
                }
            }
            TokenKind::LBracket => self.parse_array(),
            TokenKind::Ident(_) => {
                let path = self.parse_path_expr();
                if self.allow_struct && self.is(TokenKind::LBrace) {
                    self.parse_struct_lit(path)
                } else {
                    let span = path.span;
                    Expr {
                        id: self.fresh(),
                        kind: ExprKind::Path(path),
                        span,
                    }
                }
            }
            _ => {
                self.error_here("expected an expression");
                if !self.is_sync() {
                    self.bump();
                }
                Expr::error(self.fresh(), self.span_to(start))
            }
        }
    }

    fn is_sync(&self) -> bool {
        matches!(
            self.current().kind,
            TokenKind::Semi
                | TokenKind::RBrace
                | TokenKind::RParen
                | TokenKind::RBracket
                | TokenKind::Eof
                | TokenKind::Comma
        )
    }

    fn parse_paren(&mut self) -> Expr {
        let start = self.span_start();
        self.expect(TokenKind::LParen, "`(`");
        let saved_struct = self.allow_struct;
        self.allow_struct = true;
        if self.eat(TokenKind::RParen) {
            self.allow_struct = saved_struct;
            return Expr {
                id: self.fresh(),
                kind: ExprKind::Unit,
                span: self.span_to(start),
            };
        }
        let first = self.parse_expr();
        if self.eat(TokenKind::Comma) {
            let mut xs = vec![first];
            if !self.is(TokenKind::RParen) {
                loop {
                    xs.push(self.parse_expr());
                    if !self.eat(TokenKind::Comma) {
                        break;
                    }
                    if self.is(TokenKind::RParen) {
                        break;
                    }
                }
            }
            self.expect(TokenKind::RParen, "`)`");
            self.allow_struct = saved_struct;
            Expr {
                id: self.fresh(),
                kind: ExprKind::Tuple(xs),
                span: self.span_to(start),
            }
        } else {
            self.expect(TokenKind::RParen, "`)`");
            self.allow_struct = saved_struct;
            first
        }
    }

    fn parse_array(&mut self) -> Expr {
        let start = self.span_start();
        self.expect(TokenKind::LBracket, "`[`");
        if self.eat(TokenKind::RBracket) {
            return Expr {
                id: self.fresh(),
                kind: ExprKind::Array(Vec::new()),
                span: self.span_to(start),
            };
        }
        let first = self.parse_expr();
        if self.eat(TokenKind::Semi) {
            let len = self.parse_expr();
            self.expect(TokenKind::RBracket, "`]`");
            return Expr {
                id: self.fresh(),
                kind: ExprKind::Repeat {
                    value: Box::new(first),
                    len: Box::new(len),
                },
                span: self.span_to(start),
            };
        }
        let mut xs = vec![first];
        while self.eat(TokenKind::Comma) {
            if self.is(TokenKind::RBracket) {
                break;
            }
            xs.push(self.parse_expr());
        }
        self.expect(TokenKind::RBracket, "`]`");
        Expr {
            id: self.fresh(),
            kind: ExprKind::Array(xs),
            span: self.span_to(start),
        }
    }

    fn parse_if(&mut self) -> Expr {
        let start = self.span_start();
        self.expect(TokenKind::If, "`if`");
        let cond = self.parse_expr_no_struct();
        let then_branch = self.parse_block();
        let else_branch = if self.eat(TokenKind::Else) {
            if self.is(TokenKind::If) {
                Some(Box::new(self.parse_if()))
            } else {
                let block = self.parse_block();
                let span = block.span;
                Some(Box::new(Expr {
                    id: self.fresh(),
                    kind: ExprKind::Block(Box::new(block)),
                    span,
                }))
            }
        } else {
            None
        };
        let end = else_branch
            .as_ref()
            .map(|e| e.span.end)
            .unwrap_or(then_branch.span.end);
        Expr {
            id: self.fresh(),
            kind: ExprKind::If {
                cond: Box::new(cond),
                then_branch: Box::new(then_branch),
                else_branch,
            },
            span: Span::new(start, end),
        }
    }

    fn parse_match(&mut self) -> Expr {
        let start = self.span_start();
        self.expect(TokenKind::Match, "`match`");
        let scrutinee = self.parse_expr_no_struct();
        self.expect(TokenKind::LBrace, "`{`");
        let mut arms = Vec::new();
        while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
            let astart = self.span_start();
            let pat = self.parse_pattern();
            self.expect(TokenKind::FatArrow, "`=>`");
            let body = if self.is(TokenKind::LBrace) {
                let block = self.parse_block();
                let span = block.span;
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Block(Box::new(block)),
                    span,
                }
            } else {
                self.parse_expr()
            };
            let span = Span::new(astart, body.span.end);
            arms.push(Arm { pat, body, span });
            if !self.eat(TokenKind::Comma) && !self.is(TokenKind::RBrace) {
                // A block arm does not need a comma. Anything else does,
                // unless the match is over.
                if !matches!(arms.last().map(|a| &a.body.kind), Some(ExprKind::Block(_))) {
                    self.error_here("expected `,` between match arms");
                }
            }
        }
        self.expect(TokenKind::RBrace, "`}`");
        Expr {
            id: self.fresh(),
            kind: ExprKind::Match {
                scrutinee: Box::new(scrutinee),
                arms,
            },
            span: self.span_to(start),
        }
    }

    fn parse_lambda(&mut self) -> Expr {
        let start = self.span_start();
        self.expect(TokenKind::Pipe, "`|`");
        let mut params = Vec::new();
        if !self.is(TokenKind::Pipe) {
            loop {
                let pstart = self.span_start();
                let (name, _) = self.expect_ident();
                let ty = if self.eat(TokenKind::Colon) {
                    Some(self.parse_type())
                } else {
                    None
                };
                params.push(LambdaParam {
                    name,
                    ty,
                    span: self.span_to(pstart),
                });
                if !self.eat(TokenKind::Comma) {
                    break;
                }
                if self.is(TokenKind::Pipe) {
                    break;
                }
            }
        }
        self.expect(TokenKind::Pipe, "`|`");
        let body = self.parse_expr();
        let span = Span::new(start, body.span.end.max(self.last_end));
        Expr {
            id: self.fresh(),
            kind: ExprKind::Lambda {
                params,
                body: Box::new(body),
            },
            span,
        }
    }

    fn parse_struct_lit(&mut self, path: Path) -> Expr {
        let start = path.span.start;
        self.expect(TokenKind::LBrace, "`{`");
        let mut fields = Vec::new();
        while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
            let fstart = self.span_start();
            let (name, _) = self.expect_ident();
            let value = if self.eat(TokenKind::Colon) {
                self.parse_expr()
            } else {
                // Shorthand: `Point { x }` means `x: x`.
                Expr {
                    id: self.fresh(),
                    kind: ExprKind::Path(Path {
                        segments: vec![PathSeg {
                            name: name.clone(),
                            args: Vec::new(),
                            span: Span::new(fstart, self.last_end),
                        }],
                        span: Span::new(fstart, self.last_end),
                    }),
                    span: Span::new(fstart, self.last_end),
                }
            };
            fields.push(StructFieldInit {
                name,
                value,
                span: self.span_to(fstart),
            });
            if !self.eat(TokenKind::Comma) {
                break;
            }
        }
        self.expect(TokenKind::RBrace, "`}`");
        Expr {
            id: self.fresh(),
            kind: ExprKind::Struct { path, fields },
            span: self.span_to(start),
        }
    }

    fn parse_pattern(&mut self) -> Pattern {
        let start = self.span_start();
        if self.is(TokenKind::Ident(String::new())) {
            if let TokenKind::Ident(name) = self.current().kind.clone() {
                if name == "_" {
                    let span = self.bump().span;
                    return Pattern {
                        id: self.fresh(),
                        kind: PatKind::Wild,
                        span,
                    };
                }
            }
        }
        if self.eat(TokenKind::Mut) {
            let (name, span) = self.expect_ident();
            return Pattern {
                id: self.fresh(),
                kind: PatKind::Binding {
                    name,
                    mutable: true,
                },
                span: self.span_to(start).merge(span),
            };
        }
        match self.current().kind.clone() {
            TokenKind::True => {
                let span = self.bump().span;
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::LitBool(true),
                    span,
                }
            }
            TokenKind::False => {
                let span = self.bump().span;
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::LitBool(false),
                    span,
                }
            }
            TokenKind::Int(v, _) => {
                let span = self.bump().span;
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::LitInt(fit_i128(v)),
                    span,
                }
            }
            TokenKind::String(s) => {
                let span = self.bump().span;
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::LitStr(s),
                    span,
                }
            }
            TokenKind::Minus => {
                self.bump();
                if let TokenKind::Int(v, _) = self.current().kind {
                    let span = self.bump().span;
                    let value = fit_i128(v).checked_neg().unwrap_or(0);
                    Pattern {
                        id: self.fresh(),
                        kind: PatKind::LitInt(value),
                        span: self.span_to(start).merge(span),
                    }
                } else {
                    self.error_here("expected an integer after `-` in a pattern");
                    Pattern {
                        id: self.fresh(),
                        kind: PatKind::Wild,
                        span: self.span_to(start),
                    }
                }
            }
            TokenKind::LParen => {
                self.bump();
                let mut pats = Vec::new();
                if !self.is(TokenKind::RParen) {
                    loop {
                        pats.push(self.parse_pattern());
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                        if self.is(TokenKind::RParen) {
                            break;
                        }
                    }
                }
                self.expect(TokenKind::RParen, "`)`");
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::Tuple(pats),
                    span: self.span_to(start),
                }
            }
            TokenKind::Ident(_) => {
                let path = self.parse_path_expr();
                if path.segments.len() == 1
                    && path.segments[0].args.is_empty()
                    && !self.is(TokenKind::LParen)
                    && !self.is(TokenKind::LBrace)
                {
                    let name = path.segments[0].name.clone();
                    return Pattern {
                        id: self.fresh(),
                        kind: PatKind::Binding {
                            name,
                            mutable: false,
                        },
                        span: path.span,
                    };
                }
                if self.is(TokenKind::LParen) {
                    self.bump();
                    let mut args = Vec::new();
                    if !self.is(TokenKind::RParen) {
                        loop {
                            args.push(self.parse_pattern());
                            if !self.eat(TokenKind::Comma) {
                                break;
                            }
                            if self.is(TokenKind::RParen) {
                                break;
                            }
                        }
                    }
                    self.expect(TokenKind::RParen, "`)`");
                    return Pattern {
                        id: self.fresh(),
                        kind: PatKind::Variant { path, args },
                        span: self.span_to(start),
                    };
                }
                if self.is(TokenKind::LBrace) {
                    self.bump();
                    let mut fields = Vec::new();
                    while !self.is(TokenKind::RBrace) && !self.is(TokenKind::Eof) {
                        let fstart = self.span_start();
                        let (name, _) = self.expect_ident();
                        let pat = if self.eat(TokenKind::Colon) {
                            self.parse_pattern()
                        } else {
                            Pattern {
                                id: self.fresh(),
                                kind: PatKind::Binding {
                                    name: name.clone(),
                                    mutable: false,
                                },
                                span: self.span_to(fstart),
                            }
                        };
                        fields.push(FieldPat {
                            name,
                            pat,
                            span: self.span_to(fstart),
                        });
                        if !self.eat(TokenKind::Comma) {
                            break;
                        }
                    }
                    self.expect(TokenKind::RBrace, "`}`");
                    return Pattern {
                        id: self.fresh(),
                        kind: PatKind::Struct { path, fields },
                        span: self.span_to(start),
                    };
                }
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::Variant {
                        path,
                        args: Vec::new(),
                    },
                    span: self.span_to(start),
                }
            }
            _ => {
                self.error_here("expected a pattern");
                if !self.is_sync() {
                    self.bump();
                }
                Pattern {
                    id: self.fresh(),
                    kind: PatKind::Wild,
                    span: self.span_to(start),
                }
            }
        }
    }
}

fn fit_i128(v: u128) -> i128 {
    i128::try_from(v).unwrap_or(i128::MAX)
}

fn is_blocky(expr: &Expr) -> bool {
    matches!(
        expr.kind,
        ExprKind::If { .. } | ExprKind::Match { .. } | ExprKind::Block(_)
    )
}

fn infix_op(kind: &TokenKind) -> Option<(u8, BinOp)> {
    let (prec, op) = match kind {
        TokenKind::DotDot => (1, BinOp::Range),
        TokenKind::OrOr => (2, BinOp::Or),
        TokenKind::AndAnd => (3, BinOp::And),
        TokenKind::EqEq => (4, BinOp::Eq),
        TokenKind::NotEq => (4, BinOp::Ne),
        TokenKind::Lt => (5, BinOp::Lt),
        TokenKind::Gt => (5, BinOp::Gt),
        TokenKind::Le => (5, BinOp::Le),
        TokenKind::Ge => (5, BinOp::Ge),
        TokenKind::Pipe => (6, BinOp::BitOr),
        TokenKind::Caret => (7, BinOp::BitXor),
        TokenKind::Amp => (8, BinOp::BitAnd),
        TokenKind::Shl => (9, BinOp::Shl),
        TokenKind::Shr => (9, BinOp::Shr),
        TokenKind::Plus => (10, BinOp::Add),
        TokenKind::Minus => (10, BinOp::Sub),
        TokenKind::Star => (11, BinOp::Mul),
        TokenKind::Slash => (11, BinOp::Div),
        TokenKind::Percent => (11, BinOp::Rem),
        _ => return None,
    };
    Some((prec, op))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) -> Program {
        let file = SourceFile::new("t.mo", src);
        let out = parse(&file);
        if mohar_diag::has_errors(&out.diagnostics) {
            panic!(
                "parse failed:\n{}\n{}",
                src,
                mohar_diag::render_all(&file, &out.diagnostics)
            );
        }
        out.program
    }

    #[test]
    fn parses_hello() {
        let p = parse_ok(
            r#"
            fn main(caps: Caps) {
                let out = caps.console();
                out.println("namaste, duniya");
            }
            "#,
        );
        assert_eq!(p.items.len(), 1);
    }

    #[test]
    fn parses_labels_and_turbofish() {
        let p = parse_ok(
            r#"
            fn main(caps: Caps) {
                let key: secret [u8; 32] = caps.rand().secret_bytes::<32>();
                let docs = caps.fs_read::<"./inbox">();
            }
            "#,
        );
        assert_eq!(p.items.len(), 1);
    }

    #[test]
    fn parses_use_forms() {
        let p = parse_ok(
            r#"
            use std.ct;
            use std.pq::{Kem, KemPublicKey};
            use std.legacy::ecdsa_p256;
            "#,
        );
        assert_eq!(p.items.len(), 3);
    }

    #[test]
    fn parses_profile_and_match() {
        let p = parse_ok(
            r#"
            enum Color { Red, Blue(i64) }
            #[profile(plan)]
            fn main(caps: Caps) -> i64 {
                let c = Color::Blue(3);
                match c {
                    Color::Red => 0,
                    Color::Blue(n) => n,
                }
            }
            "#,
        );
        assert_eq!(p.items.len(), 2);
    }

    #[test]
    fn reports_a_real_span_for_junk() {
        let file = SourceFile::new("bad.mo", "fn main(caps: Caps) { let = 1; }\n");
        let out = parse(&file);
        assert!(mohar_diag::has_errors(&out.diagnostics));
        let text = mohar_diag::render_all(&file, &out.diagnostics);
        assert!(text.contains("error[E001]"));
        assert!(text.contains("--> bad.mo:"));
    }

    #[test]
    fn parser_does_not_panic_on_noise() {
        let samples = [
            "",
            "fn",
            "@@@@",
            "fn main(caps: Caps) {",
            "let",
            "\"unterminated",
            "/*",
            "1 + + +",
            "match",
        ];
        for src in samples {
            let file = SourceFile::new("noise.mo", src);
            let _ = parse(&file);
        }
    }

    #[test]
    fn lexer_keeps_going_after_a_bad_byte() {
        let file = SourceFile::new("bad.mo", "fn main(caps: Caps) { let x = 1 $ 2; }\n");
        let out = parse(&file);
        assert!(
            out.diagnostics
                .iter()
                .any(|d| d.message.contains("unexpected"))
        );
    }
}
