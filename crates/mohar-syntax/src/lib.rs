//! Lexer, parser and AST for Mohar.
//!
//! The lexer is a straight scan of UTF-8. The parser is recursive descent
//! with Pratt precedence for expressions. Neither panics on bad input:
//! both return diagnostics and a partial tree so later errors still surface.

mod ast;
mod lexer;
mod parser;
pub mod print;
mod token;

pub use ast::*;
pub use lexer::lex;
pub use parser::{ParseOutput, parse};
pub use token::{IntSuffix, Token, TokenKind};

use mohar_diag::SourceFile;

/// Lex and parse one file.
pub fn parse_source(name: &str, source: &str) -> ParseOutput {
    let file = SourceFile::new(name, source);
    parse(&file)
}
