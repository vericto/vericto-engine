// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Lexer, syntax tree and parser for the CEL subset Vericto policies use.
//!
//! The grammar is CEL's (cel-spec `doc/langdef.md`), restricted to what a
//! policy over SQL facts needs: literals (int, uint, double, string, bool,
//! null), lists, maps, field selection, indexing, calls, the unary, binary
//! and conditional operators, and the macros `has`, `all`, `exists`,
//! `exists_one`, `map` and `filter`. Bytes literals, message construction
//! and `.`-prefixed absolute names are not part of the subset and are
//! refused with a positioned error, so a document that parses here is
//! standard CEL that any CEL implementation reads the same way.
//!
//! The parser is recursive descent with an explicit depth limit
//! ([`MAX_PARSE_DEPTH`]): the input is bounded (2 KiB) but parentheses can
//! still nest deeply, and running out of stack is an abort, not an error.

use std::fmt;

/// Deepest nesting the parser accepts (parentheses, lists, calls, operators).
pub(crate) const MAX_PARSE_DEPTH: usize = 64;

/// A byte offset into the expression source.
pub(crate) type Pos = usize;

/// A parse or check error, positioned at a byte offset of the expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at offset {})", self.message, self.offset)
    }
}

fn err<T>(offset: usize, message: impl Into<String>) -> Result<T, SyntaxError> {
    Err(SyntaxError {
        offset,
        message: message.into(),
    })
}

// ---------------------------------------------------------------------------
// Tokens

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Tok {
    Ident(String),
    Int(i64),
    Uint(u64),
    Double(f64),
    Str(String),
    True,
    False,
    Null,
    In,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Dot,
    Comma,
    Colon,
    Question,
    OrOr,
    AndAnd,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eof,
}

/// CEL reserved words that are not identifiers (cel-spec "Syntax").
const RESERVED: &[&str] = &[
    "as",
    "break",
    "const",
    "continue",
    "else",
    "for",
    "function",
    "if",
    "import",
    "let",
    "loop",
    "package",
    "namespace",
    "return",
    "var",
    "void",
    "while",
];

pub(crate) fn lex(src: &str) -> Result<Vec<(Tok, Pos)>, SyntaxError> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // `//` comments run to the end of the line (cel-spec allows them).
        if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        let two = |a: u8, b: u8| c == a && bytes.get(i + 1) == Some(&b);
        let tok = if two(b'|', b'|') {
            i += 2;
            Tok::OrOr
        } else if two(b'&', b'&') {
            i += 2;
            Tok::AndAnd
        } else if two(b'=', b'=') {
            i += 2;
            Tok::Eq
        } else if two(b'!', b'=') {
            i += 2;
            Tok::Ne
        } else if two(b'<', b'=') {
            i += 2;
            Tok::Le
        } else if two(b'>', b'=') {
            i += 2;
            Tok::Ge
        } else {
            match c {
                b'(' => single(&mut i, Tok::LParen),
                b')' => single(&mut i, Tok::RParen),
                b'[' => single(&mut i, Tok::LBracket),
                b']' => single(&mut i, Tok::RBracket),
                b'{' => single(&mut i, Tok::LBrace),
                b'}' => single(&mut i, Tok::RBrace),
                b'.' if !bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                    single(&mut i, Tok::Dot)
                }
                b',' => single(&mut i, Tok::Comma),
                b':' => single(&mut i, Tok::Colon),
                b'?' => single(&mut i, Tok::Question),
                b'!' => single(&mut i, Tok::Not),
                b'<' => single(&mut i, Tok::Lt),
                b'>' => single(&mut i, Tok::Gt),
                b'+' => single(&mut i, Tok::Plus),
                b'-' => single(&mut i, Tok::Minus),
                b'*' => single(&mut i, Tok::Star),
                b'/' => single(&mut i, Tok::Slash),
                b'%' => single(&mut i, Tok::Percent),
                b'=' => return err(start, "`=` is not an operator; use `==`"),
                b'&' => return err(start, "`&` is not an operator; use `&&`"),
                b'|' => return err(start, "`|` is not an operator; use `||`"),
                b'"' | b'\'' => {
                    let (s, next) = lex_string(src, i, false)?;
                    i = next;
                    Tok::Str(s)
                }
                b'0'..=b'9' | b'.' => {
                    let (t, next) = lex_number(src, i)?;
                    i = next;
                    t
                }
                b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                    // Raw (`r"…"`) and bytes (`b"…"`) string prefixes.
                    let next = bytes.get(i + 1).copied();
                    if matches!(c, b'r' | b'R') && matches!(next, Some(b'"' | b'\'')) {
                        let (s, n) = lex_string(src, i + 1, true)?;
                        i = n;
                        Tok::Str(s)
                    } else if matches!(c, b'b' | b'B')
                        && matches!(next, Some(b'"' | b'\'' | b'r' | b'R'))
                    {
                        return err(start, "bytes literals are not supported in policies");
                    } else {
                        while i < bytes.len()
                            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                        {
                            i += 1;
                        }
                        let word = &src[start..i];
                        match word {
                            "true" => Tok::True,
                            "false" => Tok::False,
                            "null" => Tok::Null,
                            "in" => Tok::In,
                            w if RESERVED.contains(&w) => {
                                return err(start, format!("`{w}` is a reserved word in CEL"));
                            }
                            w => Tok::Ident(w.to_string()),
                        }
                    }
                }
                _ => {
                    let ch = src[i..].chars().next().unwrap_or('?');
                    return err(start, format!("unexpected character `{ch}`"));
                }
            }
        };
        out.push((tok, start));
    }
    out.push((Tok::Eof, src.len()));
    Ok(out)
}

fn single(i: &mut usize, t: Tok) -> Tok {
    *i += 1;
    t
}

fn lex_number(src: &str, start: usize) -> Result<(Tok, usize), SyntaxError> {
    let bytes = src.as_bytes();
    let mut i = start;
    // Hex integers: 0x… with an optional `u`.
    if bytes[i] == b'0' && matches!(bytes.get(i + 1), Some(b'x' | b'X')) {
        i += 2;
        let digits = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let text = &src[digits..i];
        if text.is_empty() {
            return err(start, "hex literal without digits");
        }
        if matches!(bytes.get(i), Some(b'u' | b'U')) {
            let v = u64::from_str_radix(text, 16)
                .or_else(|_| err(start, "unsigned integer literal out of range"))?;
            return Ok((Tok::Uint(v), i + 1));
        }
        let v = i64::from_str_radix(text, 16)
            .or_else(|_| err(start, "integer literal out of range"))?;
        return Ok((Tok::Int(v), i));
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let mut is_double = false;
    if bytes.get(i) == Some(&b'.') && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
        is_double = true;
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
    }
    if matches!(bytes.get(i), Some(b'e' | b'E')) {
        let mut j = i + 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        if bytes.get(j).is_some_and(u8::is_ascii_digit) {
            is_double = true;
            i = j;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
    }
    let text = &src[start..i];
    if is_double {
        let v: f64 = text
            .parse()
            .or_else(|_| err(start, "invalid double literal"))?;
        if !v.is_finite() {
            return err(start, "double literal out of range");
        }
        return Ok((Tok::Double(v), i));
    }
    if matches!(bytes.get(i), Some(b'u' | b'U')) {
        let v: u64 = text
            .parse()
            .or_else(|_| err(start, "unsigned integer literal out of range"))?;
        return Ok((Tok::Uint(v), i + 1));
    }
    // `-9223372036854775808` is lexed as `-` and `9223372036854775808`; the
    // parser folds it (see `unary`). Keep the magnitude here.
    match text.parse::<i64>() {
        Ok(v) => Ok((Tok::Int(v), i)),
        Err(_) if text == "9223372036854775808" => Ok((Tok::Uint(1u64 << 63), i)),
        Err(_) => err(start, "integer literal out of range"),
    }
}

/// A quoted string starting at `start` (the quote), `raw` for `r"…"`.
/// Supports single, double and triple quotes and the CEL escapes.
fn lex_string(src: &str, start: usize, raw: bool) -> Result<(String, usize), SyntaxError> {
    let bytes = src.as_bytes();
    let q = bytes[start];
    let triple = bytes.get(start + 1) == Some(&q) && bytes.get(start + 2) == Some(&q);
    let mut i = start + if triple { 3 } else { 1 };
    let mut out = String::new();
    loop {
        if i >= bytes.len() {
            return err(start, "unterminated string literal");
        }
        let c = bytes[i];
        if triple {
            if c == q && bytes.get(i + 1) == Some(&q) && bytes.get(i + 2) == Some(&q) {
                return Ok((out, i + 3));
            }
        } else if c == q {
            return Ok((out, i + 1));
        } else if c == b'\n' || c == b'\r' {
            return err(start, "newline in a single-quoted string literal");
        }
        if c == b'\\' && !raw {
            let (ch, next) = escape(src, i)?;
            out.push(ch);
            i = next;
            continue;
        }
        let ch = src[i..].chars().next().ok_or_else(|| SyntaxError {
            offset: i,
            message: "invalid UTF-8".into(),
        })?;
        out.push(ch);
        i += ch.len_utf8();
    }
}

fn escape(src: &str, at: usize) -> Result<(char, usize), SyntaxError> {
    let bytes = src.as_bytes();
    let Some(&e) = bytes.get(at + 1) else {
        return err(at, "unterminated escape sequence");
    };
    let simple = |c: char| Ok((c, at + 2));
    match e {
        b'n' => simple('\n'),
        b't' => simple('\t'),
        b'r' => simple('\r'),
        b'a' => simple('\u{7}'),
        b'b' => simple('\u{8}'),
        b'f' => simple('\u{c}'),
        b'v' => simple('\u{b}'),
        b'\\' => simple('\\'),
        b'\'' => simple('\''),
        b'"' => simple('"'),
        b'`' => simple('`'),
        b'?' => simple('?'),
        b'x' | b'X' => hex_escape(src, at, 2),
        b'u' => hex_escape(src, at, 4),
        b'U' => hex_escape(src, at, 8),
        b'0'..=b'3' => {
            let digits = src.get(at + 1..at + 4).unwrap_or("");
            let v = u32::from_str_radix(digits, 8)
                .ok()
                .filter(|_| digits.len() == 3)
                .ok_or_else(|| SyntaxError {
                    offset: at,
                    message: "invalid octal escape".into(),
                })?;
            let ch = char::from_u32(v).ok_or_else(|| SyntaxError {
                offset: at,
                message: "invalid octal escape".into(),
            })?;
            Ok((ch, at + 4))
        }
        _ => err(at, "invalid escape sequence"),
    }
}

fn hex_escape(src: &str, at: usize, n: usize) -> Result<(char, usize), SyntaxError> {
    let digits = src.get(at + 2..at + 2 + n).unwrap_or("");
    let ch = (digits.len() == n)
        .then(|| u32::from_str_radix(digits, 16).ok())
        .flatten()
        .and_then(char::from_u32)
        .ok_or_else(|| SyntaxError {
            offset: at,
            message: "invalid hex or unicode escape".into(),
        })?;
    Ok((ch, at + 2 + n))
}

// ---------------------------------------------------------------------------
// Syntax tree

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

impl BinOp {
    pub(crate) fn symbol(self) -> &'static str {
        match self {
            BinOp::Or => "||",
            BinOp::And => "&&",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::In => "in",
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Rem => "%",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnOp {
    Not,
    Neg,
}

/// The comprehension macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Macro {
    All,
    Exists,
    ExistsOne,
    /// `map(x, t)`.
    Map,
    /// `map(x, p, t)`: filter then transform.
    MapFilter,
    Filter,
}

impl Macro {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Macro::All => "all",
            Macro::Exists => "exists",
            Macro::ExistsOne => "exists_one",
            Macro::Map | Macro::MapFilter => "map",
            Macro::Filter => "filter",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Lit {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    Str(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ExprKind {
    Lit(Lit),
    Ident(String),
    /// `operand.field`.
    Select(Box<Expr>, String),
    /// `has(operand.field)`.
    Has(Box<Expr>, String),
    /// `operand[index]`.
    Index(Box<Expr>, Box<Expr>),
    /// `f(args)` or `target.f(args)`.
    Call {
        target: Option<Box<Expr>>,
        func: String,
        args: Vec<Expr>,
    },
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Map(Vec<(Expr, Expr)>),
    /// `range.macro(var, …)`: `pred` is the predicate of all/exists/
    /// exists_one/filter/map-with-filter, `body` the transform of map.
    Comprehension {
        mac: Macro,
        range: Box<Expr>,
        var: String,
        pred: Option<Box<Expr>>,
        body: Option<Box<Expr>>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Expr {
    pub(crate) kind: ExprKind,
    pub(crate) pos: Pos,
}

impl Expr {
    fn new(kind: ExprKind, pos: Pos) -> Self {
        Expr { kind, pos }
    }

    /// Every node of the tree (for the static node limit).
    pub(crate) fn node_count(&self) -> usize {
        let mut n = 1;
        self.for_each_child(|c| n += c.node_count());
        n
    }

    pub(crate) fn for_each_child(&self, mut f: impl FnMut(&Expr)) {
        match &self.kind {
            ExprKind::Lit(_) | ExprKind::Ident(_) => {}
            ExprKind::Select(e, _) | ExprKind::Has(e, _) | ExprKind::Unary(_, e) => f(e),
            ExprKind::Index(a, b) | ExprKind::Binary(_, a, b) => {
                f(a);
                f(b);
            }
            ExprKind::Call { target, args, .. } => {
                if let Some(t) = target {
                    f(t);
                }
                args.iter().for_each(f);
            }
            ExprKind::Cond(a, b, c) => {
                f(a);
                f(b);
                f(c);
            }
            ExprKind::List(items) => items.iter().for_each(f),
            ExprKind::Map(entries) => {
                for (k, v) in entries {
                    f(k);
                    f(v);
                }
            }
            ExprKind::Comprehension {
                range, pred, body, ..
            } => {
                f(range);
                if let Some(p) = pred {
                    f(p);
                }
                if let Some(b) = body {
                    f(b);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parser

pub(crate) fn parse(src: &str) -> Result<Expr, SyntaxError> {
    let toks = lex(src)?;
    let mut p = Parser {
        toks,
        at: 0,
        depth: 0,
    };
    let e = p.expr()?;
    match p.peek() {
        Tok::Eof => Ok(e),
        _ => err(p.pos(), "unexpected token after the end of the expression"),
    }
}

struct Parser {
    toks: Vec<(Tok, Pos)>,
    at: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.at].0
    }

    fn pos(&self) -> Pos {
        self.toks[self.at].1
    }

    fn bump(&mut self) -> (Tok, Pos) {
        let t = self.toks[self.at].clone();
        if self.at + 1 < self.toks.len() {
            self.at += 1;
        }
        t
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<Pos, SyntaxError> {
        if self.peek() == want {
            Ok(self.bump().1)
        } else {
            err(self.pos(), format!("expected {what}"))
        }
    }

    fn enter(&mut self) -> Result<(), SyntaxError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return err(
                self.pos(),
                format!("expression nests deeper than {MAX_PARSE_DEPTH} levels"),
            );
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn expr(&mut self) -> Result<Expr, SyntaxError> {
        self.enter()?;
        let cond = self.or()?;
        let out = if self.peek() == &Tok::Question {
            let pos = self.bump().1;
            let then = self.or()?;
            self.expect(&Tok::Colon, "`:` of the conditional")?;
            let otherwise = self.expr()?;
            Expr::new(
                ExprKind::Cond(Box::new(cond), Box::new(then), Box::new(otherwise)),
                pos,
            )
        } else {
            cond
        };
        self.leave();
        Ok(out)
    }

    fn or(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.and()?;
        while self.peek() == &Tok::OrOr {
            let pos = self.bump().1;
            let right = self.and()?;
            left = Expr::new(
                ExprKind::Binary(BinOp::Or, Box::new(left), Box::new(right)),
                pos,
            );
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.relation()?;
        while self.peek() == &Tok::AndAnd {
            let pos = self.bump().1;
            let right = self.relation()?;
            left = Expr::new(
                ExprKind::Binary(BinOp::And, Box::new(left), Box::new(right)),
                pos,
            );
        }
        Ok(left)
    }

    fn relation(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.addition()?;
        loop {
            let op = match self.peek() {
                Tok::Eq => BinOp::Eq,
                Tok::Ne => BinOp::Ne,
                Tok::Lt => BinOp::Lt,
                Tok::Le => BinOp::Le,
                Tok::Gt => BinOp::Gt,
                Tok::Ge => BinOp::Ge,
                Tok::In => BinOp::In,
                _ => return Ok(left),
            };
            let pos = self.bump().1;
            let right = self.addition()?;
            left = Expr::new(ExprKind::Binary(op, Box::new(left), Box::new(right)), pos);
        }
    }

    fn addition(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.multiplication()?;
        loop {
            let op = match self.peek() {
                Tok::Plus => BinOp::Add,
                Tok::Minus => BinOp::Sub,
                _ => return Ok(left),
            };
            let pos = self.bump().1;
            let right = self.multiplication()?;
            left = Expr::new(ExprKind::Binary(op, Box::new(left), Box::new(right)), pos);
        }
    }

    fn multiplication(&mut self) -> Result<Expr, SyntaxError> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Slash => BinOp::Div,
                Tok::Percent => BinOp::Rem,
                _ => return Ok(left),
            };
            let pos = self.bump().1;
            let right = self.unary()?;
            left = Expr::new(ExprKind::Binary(op, Box::new(left), Box::new(right)), pos);
        }
    }

    fn unary(&mut self) -> Result<Expr, SyntaxError> {
        self.enter()?;
        let out = match self.peek() {
            Tok::Not => {
                let pos = self.bump().1;
                let operand = self.unary()?;
                Expr::new(ExprKind::Unary(UnOp::Not, Box::new(operand)), pos)
            }
            Tok::Minus => {
                let pos = self.bump().1;
                // Fold `-<literal>` so `-9223372036854775808` is representable.
                match self.peek().clone() {
                    Tok::Int(v)
                        if !matches!(self.toks[self.at + 1].0, Tok::Dot | Tok::LBracket) =>
                    {
                        self.bump();
                        Expr::new(ExprKind::Lit(Lit::Int(-v)), pos)
                    }
                    Tok::Uint(v)
                        if v == 1u64 << 63
                            && !matches!(self.toks[self.at + 1].0, Tok::Dot | Tok::LBracket) =>
                    {
                        self.bump();
                        Expr::new(ExprKind::Lit(Lit::Int(i64::MIN)), pos)
                    }
                    Tok::Double(v)
                        if !matches!(self.toks[self.at + 1].0, Tok::Dot | Tok::LBracket) =>
                    {
                        self.bump();
                        Expr::new(ExprKind::Lit(Lit::Double(-v)), pos)
                    }
                    _ => {
                        let operand = self.unary()?;
                        Expr::new(ExprKind::Unary(UnOp::Neg, Box::new(operand)), pos)
                    }
                }
            }
            _ => self.member()?,
        };
        self.leave();
        Ok(out)
    }

    fn member(&mut self) -> Result<Expr, SyntaxError> {
        let mut e = self.primary()?;
        loop {
            match self.peek() {
                Tok::Dot => {
                    self.bump();
                    let (name, npos) = match self.bump() {
                        (Tok::Ident(n), p) => (n, p),
                        (_, p) => return err(p, "expected a field or method name after `.`"),
                    };
                    if self.peek() == &Tok::LParen {
                        self.bump();
                        let args = self.args(&Tok::RParen)?;
                        e = self.method(e, name, args, npos)?;
                    } else {
                        e = Expr::new(ExprKind::Select(Box::new(e), name), npos);
                    }
                }
                Tok::LBracket => {
                    let pos = self.bump().1;
                    self.enter()?;
                    let index = self.expr()?;
                    self.leave();
                    self.expect(&Tok::RBracket, "`]`")?;
                    e = Expr::new(ExprKind::Index(Box::new(e), Box::new(index)), pos);
                }
                Tok::LBrace => {
                    return err(
                        self.pos(),
                        "message construction (`Type{…}`) is not supported in policies",
                    );
                }
                _ => return Ok(e),
            }
        }
    }

    /// `target.name(args)`: a comprehension macro or a method call.
    fn method(
        &mut self,
        target: Expr,
        name: String,
        mut args: Vec<Expr>,
        pos: Pos,
    ) -> Result<Expr, SyntaxError> {
        let mac = match (name.as_str(), args.len()) {
            ("all", 2) => Some(Macro::All),
            ("exists", 2) => Some(Macro::Exists),
            ("exists_one", 2) => Some(Macro::ExistsOne),
            ("filter", 2) => Some(Macro::Filter),
            ("map", 2) => Some(Macro::Map),
            ("map", 3) => Some(Macro::MapFilter),
            ("all" | "exists" | "exists_one" | "filter", _) => {
                return err(pos, format!("`{name}` takes a variable and a predicate"));
            }
            ("map", _) => return err(pos, "`map` takes a variable and one or two expressions"),
            _ => None,
        };
        let Some(mac) = mac else {
            return Ok(Expr::new(
                ExprKind::Call {
                    target: Some(Box::new(target)),
                    func: name,
                    args,
                },
                pos,
            ));
        };
        let var = match &args[0].kind {
            ExprKind::Ident(v) => v.clone(),
            _ => {
                return err(
                    args[0].pos,
                    "the first argument of a macro must be a variable name",
                );
            }
        };
        let (pred, body) = match mac {
            Macro::Map => (None, Some(Box::new(args.remove(1)))),
            Macro::MapFilter => {
                let body = args.remove(2);
                (Some(Box::new(args.remove(1))), Some(Box::new(body)))
            }
            _ => (Some(Box::new(args.remove(1))), None),
        };
        Ok(Expr::new(
            ExprKind::Comprehension {
                mac,
                range: Box::new(target),
                var,
                pred,
                body,
            },
            pos,
        ))
    }

    fn args(&mut self, close: &Tok) -> Result<Vec<Expr>, SyntaxError> {
        self.enter()?;
        let mut out = Vec::new();
        if self.peek() == close {
            self.bump();
            self.leave();
            return Ok(out);
        }
        loop {
            out.push(self.expr()?);
            match self.peek() {
                Tok::Comma => {
                    self.bump();
                    // A trailing comma is allowed in lists and maps.
                    if self.peek() == close {
                        self.bump();
                        break;
                    }
                }
                t if t == close => {
                    self.bump();
                    break;
                }
                _ => return err(self.pos(), "expected `,` or the closing bracket"),
            }
        }
        self.leave();
        Ok(out)
    }

    fn primary(&mut self) -> Result<Expr, SyntaxError> {
        let (tok, pos) = self.bump();
        let lit = |l| Ok(Expr::new(ExprKind::Lit(l), pos));
        match tok {
            Tok::Int(v) => lit(Lit::Int(v)),
            Tok::Uint(v) if v == 1u64 << 63 => err(pos, "integer literal out of range"),
            Tok::Uint(v) => lit(Lit::Uint(v)),
            Tok::Double(v) => lit(Lit::Double(v)),
            Tok::Str(s) => lit(Lit::Str(s)),
            Tok::True => lit(Lit::Bool(true)),
            Tok::False => lit(Lit::Bool(false)),
            Tok::Null => lit(Lit::Null),
            Tok::Ident(name) => {
                if self.peek() != &Tok::LParen {
                    return Ok(Expr::new(ExprKind::Ident(name), pos));
                }
                self.bump();
                let mut args = self.args(&Tok::RParen)?;
                if name == "has" {
                    if args.len() != 1 {
                        return err(
                            pos,
                            "`has` takes one field selection, e.g. has(session.tenant)",
                        );
                    }
                    let arg = args.remove(0);
                    return match arg.kind {
                        ExprKind::Select(operand, field) => {
                            Ok(Expr::new(ExprKind::Has(operand, field), pos))
                        }
                        _ => err(
                            arg.pos,
                            "`has` takes a field selection, e.g. has(session.tenant)",
                        ),
                    };
                }
                Ok(Expr::new(
                    ExprKind::Call {
                        target: None,
                        func: name,
                        args,
                    },
                    pos,
                ))
            }
            Tok::LParen => {
                self.enter()?;
                let e = self.expr()?;
                self.leave();
                self.expect(&Tok::RParen, "`)`")?;
                Ok(e)
            }
            Tok::LBracket => {
                let items = self.args(&Tok::RBracket)?;
                Ok(Expr::new(ExprKind::List(items), pos))
            }
            Tok::LBrace => {
                self.enter()?;
                let mut entries = Vec::new();
                if self.peek() == &Tok::RBrace {
                    self.bump();
                } else {
                    loop {
                        let k = self.expr()?;
                        self.expect(&Tok::Colon, "`:` in a map literal")?;
                        let v = self.expr()?;
                        entries.push((k, v));
                        match self.bump() {
                            (Tok::Comma, _) if self.peek() == &Tok::RBrace => {
                                self.bump();
                                break;
                            }
                            (Tok::Comma, _) => {}
                            (Tok::RBrace, _) => break,
                            (_, p) => return err(p, "expected `,` or `}` in a map literal"),
                        }
                    }
                }
                self.leave();
                Ok(Expr::new(ExprKind::Map(entries), pos))
            }
            Tok::Dot => err(
                pos,
                "absolute names (`.name`) are not supported in policies",
            ),
            Tok::Eof => err(pos, "unexpected end of the expression"),
            _ => err(pos, "expected an expression"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Expr {
        parse(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn precedence_follows_cel() {
        // `a || b && c` is `a || (b && c)`.
        let e = p("a || b && c");
        assert!(matches!(e.kind, ExprKind::Binary(BinOp::Or, _, _)));
        // `!a == b` is `(!a) == b`.
        let e = p("!a == b");
        assert!(matches!(e.kind, ExprKind::Binary(BinOp::Eq, _, _)));
        // `1 + 2 * 3` multiplies first.
        let ExprKind::Binary(BinOp::Add, _, r) = p("1 + 2 * 3").kind else {
            panic!()
        };
        assert!(matches!(r.kind, ExprKind::Binary(BinOp::Mul, _, _)));
        // The conditional is right-associative and binds loosest.
        let e = p("a ? b : c ? d : e");
        let ExprKind::Cond(_, _, other) = e.kind else {
            panic!()
        };
        assert!(matches!(other.kind, ExprKind::Cond(..)));
    }

    #[test]
    fn literals() {
        assert_eq!(p("0x1F").kind, ExprKind::Lit(Lit::Int(31)));
        assert_eq!(p("7u").kind, ExprKind::Lit(Lit::Uint(7)));
        assert_eq!(p("1.5e2").kind, ExprKind::Lit(Lit::Double(150.0)));
        assert_eq!(
            p("-9223372036854775808").kind,
            ExprKind::Lit(Lit::Int(i64::MIN))
        );
        assert_eq!(
            p(r#""a\n\x41é""#).kind,
            ExprKind::Lit(Lit::Str("a\nAé".into()))
        );
        assert_eq!(p(r"r'\d+'").kind, ExprKind::Lit(Lit::Str(r"\d+".into())));
        assert_eq!(p("'''x'y'''").kind, ExprKind::Lit(Lit::Str("x'y".into())));
        assert!(parse("9223372036854775808").is_err());
        assert!(parse("b'x'").is_err());
    }

    #[test]
    fn macros_and_has() {
        let e = p("stmt.tables.all(t, t.startsWith('public.'))");
        assert!(matches!(
            e.kind,
            ExprKind::Comprehension {
                mac: Macro::All,
                ..
            }
        ));
        assert!(matches!(p("has(session.tenant)").kind, ExprKind::Has(..)));
        assert!(parse("has(x)").is_err());
        assert!(parse("l.all(1, true)").is_err());
        assert!(matches!(
            p("l.map(x, x > 1, x * 2)").kind,
            ExprKind::Comprehension {
                mac: Macro::MapFilter,
                ..
            }
        ));
    }

    #[test]
    fn errors_are_positioned() {
        let e = parse("a = b").unwrap_err();
        assert_eq!(e.offset, 2);
        let e = parse("for").unwrap_err();
        assert!(e.message.contains("reserved"));
        assert!(parse("'unterminated").is_err());
        assert!(parse("a.b{}").is_err());
        assert!(parse(".a").is_err());
        assert!(parse("(1").is_err());
        assert!(parse("1 2").is_err());
    }

    #[test]
    fn deep_nesting_is_an_error_not_an_abort() {
        let src = format!("{}1{}", "(".repeat(1000), ")".repeat(1000));
        assert!(parse(&src).unwrap_err().message.contains("deeper"));
        let src = format!("{}true", "!".repeat(1000));
        assert!(parse(&src).is_err());
        let src = format!("{}1", "-".repeat(1000));
        assert!(parse(&src).is_err());
        let src = format!("{}1{}", "[".repeat(500), "]".repeat(500));
        assert!(parse(&src).is_err());
    }
}
