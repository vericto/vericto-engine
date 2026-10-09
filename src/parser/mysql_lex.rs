//! MySQL lexical normalization: the text MySQL executes, before any rule runs.
//!
//! sqlparser's tokenizer is not MySQL's lexer, and the two disagree on text a
//! client controls: which comments MySQL executes (and for which server
//! versions), when a comment starts and whether comments nest, and, depending
//! on the server's string-escape mode (which the engine cannot see), where a
//! string literal ends.
//!
//! [`readings`] lexes the text the way MySQL does, once per escape mode, and
//! renders every statement the server could execute as text sqlparser reads
//! the same way: ordinary comments become a space, comments MySQL executes
//! become their content, minus signs MySQL does not read as a comment are
//! spaced apart, and in the mode without backslash escapes every backslash
//! inside a literal is doubled (sqlparser always unescapes). The **base**
//! reading includes every executed comment, with backslash escapes (MySQL's
//! default). The **alternatives** are the other server versions and the other
//! escape mode; the rule engine evaluates each and keeps the strictest
//! outcome.
//!
//! Anything this lexer cannot resolve with certainty is [`Readings::Ambiguous`]:
//! the engine blocks it with VERICTO-086. Never a parse error, which a
//! fail-open host would forward.
//!
//! Text with none of these constructs is [`Readings::Plain`] and goes through
//! exactly the path it went through before, so its outcome is unchanged byte
//! for byte.

/// How many distinct readings a statement may have before it is ambiguous.
/// Each costs one sqlparser parse. Legitimate text has one or two (a dump with
/// a few versioned comments, or a literal with a backslash).
const MAX_READINGS: usize = 16;

/// What MySQL may execute for a piece of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Readings {
    /// No construct MySQL reads differently: evaluate the text as it is.
    Plain,
    /// The text cannot be read with certainty; the reason is for the report.
    Ambiguous(String),
    /// The text MySQL executes on an up-to-date server with backslash escapes
    /// (`base`), and every other text some server may execute instead, each
    /// distinct from `base` and from one another.
    Normalized {
        base: String,
        alternatives: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escapes {
    /// MySQL's default: `\` escapes the next character inside a literal.
    Backslash,
    /// No backslash escapes: `\` is an ordinary character.
    NoBackslash,
}

/// The condition on an executable comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cond {
    /// Executed by every server.
    Always,
    /// Executed by MySQL from the given version on, and by MariaDB.
    MySql(u32),
    /// Executed by MariaDB only, from the given version on.
    MariaDb(u32),
}

#[derive(Debug, Clone)]
enum Piece {
    /// Code, already in the form sqlparser must read.
    Text(String),
    /// A comment: a token separator.
    Gap,
    /// A top-level `;`.
    Semi,
    Cond(Cond, Vec<Piece>),
}

/// One escape mode's lexing of the text.
struct Lexed {
    pieces: Vec<Piece>,
    /// Set when the statement in progress can never execute in this mode (an
    /// unterminated literal, a stray backslash): the rest of the text,
    /// verbatim, from the offending character on.
    rejected: Option<String>,
    /// Whether any piece differs from the source text.
    changed: bool,
}

struct Ambiguous(String);

fn amb<T>(why: &str) -> Result<T, Ambiguous> {
    Err(Ambiguous(why.to_string()))
}

/// How the sequence in progress ended.
enum End {
    Eof,
    /// `*/` closing the executable comment being lexed.
    Close,
    /// The statement in progress is rejected; see [`Lexed::rejected`].
    Rejected(usize),
}

struct Lexer<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
    mode: Escapes,
    changed: bool,
}

/// Bytes that may start something other than plain code. All ASCII, so the
/// text between them can be sliced at them safely.
fn special(c: u8) -> bool {
    matches!(
        c,
        b'\'' | b'"' | b'`' | b'#' | b'-' | b'/' | b'*' | b';' | b'\\' | 0
    )
}

/// MySQL's `my_isspace || my_iscntrl`: what must follow a double dash for it
/// to start a comment.
fn ends_dash_dash(c: u8) -> bool {
    c <= b' ' || c == 0x7f
}

impl<'a> Lexer<'a> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.b.get(self.i + k).copied()
    }

    /// Lexes code until the end of the text, or until the `*/` that closes
    /// the executable comment being read when `in_cond`.
    fn seq(&mut self, in_cond: bool) -> Result<(Vec<Piece>, End), Ambiguous> {
        let mut out: Vec<Piece> = Vec::new();
        let mut text = String::new();
        let flush = |text: &mut String, out: &mut Vec<Piece>| {
            if !text.is_empty() {
                out.push(Piece::Text(std::mem::take(text)));
            }
        };
        loop {
            // Plain code up to the next special byte.
            let start = self.i;
            while self.i < self.b.len() && !special(self.b[self.i]) {
                self.i += 1;
            }
            text.push_str(&self.s[start..self.i]);
            let Some(c) = self.peek(0) else {
                if in_cond {
                    return amb("an executable comment is not terminated");
                }
                flush(&mut text, &mut out);
                return Ok((out, End::Eof));
            };
            match c {
                b'\'' | b'"' | b'`' => match self.literal(c, in_cond)? {
                    Some(lit) => text.push_str(&lit),
                    None => {
                        if in_cond {
                            return amb("a literal inside an executable comment is not terminated");
                        }
                        flush(&mut text, &mut out);
                        return Ok((out, End::Rejected(self.i)));
                    }
                },
                b'#' => {
                    if in_cond {
                        return amb("a comment inside an executable comment");
                    }
                    self.line_comment()?;
                    flush(&mut text, &mut out);
                    out.push(Piece::Gap);
                }
                b'-' if self.peek(1) == Some(b'-') => match self.peek(2) {
                    None => {
                        if in_cond {
                            return amb("a comment inside an executable comment");
                        }
                        self.i = self.b.len();
                        self.changed = true;
                        flush(&mut text, &mut out);
                        out.push(Piece::Gap);
                    }
                    Some(n) if ends_dash_dash(n) => {
                        if in_cond {
                            return amb("a comment inside an executable comment");
                        }
                        self.line_comment()?;
                        flush(&mut text, &mut out);
                        out.push(Piece::Gap);
                    }
                    // MySQL's ctype for a multibyte character's lead byte is
                    // charset-dependent: not certain either way.
                    Some(n) if n >= 0x80 => {
                        return amb("`--` followed by a non-ASCII character");
                    }
                    // Not a comment: two minus signs. Spaced, so sqlparser does
                    // not read a comment either.
                    Some(_) => {
                        text.push_str("- ");
                        self.i += 1;
                        self.changed = true;
                    }
                },
                b'/' if self.peek(1) == Some(b'*') => {
                    if in_cond {
                        return amb("a comment inside an executable comment");
                    }
                    flush(&mut text, &mut out);
                    self.block_comment(&mut out)?;
                }
                b'*' if in_cond && self.peek(1) == Some(b'/') => {
                    self.i += 2;
                    flush(&mut text, &mut out);
                    return Ok((out, End::Close));
                }
                b';' => {
                    if in_cond {
                        return amb("a statement separator inside an executable comment");
                    }
                    self.i += 1;
                    flush(&mut text, &mut out);
                    out.push(Piece::Semi);
                }
                b'\\' => {
                    if self.peek(1) == Some(b'N') {
                        // `\N` is a NULL literal on older servers.
                        text.push_str("\\N");
                        self.i += 2;
                    } else {
                        // No MySQL grammar has a bare backslash: the
                        // statement fails to parse on the server.
                        if in_cond {
                            return amb("a backslash inside an executable comment");
                        }
                        flush(&mut text, &mut out);
                        return Ok((out, End::Rejected(self.i)));
                    }
                }
                0 => return amb("a NUL byte outside a string literal"),
                _ => {
                    // `-`, `/` or `*` not starting anything.
                    text.push(c as char);
                    self.i += 1;
                }
            }
        }
    }

    /// A quoted literal or identifier starting at `self.i`, as sqlparser must
    /// read it. `None` when it is not terminated (and `self.i` is left at the
    /// opening quote).
    fn literal(&mut self, q: u8, in_cond: bool) -> Result<Option<String>, Ambiguous> {
        let open = self.i;
        let mut j = open + 1;
        let mut backslash = false;
        loop {
            let Some(&x) = self.b.get(j) else {
                return Ok(None);
            };
            if x == q {
                if self.b.get(j + 1) == Some(&q) {
                    j += 2;
                    continue;
                }
                j += 1;
                break;
            }
            if x == b'\\' && q != b'`' {
                backslash = true;
                if self.mode == Escapes::Backslash {
                    if j + 1 >= self.b.len() {
                        return Ok(None);
                    }
                    j += 2;
                    continue;
                }
            }
            j += 1;
        }
        self.i = j;
        let raw = &self.s[open..j];
        if in_cond && raw[1..raw.len() - 1].contains("*/") {
            // Whether `*/` inside a literal closes the comment depends on
            // whether the server executes or skips the comment.
            return amb("a comment terminator inside a literal in an executable comment");
        }
        if backslash && self.mode == Escapes::NoBackslash {
            // The backslashes are literal characters; sqlparser would unescape
            // them, so double them.
            self.changed = true;
            let body = &raw[1..raw.len() - 1];
            let qc = q as char;
            return Ok(Some(format!("{qc}{}{qc}", body.replace('\\', "\\\\"))));
        }
        Ok(Some(raw.to_string()))
    }

    /// A line comment, to the end of the line (the newline stays code).
    fn line_comment(&mut self) -> Result<(), Ambiguous> {
        let end = self.b[self.i..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(self.b.len(), |p| self.i + p);
        if self.b[self.i..end].contains(&0) {
            // MySQL's line-comment loop stops at a NUL byte.
            return amb("a NUL byte inside a comment");
        }
        self.i = end;
        self.changed = true;
        Ok(())
    }

    /// A block comment at `self.i`: ignored, or executed.
    fn block_comment(&mut self, out: &mut Vec<Piece>) -> Result<(), Ambiguous> {
        self.changed = true;
        let after = self.i + 2;
        let (cond_at, maria) = match (self.b.get(after), self.b.get(after + 1)) {
            (Some(b'!'), _) => (Some(after + 1), false),
            (Some(b'M'), Some(b'!')) => (Some(after + 2), true),
            _ => (None, false),
        };
        if let Some(at) = cond_at {
            let digits = self.b[at..]
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count();
            let version = || self.s[at..at + digits].parse::<u32>().unwrap_or(u32::MAX);
            let cond = match (maria, digits) {
                (false, 0) => Cond::Always,
                (true, 0) => Cond::MariaDb(0),
                (false, 5) => Cond::MySql(version()),
                (true, 5 | 6) => Cond::MariaDb(version()),
                _ => return amb("an executable comment's version number is not five digits"),
            };
            self.i = at + digits;
            let (body, end) = self.seq(true)?;
            debug_assert!(matches!(end, End::Close));
            out.push(Piece::Cond(cond, body));
            return Ok(());
        }
        let Some(len) = self.s[after..].find("*/") else {
            return amb("a comment is not terminated");
        };
        let body = &self.s[after..after + len];
        if body.contains("/*") {
            return amb("a comment inside a comment");
        }
        if body.contains('\0') {
            return amb("a NUL byte inside a comment");
        }
        if body.starts_with('+') && body.contains(['\'', '"', '`']) {
            // Optimizer hints have their own lexer, which reads quoted names.
            return amb("a quoted name inside an optimizer hint");
        }
        self.i = after + len + 2;
        out.push(Piece::Gap);
        Ok(())
    }
}

fn lex(sql: &str, mode: Escapes) -> Result<Lexed, Ambiguous> {
    let mut lx = Lexer {
        s: sql,
        b: sql.as_bytes(),
        i: 0,
        mode,
        changed: false,
    };
    let (pieces, end) = lx.seq(false)?;
    let rejected = match end {
        End::Rejected(at) => Some(sql[at..].to_string()),
        End::Eof => None,
        End::Close => unreachable!("only an executable comment closes"),
    };
    Ok(Lexed {
        pieces,
        rejected,
        changed: lx.changed,
    })
}

/// A server whose executable comments a reading follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Server {
    /// Executes MySQL-versioned comments up to `max` (`None`: none), never
    /// MariaDB-only ones.
    MySql(Option<u32>),
    /// Executes every MySQL-versioned comment (MariaDB's version numbers are
    /// larger) and MariaDB-only ones up to `max`.
    MariaDb(Option<u32>),
}

impl Server {
    fn runs(self, cond: Cond) -> bool {
        match (self, cond) {
            (_, Cond::Always) => true,
            (Server::MySql(max), Cond::MySql(v)) => max.is_some_and(|m| v <= m),
            (Server::MySql(_), Cond::MariaDb(_)) => false,
            (Server::MariaDb(_), Cond::MySql(_)) => true,
            (Server::MariaDb(max), Cond::MariaDb(v)) => max.is_some_and(|m| v <= m),
        }
    }
}

/// Every server configuration that can tell the comments in `pieces` apart.
/// The first one executes them all.
fn servers(pieces: &[Piece]) -> Vec<Server> {
    let (mut my, mut maria) = (Vec::new(), Vec::new());
    for p in pieces {
        match p {
            Piece::Cond(Cond::MySql(v), _) => my.push(*v),
            Piece::Cond(Cond::MariaDb(v), _) => maria.push(*v),
            _ => {}
        }
    }
    my.sort_unstable();
    my.dedup();
    maria.sort_unstable();
    maria.dedup();
    let mut out = vec![Server::MariaDb(Some(u32::MAX))];
    out.extend(
        maria
            .iter()
            .rev()
            .skip(1)
            .map(|&v| Server::MariaDb(Some(v))),
    );
    if !maria.is_empty() {
        out.push(Server::MariaDb(None));
    }
    if !my.is_empty() || !maria.is_empty() {
        out.extend(my.iter().rev().map(|&v| Server::MySql(Some(v))));
        out.push(Server::MySql(None));
    }
    out
}

fn render_into(pieces: &[Piece], server: Server, out: &mut String) {
    for p in pieces {
        match p {
            Piece::Text(t) => out.push_str(t),
            Piece::Gap => out.push(' '),
            Piece::Semi => out.push(';'),
            Piece::Cond(c, body) => {
                out.push(' ');
                if server.runs(*c) {
                    render_into(body, server, out);
                    out.push(' ');
                }
            }
        }
    }
}

/// The text `server` executes. For a rejected statement: the base reading
/// keeps the rest verbatim (sqlparser then reports it as before); any other
/// reading keeps only the statements before it, which the server runs before
/// it fails (`None` when there are none).
fn render(lexed: &Lexed, server: Server, base: bool) -> Option<String> {
    let mut out = String::new();
    match &lexed.rejected {
        None => render_into(&lexed.pieces, server, &mut out),
        Some(rest) if base => {
            render_into(&lexed.pieces, server, &mut out);
            out.push_str(rest);
        }
        Some(_) => {
            let last = lexed
                .pieces
                .iter()
                .rposition(|p| matches!(p, Piece::Semi))?;
            render_into(&lexed.pieces[..last], server, &mut out);
        }
    }
    Some(out)
}

/// Reads `sql` the way MySQL does. See the module documentation.
pub(crate) fn readings(sql: &str) -> Readings {
    match readings_inner(sql) {
        Ok(r) => r,
        Err(Ambiguous(why)) => Readings::Ambiguous(why),
    }
}

fn readings_inner(sql: &str) -> Result<Readings, Ambiguous> {
    let bs = lex(sql, Escapes::Backslash)?;
    // Without a backslash both modes lex identically.
    let nbe = if sql.contains('\\') {
        Some(lex(sql, Escapes::NoBackslash)?)
    } else {
        None
    };
    if !bs.changed && nbe.is_none() {
        return Ok(Readings::Plain);
    }
    let bs_servers = servers(&bs.pieces);
    let base = render(&bs, bs_servers[0], true).expect("the base reading always renders");
    let mut alternatives: Vec<String> = Vec::new();
    let add = |text: Option<String>, alternatives: &mut Vec<String>| {
        if let Some(t) = text
            && t != base
            && !alternatives.contains(&t)
        {
            alternatives.push(t);
        }
    };
    for &s in &bs_servers[1..] {
        add(render(&bs, s, false), &mut alternatives);
    }
    if let Some(nbe) = &nbe {
        let nbe_servers = servers(&nbe.pieces);
        if bs_servers.len() + nbe_servers.len() > MAX_READINGS {
            return amb("too many executable comments with different versions");
        }
        for &s in &nbe_servers {
            add(render(nbe, s, false), &mut alternatives);
        }
    } else if bs_servers.len() > MAX_READINGS {
        return amb("too many executable comments with different versions");
    }
    if base == sql && alternatives.is_empty() {
        return Ok(Readings::Plain);
    }
    Ok(Readings::Normalized { base, alternatives })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(sql: &str) -> (String, Vec<String>) {
        match readings(sql) {
            Readings::Normalized { base, alternatives } => (base, alternatives),
            other => panic!("{sql}: {other:?}"),
        }
    }

    fn base(sql: &str) -> String {
        normalized(sql).0
    }

    fn ambiguous(sql: &str) -> String {
        match readings(sql) {
            Readings::Ambiguous(why) => why,
            other => panic!("{sql}: {other:?}"),
        }
    }

    #[test]
    fn text_without_constructs_is_plain() {
        for sql in [
            "SELECT 1",
            "DELETE FROM accounts WHERE id = 1",
            "SELECT 'a''b', \"c\", `d``e` FROM t WHERE x - 1 > 0 AND y = -1",
            "SELECT a * b / c FROM t",
            "SELECT '/* not a comment */', '-- nor this', '# nor this' FROM t",
            "SELECT `--x`, `/*!x*/`, `#` FROM t",
            "SELECT 1; SELECT 2;",
            "",
        ] {
            assert_eq!(readings(sql), Readings::Plain, "{sql}");
        }
    }

    #[test]
    fn executed_comments_become_code() {
        assert_eq!(
            base("/*! DELETE FROM accounts */"),
            "  DELETE FROM accounts  "
        );
        assert_eq!(
            base("/*!50000 DELETE FROM accounts */"),
            "  DELETE FROM accounts  "
        );
        assert_eq!(
            base("/*!50000DELETE FROM accounts*/"),
            " DELETE FROM accounts "
        );
        assert_eq!(
            base("/*M!100100 TRUNCATE accounts */"),
            "  TRUNCATE accounts  "
        );
        assert_eq!(
            base("SELECT 1 /*!40101 , 2 */ FROM t"),
            "SELECT 1   , 2   FROM t"
        );
        // A literal inside keeps its comment-like text.
        assert_eq!(base("/*! SELECT '--x' */"), "  SELECT '--x'  ");
    }

    #[test]
    fn versioned_comments_have_a_reading_per_server() {
        let (b, alts) = normalized("DELETE FROM accounts /*!99999 WHERE id = 1 */");
        assert_eq!(b, "DELETE FROM accounts   WHERE id = 1  ");
        assert_eq!(alts, vec!["DELETE FROM accounts  ".to_string()]);
        // An unversioned comment runs everywhere: one reading.
        let (_, alts) = normalized("/*! DELETE FROM accounts */");
        assert!(alts.is_empty(), "{alts:?}");
        // MySQL never runs MariaDB-only comments; MariaDB runs every
        // MySQL-versioned one.
        let (b, alts) = normalized("SELECT 1 /*!50000 + 2 */ /*M!100000 + 3 */");
        assert_eq!(b, "SELECT 1   + 2     + 3  ");
        assert_eq!(
            alts,
            vec!["SELECT 1   + 2    ".to_string(), "SELECT 1    ".to_string()]
        );
    }

    #[test]
    fn comments_become_a_space() {
        assert_eq!(base("DELETE/**/FROM accounts"), "DELETE FROM accounts");
        assert_eq!(
            base("DELETE FROM accounts # x\nWHERE id = 1"),
            "DELETE FROM accounts  \nWHERE id = 1"
        );
        assert_eq!(
            base("DELETE FROM accounts -- x\nWHERE id = 1"),
            "DELETE FROM accounts  \nWHERE id = 1"
        );
        assert_eq!(base("DELETE FROM accounts --\tx"), "DELETE FROM accounts  ");
        assert_eq!(base("DELETE FROM accounts --"), "DELETE FROM accounts  ");
        assert_eq!(base("SELECT 1 /* it's */ FROM t"), "SELECT 1   FROM t");
        assert_eq!(base("SELECT /*+ BKA(t) */ 1 FROM t"), "SELECT   1 FROM t");
        assert_eq!(base("SELECT 1-/**/-1"), "SELECT 1- -1");
    }

    #[test]
    fn comment_start_follows_mysql() {
        assert_eq!(base("SELECT 1 --1"), "SELECT 1 - -1");
        assert_eq!(base("SELECT 1 ---1"), "SELECT 1 - - -1");
        assert_eq!(base("SELECT 1 --- 1"), "SELECT 1 -  ");
    }

    #[test]
    fn literals_have_a_reading_per_escape_mode() {
        // Same structure in both modes: the alternative only differs in the
        // literal's content.
        let (b, alts) = normalized(r"SELECT 'C:\\x' FROM t");
        assert_eq!(b, r"SELECT 'C:\\x' FROM t");
        assert_eq!(alts, vec![r"SELECT 'C:\\\\x' FROM t".to_string()]);
        // Different structure: the literal ends at the backslash without
        // backslash escapes.
        let (b, alts) = normalized(r"SELECT 'a\'; DELETE FROM accounts; -- '");
        assert_eq!(b, r"SELECT 'a\'; DELETE FROM accounts; -- '");
        assert_eq!(
            alts,
            vec![r"SELECT 'a\\'; DELETE FROM accounts;  ".to_string()]
        );
        let (_, alts) = normalized(r#"SELECT "a\" ; DELETE FROM accounts ; -- ""#);
        assert_eq!(
            alts,
            vec![r#"SELECT "a\\" ; DELETE FROM accounts ;  "#.to_string()]
        );
    }

    #[test]
    fn a_statement_the_server_rejects_in_one_mode_drops_out_of_that_reading() {
        // Without backslash escapes the literal is unterminated: nothing runs
        // in that mode, so the text is read as it is.
        assert_eq!(readings(r"SELECT 'O\'Brien' FROM t"), Readings::Plain);
        assert_eq!(
            readings(r"SELECT 'O\'Brien', 'D\'Arcy' FROM t"),
            Readings::Plain
        );
        // The statements before the rejected one still run.
        let (_, alts) = normalized(r"SELECT 'a\'; DELETE FROM accounts; SELECT 'x");
        assert_eq!(
            alts,
            vec![r"SELECT 'a\\'; DELETE FROM accounts".to_string()]
        );
    }

    #[test]
    fn unresolvable_text_is_ambiguous() {
        for sql in [
            "/*! DELETE FROM accounts",
            "/*!50000 DELETE FROM accounts",
            "/*! DELETE /* x */ FROM accounts */",
            "/*! DELETE FROM accounts # x\n */",
            "/*! DELETE FROM accounts -- x\n */",
            "/*! DELETE FROM accounts --",
            "/*! SELECT 1; DELETE FROM accounts */",
            "/*! SELECT '*/' */",
            "/*! SELECT 'x */",
            "/*!500001 SELECT 1 */",
            "/*!5000 SELECT 1 */",
            "/*M!1000 SELECT 1 */",
            "SELECT 1 /* /* */ */",
            "SELECT 1 /* x",
            "SELECT 1 /*+ QB_NAME('x') */",
            "SELECT 1 --\u{a0}x",
            "SELECT 1 \0",
            "SELECT 1 # \0 x",
        ] {
            ambiguous(sql);
        }
    }

    /// The readings `tests/mysql_mask_equivalence.rs` runs on a real MySQL 8
    /// next to the client's text (`mysql_executes_the_normalized_text`).
    #[test]
    fn the_live_harness_readings_are_the_engines() {
        for (client, reading) in [
            ("SELECT 1 /*!50000 + 1 */ AS v", "SELECT 1   + 1   AS v"),
            ("SELECT 1 /*! + 1 */ AS v", "SELECT 1   + 1   AS v"),
            ("SELECT 1 /*!99999 + 1 */ AS v", "SELECT 1   AS v"),
            ("SELECT 1 /*M! + 1 */ AS v", "SELECT 1   AS v"),
            ("SELECT 1 --1 AS v", "SELECT 1 - -1 AS v"),
            ("SELECT 1 ---1 AS v", "SELECT 1 - - -1 AS v"),
            ("SELECT 2 -- 1\n AS v", "SELECT 2  \n AS v"),
            ("SELECT 3 # 1\n AS v", "SELECT 3  \n AS v"),
            ("SELECT 4/**/AS v", "SELECT 4 AS v"),
        ] {
            let (b, alts) = normalized(client);
            assert!(
                b == reading || alts.iter().any(|a| a == reading),
                "{client}: {b:?} {alts:?}"
            );
        }
        assert_eq!(readings(r"SELECT 'a\'b' AS v"), Readings::Plain);
    }

    #[test]
    fn too_many_versions_is_ambiguous() {
        let sql: String = (0..20)
            .map(|i| format!("/*!{} SELECT 1 */", 50000 + i))
            .collect();
        assert!(ambiguous(&sql).contains("too many"));
        let sql: String = (0..4)
            .map(|i| format!("/*!{} SELECT 1 */", 50000 + i))
            .collect();
        normalized(&sql);
    }
}
