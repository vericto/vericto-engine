//! VERICTO-085 `mask` on MySQL (3.7.0), through the public API only.
//!
//! Every rewrite is parsed back with sqlparser's MySQL dialect and its AST is
//! compared with the original's, minus the masked projections: everything the
//! client did not ask to mask must be byte-for-byte the same tree, and every
//! `?` must still be there, in the same number. The database half (does MySQL
//! return the same rows?) is `tests/mysql_mask_equivalence.rs`.

use sqlparser::ast::{Expr, SelectItem, SetExpr, Statement, Value};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};
use vericto_engine::{
    Decision, Dialect, EnforcementPolicy, MaskStyle, SensitiveColumn, SensitivePolicy, evaluate,
};

fn tag(column: &str, policy: SensitivePolicy, mask_style: MaskStyle) -> SensitiveColumn {
    SensitiveColumn {
        schema: None,
        table: "customers".into(),
        column: column.into(),
        policy,
        mask_style,
    }
}

fn tags() -> Vec<SensitiveColumn> {
    vec![
        tag("email", SensitivePolicy::Mask, MaskStyle::Email),
        tag("card", SensitivePolicy::Mask, MaskStyle::Last4),
        tag("ssn", SensitivePolicy::Mask, MaskStyle::Hash),
        tag("created", SensitivePolicy::Mask, MaskStyle::Full),
    ]
}

fn policy() -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: tags(),
        ..EnforcementPolicy::default()
    }
}

fn my(sql: &str) -> vericto_engine::EvaluationOutcome {
    evaluate(sql, Dialect::Mysql, &[], &policy())
}

#[track_caller]
fn rewritten(sql: &str) -> String {
    let o = my(sql);
    assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
    o.rewritten_query
        .unwrap_or_else(|| panic!("{sql}: no rewrite: {:?}", o.ast_node_path))
}

#[track_caller]
fn blocked(sql: &str) -> String {
    let o = my(sql);
    assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    assert!(o.rewritten_query.is_none(), "{sql}");
    o.ast_node_path.unwrap_or_default()
}

/// Parsed the way the engine reads MySQL: string literals verbatim.
fn parse(sql: &str) -> Vec<Statement> {
    let d = MySqlDialect {};
    let toks = Tokenizer::new(&d, sql)
        .with_unescape(false)
        .tokenize_with_location()
        .unwrap_or_else(|e| panic!("{sql}: {e}"));
    Parser::new(&d)
        .with_tokens_with_locations(toks)
        .parse_statements()
        .unwrap_or_else(|e| panic!("does not parse back: {sql}: {e}"))
}

/// `?` in the parsed tree (counted on its rendering, token by token, so a
/// `?` inside a string literal does not count).
fn placeholders(sql: &str) -> usize {
    let d = MySqlDialect {};
    let tree: Vec<String> = parse(sql).iter().map(ToString::to_string).collect();
    Tokenizer::new(&d, &tree.join("; "))
        .with_unescape(false)
        .tokenize()
        .unwrap()
        .iter()
        .filter(|t| matches!(t, Token::Placeholder(p) if p == "?"))
        .count()
}

/// MySQL's output name of a select item, as far as these tests need it.
fn out_name(item: &SelectItem) -> Option<String> {
    match item {
        SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
        SelectItem::UnnamedExpr(Expr::Identifier(i)) => Some(i.value.clone()),
        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(ids)) => {
            ids.last().map(|i| i.value.clone())
        }
        SelectItem::UnnamedExpr(e) => Some(e.to_string()),
        _ => None,
    }
}

/// Replaces the client-visible projections named in `masked` by `NULL`, and
/// undoes the `ORDER BY COALESCE(col)` / position fixes, so the two trees can
/// be compared on everything else.
fn strip(stmts: &mut [Statement], masked: &[&str]) {
    fn body(b: &mut SetExpr, masked: &[&str]) {
        match b {
            SetExpr::Select(s) => {
                for item in s.projection.iter_mut() {
                    // MySQL names compare case-insensitively; an expression's
                    // name is its text, compared without whitespace.
                    let squash = |s: &str| s.replace(' ', "").to_ascii_lowercase();
                    if out_name(item)
                        .is_some_and(|n| masked.iter().any(|m| squash(m) == squash(&n)))
                    {
                        *item = SelectItem::UnnamedExpr(Expr::Value(Value::Null));
                    }
                }
            }
            SetExpr::SetOperation { left, right, .. } => {
                body(left, masked);
                body(right, masked);
            }
            SetExpr::Query(q) => query(q, masked),
            _ => {}
        }
    }
    fn query(q: &mut sqlparser::ast::Query, masked: &[&str]) {
        body(&mut q.body, masked);
        if let Some(ob) = q.order_by.as_mut() {
            for e in ob.exprs.iter_mut() {
                if let Expr::Function(f) = &e.expr {
                    if f.name.to_string().eq_ignore_ascii_case("COALESCE") {
                        if let sqlparser::ast::FunctionArguments::List(l) = &f.args {
                            if let [
                                sqlparser::ast::FunctionArg::Unnamed(
                                    sqlparser::ast::FunctionArgExpr::Expr(x),
                                ),
                            ] = l.args.as_slice()
                            {
                                e.expr = x.clone();
                            }
                        }
                    }
                }
            }
        }
    }
    for s in stmts.iter_mut() {
        if let Statement::Query(q) = s {
            query(q, masked);
        }
    }
}

/// The rewrite's tree equals the original's except in the masked
/// projections, and keeps every `?`.
#[track_caller]
fn same_tree_minus(sql: &str, masked: &[&str]) -> String {
    let rw = rewritten(sql);
    let (mut a, mut b) = (parse(sql), parse(&rw));
    strip(&mut a, masked);
    strip(&mut b, masked);
    assert_eq!(a, b, "\n  original:  {sql}\n  rewritten: {rw}");
    assert_eq!(placeholders(sql), placeholders(&rw), "`?` count: {rw}");
    rw
}

#[test]
fn every_style_rewrites_on_mysql() {
    let rw = same_tree_minus(
        "SELECT id, name, email, card, ssn, created FROM customers ORDER BY id",
        &["email", "card", "ssn", "created"],
    );
    assert!(rw.contains("SHA2("), "{rw}");
    assert!(rw.contains("CONCAT('****', RIGHT("), "{rw}");
    assert!(rw.contains("LOCATE('@', "), "{rw}");
    assert!(rw.contains("'[redacted]' AS `created`"), "{rw}");
    assert!(
        !rw.contains("REGEXP_REPLACE"),
        "5.7 has no REGEXP_REPLACE: {rw}"
    );
    // Charset/collation-neutral text of the value, in every style.
    assert!(
        rw.contains("CONVERT((card) USING utf8mb4) COLLATE utf8mb4_bin"),
        "{rw}"
    );
}

#[test]
fn outcome_shape_matches_postgres() {
    let o = my("SELECT id, email FROM customers WHERE id = ?");
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"));
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some("SensitiveColumn > customers.email (mask)")
    );
    assert_eq!(o.rewritten_query, o.suggested_safe_query);
    assert_eq!(o.sensitive_columns.len(), 1);
    // monitor_mode never changes what runs.
    let mut p = policy();
    p.monitor_mode = true;
    let o = evaluate("SELECT email FROM customers", Dialect::Mysql, &[], &p);
    assert!(o.rewritten_query.is_none());
    assert!(o.suggested_safe_query.unwrap().contains("LOCATE"));
}

#[test]
fn output_names_are_kept() {
    // Bare columns keep their spelling; aliases stay; an unaliased expression
    // keeps the client's own text (MySQL names the column after it).
    let rw = same_tree_minus(
        "SELECT `EMail`, c.card AS k, LOWER( email ) FROM customers c",
        &["EMail", "k", "LOWER( email )"],
    );
    assert!(rw.contains("AS `EMail`"), "{rw}");
    assert!(rw.contains("AS `k`"), "{rw}");
    assert!(rw.contains("AS `LOWER( email )`"), "{rw}");
}

#[test]
fn mysql_syntax_round_trips_around_the_mask() {
    for (sql, masked) in [
        (
            "SELECT `id`, `c`.`email` FROM `shop`.`customers` AS `c`",
            &["email"][..],
        ),
        ("SELECT id, email FROM customers LIMIT 10, 20", &["email"]),
        (
            "SELECT id, email FROM customers LIMIT 20 OFFSET 10",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers WHERE id > ? LIMIT ?, ?",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers WHERE id > ? LIMIT ? OFFSET ?",
            &["email"],
        ),
        (
            "SELECT id, email, @x FROM customers WHERE id = @y",
            &["email"],
        ),
        (
            r"SELECT id, 'a\\b', 'x%\_', 'q''q', 'c:\\', email FROM customers WHERE name LIKE 'a\_%'",
            &["email"],
        ),
        (
            "SELECT _utf8mb4'abc' COLLATE utf8mb4_bin AS k, email FROM customers",
            &["email"],
        ),
        (
            "SELECT name COLLATE utf8mb4_unicode_ci AS n, email FROM customers",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers INNER JOIN orders o ON o.cid = customers.id LEFT OUTER JOIN x ON 1 = 1",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers WHERE email IN (?, ?) AND id <> ? FOR UPDATE",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers t WHERE t.id BETWEEN 1 AND 9 ORDER BY id DESC",
            &["email"],
        ),
        (
            "SELECT id, email FROM customers WHERE MATCH (name) AGAINST ('x' IN BOOLEAN MODE)",
            &["email"],
        ),
        (
            "SELECT id DIV 2 AS h, email FROM customers WHERE doc->>'$.a' = 'b'",
            &["email"],
        ),
        (
            "SELECT email, COUNT(*) AS n FROM customers GROUP BY email ORDER BY email",
            &["email"],
        ),
        (
            "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n, email FROM r, customers",
            &["email"],
        ),
    ] {
        let rw = same_tree_minus(sql, masked);
        eprintln!("{sql}\n  → {rw}");
    }
}

#[test]
fn multibyte_text_around_the_mask() {
    let rw = same_tree_minus(
        "SELECT 'ñandú😀', LOWER( email ), `nómbre` FROM customers WHERE name = '😀' AND id > ? LIMIT ?, ?",
        &["LOWER( email )"],
    );
    assert!(rw.contains("AS `LOWER( email )`"), "{rw}");
    assert!(
        rw.ends_with("WHERE name = '😀' AND id > ? LIMIT ?, ?"),
        "{rw}"
    );
}

#[test]
fn placeholders_keep_count_and_order() {
    // `LIMIT ?, ?` would print as `LIMIT ? OFFSET ?` and swap the two
    // bindings: the engine keeps the comma form.
    let rw = same_tree_minus(
        "SELECT id, SUBSTRING(card, ?, ?) AS part FROM customers WHERE id >= ? LIMIT ?, ?",
        &["part"],
    );
    assert!(rw.ends_with("LIMIT ?, ?"), "{rw}");
    // The computed value keeps its `?` (each bound in place), and still
    // returns only '[redacted]'.
    assert!(
        rw.contains("CONCAT('[redacted]', COALESCE(LEFT((CONVERT((SUBSTRING(card, ?, ?)) USING utf8mb4) COLLATE utf8mb4_bin), 0), ''))"),
        "{rw}"
    );
    assert_eq!(placeholders(&rw), 5);
    // A scalar subquery holding `?` would be repeated by the email form: it
    // falls back to `full`, keeping one copy of each `?`.
    let rw = same_tree_minus(
        "SELECT id, (SELECT email FROM customers c2 WHERE c2.id = ?) AS e FROM customers WHERE id < ?",
        &["e"],
    );
    assert_eq!(placeholders(&rw), 2, "{rw}");
    assert!(rw.contains("CONCAT('[redacted]'"), "{rw}");
}

#[test]
fn computed_and_aggregated_values_are_masked_full() {
    for (sql, name) in [
        ("SELECT JSON_OBJECT('e', email) AS j FROM customers", "j"),
        ("SELECT JSON_ARRAYAGG(email) AS j FROM customers", "j"),
        (
            "SELECT GROUP_CONCAT(email ORDER BY email SEPARATOR ';') AS g FROM customers",
            "g",
        ),
        ("SELECT CONCAT(email, '') AS c FROM customers", "c"),
        ("SELECT SUBSTRING(card, 1, 6) AS bin FROM customers", "bin"),
        (
            "SELECT CASE WHEN id > 0 THEN ssn END AS s FROM customers",
            "s",
        ),
        (
            "SELECT CONCAT(email, card) AS mixed FROM customers",
            "mixed",
        ),
    ] {
        let rw = same_tree_minus(sql, &[name]);
        // The value is computed and discarded (an aggregate must still
        // aggregate), so the output is exactly '[redacted]'.
        assert!(
            rw.contains("CONCAT('[redacted]', COALESCE(LEFT((CONVERT((")
                && rw.contains(&format!(
                    "USING utf8mb4) COLLATE utf8mb4_bin), 0), '')) AS `{name}`"
                )),
            "{sql}: {rw}"
        );
    }
}

#[test]
fn derived_tables_ctes_unions_mask_only_the_visible_projection() {
    let rw = same_tree_minus(
        "WITH x AS (SELECT id, email FROM customers) SELECT id, email FROM x",
        &["email"],
    );
    assert!(
        rw.starts_with("WITH x AS (SELECT id, email FROM customers) SELECT id, CASE"),
        "{rw}"
    );
    same_tree_minus("SELECT e FROM (SELECT email AS e FROM customers) s", &["e"]);
    same_tree_minus("SELECT (SELECT card FROM customers LIMIT 1) AS c", &["c"]);
    // Only the arm that derives from the masked column changes.
    let rw = same_tree_minus(
        "SELECT name FROM users UNION SELECT email FROM customers",
        &["email"],
    );
    assert!(
        rw.starts_with("SELECT name FROM users UNION SELECT CASE"),
        "{rw}"
    );
}

#[test]
fn star_copies_and_into_still_block() {
    for sql in [
        "SELECT * FROM customers",
        "SELECT c.* FROM customers c",
        "TABLE customers",
        "INSERT INTO archive SELECT email FROM customers",
        "REPLACE INTO archive (e) SELECT email FROM customers",
        "CREATE TABLE x AS SELECT email FROM customers",
        "SELECT email INTO @v FROM customers",
        "SELECT email INTO OUTFILE '/tmp/x' FROM customers",
        "SELECT email INTO DUMPFILE '/tmp/x' FROM customers",
        "SELECT email FROM customers INTO @v",
        "SET @v = (SELECT email FROM customers LIMIT 1)",
        "INSERT INTO t (a) SELECT id FROM u ON DUPLICATE KEY UPDATE a = (SELECT email FROM customers LIMIT 1)",
        "UPDATE profiles p JOIN customers c ON c.id = p.id SET p.contact = c.email",
    ] {
        blocked(sql);
    }
}

#[test]
fn text_the_renderer_cannot_reproduce_blocks() {
    for sql in [
        // Dropped by the renderer, and they change what MySQL executes.
        "SELECT /*+ SET_VAR(sql_mode='ANSI_QUOTES') */ email FROM customers",
        "SELECT SQL_CALC_FOUND_ROWS email FROM customers",
        "SELECT HIGH_PRIORITY email FROM customers",
        "SELECT STRAIGHT_JOIN email FROM customers",
        // sqlparser reads `b'101'` as `b AS '101'`.
        "SELECT b'101' AS bits, email FROM customers",
        // Where this literal ends depends on the string-escape mode.
        r"SELECT id, 'it\'s', email FROM customers",
        // sqlparser does not parse these MySQL forms: parse error → block.
        "SELECT email FROM customers USE INDEX (ix_email)",
        "SELECT email FROM customers LOCK IN SHARE MODE",
        "SELECT email, COUNT(*) FROM customers GROUP BY email WITH ROLLUP",
    ] {
        let why = blocked(sql);
        assert!(!why.is_empty(), "{sql}");
    }
    assert!(blocked("SELECT HIGH_PRIORITY email FROM customers").contains("reproduced faithfully"));
}

#[test]
fn group_by_and_having_over_a_masked_alias_block() {
    // MySQL may resolve these names to the masked alias: no safe rewrite.
    blocked("SELECT LOWER(email) AS le, COUNT(*) FROM customers GROUP BY le");
    blocked("SELECT email FROM customers HAVING email LIKE 'a%'");
    // A position always meant the select item: pointed at the original.
    let rw = rewritten("SELECT email, COUNT(*) AS n FROM customers GROUP BY 1");
    assert!(rw.ends_with("GROUP BY email"), "{rw}");
    // An expression over a masked alias that is not a column would sort by
    // the masked value.
    blocked("SELECT LOWER(email) AS le FROM customers ORDER BY LENGTH(le)");
    // ORDER BY a masked output (by name or position) sorts by the original
    // value; a bare column is wrapped so the alias cannot capture it.
    let rw = rewritten("SELECT id, email FROM customers ORDER BY 2 DESC");
    assert!(rw.ends_with("ORDER BY COALESCE(email) DESC"), "{rw}");
    let rw = rewritten("SELECT LOWER(email) AS le FROM customers ORDER BY le");
    assert!(rw.ends_with("ORDER BY LOWER(email)"), "{rw}");
}

#[test]
fn block_and_flag_keep_working_on_mysql() {
    let p = EnforcementPolicy {
        sensitive_columns: vec![tag("email", SensitivePolicy::Block, MaskStyle::Full)],
        ..EnforcementPolicy::default()
    };
    let o = evaluate("SELECT email FROM customers", Dialect::Mysql, &[], &p);
    assert_eq!(o.decision, Decision::Block);
    assert!(o.rewritten_query.is_none());
}

#[test]
fn oracle_and_sql_server_still_block_a_mask() {
    for d in [Dialect::Oracle, Dialect::MsSql] {
        let o = evaluate("SELECT email FROM customers", d, &[], &policy());
        assert_eq!(o.decision, Decision::Block, "{d:?}");
        assert!(o.ast_node_path.unwrap().contains("no rewrite for"), "{d:?}");
    }
}
