//! Regression: deeply nested input must be REFUSED, not abort the process.
//!
//! Before `guard_nesting_depth`, ~950 nested `NOT`s overflowed the stack inside
//! `pg_query`/`sqlparser` while they built the tree. A stack overflow is not a
//! catchable panic in Rust, and both consumers compile `panic = "abort"`, so one
//! ~4 KB statement — far below MAX_QUERY_SIZE_BYTES — killed an eval sidecar or a
//! proxy worker outright. This test crashes the whole test binary if it regresses.

use vericto_engine::Dialect;
use vericto_engine::error::ProxyError;
use vericto_engine::parser::parser_for;

fn bomb(n: usize) -> String {
    format!("SELECT 1 WHERE {}TRUE", "NOT ".repeat(n))
}

#[test]
fn deep_not_nesting_is_refused_on_every_dialect() {
    for dialect in [
        Dialect::Postgres,
        Dialect::Mysql,
        Dialect::Oracle,
        Dialect::MsSql,
    ] {
        let parser = parser_for(dialect);
        // Well past the measured overflow threshold (920-950).
        let err = parser.parse(&bomb(2000)).expect_err("must be refused");
        assert!(
            matches!(err, ProxyError::AstTooDeep),
            "{dialect:?}: expected AstTooDeep, got {err:?}"
        );
    }
}

#[test]
fn deep_parenthesis_nesting_is_refused() {
    for dialect in [Dialect::Postgres, Dialect::Mysql] {
        let parser = parser_for(dialect);
        let sql = format!("SELECT {}1{}", "(".repeat(2000), ")".repeat(2000));
        let err = parser.parse(&sql).expect_err("must be refused");
        assert!(
            matches!(err, ProxyError::AstTooDeep),
            "{dialect:?}: {err:?}"
        );
    }
}

#[test]
fn realistic_nesting_still_parses() {
    // The guard must not cost real queries anything. These are deeper than any
    // ORM emits and must still go through.
    let parser = parser_for(Dialect::Postgres);
    parser
        .parse("SELECT 1 WHERE NOT NOT NOT TRUE")
        .expect("chained NOT is legitimate");
    parser
        .parse("SELECT id FROM t WHERE (((a = 1 AND b = 2) OR c = 3) AND d = 4)")
        .expect("normal parenthesised predicate");
    // `not` appearing as an identifier must not be counted as the operator.
    parser
        .parse("SELECT not_deleted, notes FROM t WHERE not_deleted = true")
        .expect("identifiers containing 'not'");
}
