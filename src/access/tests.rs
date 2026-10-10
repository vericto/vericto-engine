//! VERICTO-087 unit tests: every evasion form of VERICTO-085's suite applied
//! to the allowlist, writes, DDL, the catalogue, name resolution, the
//! precedence with VERICTO-085 (design §6.1), observe mode, `None` and the
//! zero-cost path, and the JSON shape.

use crate::access::{
    ACCESS_RULE_CODE, AccessColumns, AccessEntry, AccessLevel, AccessMode, AccessPolicy,
    AccessPolicyMap, DdlPolicy, DeniedRef, Needed,
};
use crate::parser::Dialect;
use crate::rules::engine::{
    Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, ParseErrorAction,
};
use crate::sensitive::{MaskStyle, SensitiveColumn, SensitivePolicy};

use AccessLevel::*;
use Dialect::*;

fn entry(table: &str, cols: &[&str], access: AccessLevel) -> AccessEntry {
    AccessEntry {
        schema: None,
        table: table.into(),
        columns: if cols == ["*"] {
            AccessColumns::AllColumns
        } else {
            AccessColumns::List(cols.iter().map(|c| c.to_string()).collect())
        },
        access,
    }
}

fn in_schema(schema: &str, e: AccessEntry) -> AccessEntry {
    AccessEntry {
        schema: Some(schema.into()),
        ..e
    }
}

fn allow(entries: Vec<AccessEntry>) -> AccessPolicy {
    AccessPolicy {
        mode: AccessMode::Enforce,
        entries,
        ddl: DdlPolicy::Deny,
        default_schema: None,
    }
}

/// The support agent of the tests:
/// - `customers`: `id`, `name` (read) — `email`, `ssn` are not granted;
/// - `orders`: every column (read);
/// - `tickets`: `id`, `status`, `note` (read/write);
/// - `jobs`: every column (read/write).
///
/// Anything else (`secrets`, `admin_users`, the catalogue) is not granted.
fn agent() -> AccessPolicy {
    allow(vec![
        entry("customers", &["id", "name"], Read),
        entry("orders", &["*"], Read),
        entry("tickets", &["id", "status", "note"], ReadWrite),
        entry("jobs", &["*"], ReadWrite),
    ])
}

fn with(p: AccessPolicy) -> EnforcementPolicy {
    EnforcementPolicy {
        access_policy: Some(p),
        ..EnforcementPolicy::default()
    }
}

fn eval(dialect: Dialect, sql: &str, p: &AccessPolicy) -> EvaluationOutcome {
    crate::evaluate(sql, dialect, &[], &with(p.clone()))
}

/// `schema.table.column:needed` for each denied reference.
fn denied(o: &EvaluationOutcome) -> Vec<String> {
    o.access_denied
        .iter()
        .map(|d| {
            let mut s = String::new();
            if let Some(sc) = &d.schema {
                s.push_str(sc);
                s.push('.');
            }
            s.push_str(&d.table);
            if let Some(c) = &d.column {
                s.push('.');
                s.push_str(c);
            }
            s.push(':');
            s.push_str(d.needed.as_str());
            s
        })
        .collect()
}

#[track_caller]
fn assert_allowed_on(dialect: Dialect, sql: &str, p: &AccessPolicy) {
    let o = eval(dialect, sql, p);
    assert_eq!(
        o.decision,
        Decision::Allow,
        "{dialect:?} {sql} must be allowed: {o:?}"
    );
    assert!(o.access_denied.is_empty(), "{sql}: {:?}", denied(&o));
}

#[track_caller]
fn assert_allowed(sql: &str) {
    assert_allowed_on(Postgres, sql, &agent());
}

/// Denied by VERICTO-087, and `want` is among the denied references.
#[track_caller]
fn assert_denied_on(dialect: Dialect, sql: &str, p: &AccessPolicy, want: &str) {
    let o = eval(dialect, sql, p);
    assert_eq!(
        o.decision,
        Decision::Block,
        "{dialect:?} {sql} must be denied: {o:?}"
    );
    assert_eq!(
        o.rule_code.as_deref(),
        Some(ACCESS_RULE_CODE),
        "{sql}: {o:?}"
    );
    assert!(
        denied(&o).iter().any(|d| d == want),
        "{dialect:?} {sql}: expected {want} in {:?}",
        denied(&o)
    );
}

#[track_caller]
fn assert_denied(sql: &str, want: &str) {
    assert_denied_on(Postgres, sql, &agent(), want);
}

// ── reads: every evasion form of VERICTO-085, applied to the allowlist ──────

#[test]
fn granted_columns_and_tables_are_allowed() {
    for sql in [
        "SELECT id, name FROM customers WHERE id = $1",
        "SELECT c.id, o.total FROM customers c JOIN orders o ON o.customer_id = c.id WHERE c.name = $1 ORDER BY o.total DESC LIMIT 10",
        "SELECT * FROM orders",
        "SELECT o.* FROM orders o",
        "SELECT count(*) FROM customers",
        "SELECT name, count(*) FROM customers GROUP BY name HAVING count(*) > 1",
        "WITH x AS (SELECT id, name FROM customers) SELECT name FROM x ORDER BY name",
        "SELECT lower(name) AS n FROM customers ORDER BY n",
        "SELECT id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id)",
        "SELECT id FROM customers UNION SELECT id FROM orders",
        "SELECT s.n FROM (SELECT name AS n FROM customers) s",
        "SELECT to_jsonb(o) FROM orders o",
        // an output alias in ORDER BY is the output, not a column
        "SELECT id AS email FROM customers ORDER BY email",
        // an alias hides the table name
        "SELECT customers.total FROM orders customers",
        "SELECT row_number() OVER (PARTITION BY name ORDER BY id) FROM customers",
        "SELECT 1",
        "SELECT now(), version()",
        "TABLE orders",
        "COPY orders TO STDOUT",
        "COPY customers (id, name) TO STDOUT",
        "EXPLAIN SELECT id FROM customers",
    ] {
        assert_allowed(sql);
    }
}

#[test]
fn a_column_that_is_not_granted_is_denied_wherever_it_appears() {
    for sql in [
        // projections, aliases, expressions (085's derivation cases)
        "SELECT email FROM customers",
        "SELECT email AS e FROM customers",
        "SELECT c.email AS id FROM customers c",
        "SELECT lower(email) FROM customers",
        "SELECT concat(email, '') FROM customers",
        "SELECT substring(email, 1, 3) FROM customers",
        "SELECT email::varchar(4) FROM customers",
        "SELECT CASE WHEN id > 0 THEN email END FROM customers",
        "SELECT coalesce(email, 'x') FROM customers",
        "SELECT ARRAY[email] FROM customers",
        "SELECT ROW(id, email) FROM customers",
        "SELECT json_build_object('e', email) FROM customers",
        "SELECT xmlelement(name e, email) FROM customers",
        "SELECT string_agg(email, ',') FROM customers",
        "SELECT count(DISTINCT email) FROM customers",
        // CTEs, derived tables, set operations, subqueries in the select list
        "WITH x AS (SELECT email FROM customers) SELECT 1 FROM x",
        "WITH x AS (SELECT id, email FROM customers) SELECT id FROM x",
        "WITH a AS (SELECT email AS e FROM customers), b AS (SELECT e FROM a) SELECT 1 FROM b",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r JOIN customers c ON c.email = 'x' WHERE n < 3) SELECT n FROM r",
        "SELECT id FROM (SELECT id, email FROM customers) s",
        "SELECT id FROM orders UNION SELECT email FROM customers",
        "SELECT id FROM orders EXCEPT SELECT id FROM customers WHERE email = 'x'",
        "SELECT (SELECT email FROM customers LIMIT 1)",
        "SELECT ARRAY(SELECT email FROM customers)",
        "SELECT o.id FROM orders o, LATERAL (SELECT email FROM customers c WHERE c.id = o.customer_id) l",
        // predicates: probing a value counts (stricter than 085)
        "SELECT id FROM customers WHERE email = $1",
        "SELECT id FROM customers WHERE email LIKE 'a%'",
        "SELECT o.id FROM orders o JOIN customers c ON c.email = o.email",
        "SELECT id FROM customers GROUP BY email",
        "SELECT id FROM customers ORDER BY email",
        "SELECT name FROM customers GROUP BY name HAVING max(email) > 'a'",
        "SELECT count(*) FILTER (WHERE email LIKE '%@x') FROM customers",
        "SELECT string_agg(name, ',' ORDER BY email) FROM customers",
        "SELECT row_number() OVER (ORDER BY email) FROM customers",
        "SELECT row_number() OVER (PARTITION BY email) FROM customers",
        "SELECT DISTINCT ON (email) id FROM customers",
        "SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers WHERE email = 'x')",
        "SELECT id FROM orders o WHERE EXISTS (SELECT 1 FROM customers c WHERE c.email = 'x')",
        "SELECT EXISTS (SELECT email FROM customers)",
        "SELECT id FROM orders WHERE total > ALL (SELECT length(email) FROM customers)",
        "SELECT id FROM customers LIMIT (SELECT length(email) FROM customers LIMIT 1)",
        "SELECT id FROM customers WHERE (email, id) = ('x', 1)",
        // inside a node the walker does not model, with its own FROM
        "SELECT * FROM xmltable('/r' PASSING (SELECT email FROM customers LIMIT 1) COLUMNS a text)",
        "VALUES (1) ORDER BY (SELECT email FROM customers LIMIT 1)",
        "SELECT row_number() OVER w FROM customers WINDOW w AS (ORDER BY email)",
        "SELECT id FROM customers GROUP BY ROLLUP (name, email)",
        "SELECT id AS email FROM customers ORDER BY email || ''",
    ] {
        assert_denied(sql, "customers.email:read");
    }
}

#[test]
fn whole_row_references_need_every_column() {
    for sql in [
        "SELECT * FROM customers",
        "SELECT c.* FROM customers c",
        "TABLE customers",
        "SELECT to_jsonb(c) FROM customers c",
        "SELECT row_to_json(c) FROM customers c",
        "SELECT json_agg(c) FROM customers c",
        "SELECT c FROM customers c",
        "SELECT count(c.*) FROM customers c",
        "SELECT j FROM customers c, LATERAL to_jsonb(c) j",
        "WITH x AS (SELECT * FROM customers) SELECT id FROM x",
        "SELECT id FROM (SELECT * FROM customers) s",
        "COPY customers TO STDOUT",
        "SELECT a FROM customers AS c(a)",
        "SELECT id FROM orders UNION SELECT * FROM customers",
    ] {
        let o = eval(Postgres, sql, &agent());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert!(
            denied(&o).contains(&"customers.*:read".to_string()),
            "{sql}: {:?}",
            denied(&o)
        );
        assert!(
            o.suggested_safe_query
                .as_deref()
                .unwrap_or("")
                .contains("List the columns"),
            "{sql}: the message tells the caller to list the columns"
        );
    }
    let o = eval(Postgres, "SELECT * FROM customers", &agent());
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some("AccessPolicy > customers.* (read): list the columns explicitly")
    );
}

#[test]
fn a_table_that_is_not_granted_is_denied_even_with_no_column_named() {
    for sql in [
        "SELECT count(*) FROM secrets",
        "SELECT 1 FROM secrets",
        "SELECT 1 WHERE EXISTS (SELECT 1 FROM secrets)",
        "SELECT id FROM orders WHERE id IN (SELECT 1 FROM secrets)",
        "SELECT o.id FROM orders o LEFT JOIN secrets s ON true",
        "SELECT id FROM orders UNION ALL SELECT 1 FROM secrets",
        "WITH s AS (SELECT 1 FROM secrets) SELECT * FROM orders",
        "SELECT value FROM secrets",
        "SELECT s.value FROM secrets s",
        "SELECT * FROM secrets",
        "SELECT * FROM public.secrets",
        "COPY secrets TO STDOUT",
        "SELECT * FROM generate_series(1, 2) g WHERE EXISTS (SELECT 1 FROM secrets)",
        "SELECT xmlagg(xmlelement(name x, (SELECT 1 FROM secrets)))",
        "SELECT * FROM xmltable('/r' PASSING (SELECT value FROM secrets LIMIT 1) COLUMNS a text)",
    ] {
        let o = eval(Postgres, sql, &agent());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        let d = denied(&o);
        assert!(
            d.iter()
                .any(|x| x == "secrets:read" || x == "public.secrets:read"),
            "{sql}: {d:?}"
        );
        // Not granted at all: the table is named, not each column.
        assert!(d.iter().all(|x| !x.starts_with("secrets.")), "{sql}: {d:?}");
    }
    let o = eval(Postgres, "SELECT value FROM secrets", &agent());
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some("AccessPolicy > secrets (read)")
    );
}

#[test]
fn a_qualifier_that_names_nothing_in_scope_is_taken_as_a_table() {
    assert_denied("SELECT secrets.value FROM orders", "secrets:read");
}

#[test]
fn a_cte_shadows_a_table_of_the_same_name() {
    // `secrets` here is the CTE, built from granted columns.
    assert_allowed("WITH secrets AS (SELECT id FROM orders) SELECT id FROM secrets");
    // A schema-qualified name is never the CTE.
    assert_denied(
        "WITH secrets AS (SELECT id FROM orders) SELECT 1 FROM public.secrets",
        "public.secrets:read",
    );
}

#[test]
fn several_statements_are_all_analysed() {
    assert_denied(
        "SELECT id FROM orders; SELECT email FROM customers",
        "customers.email:read",
    );
}

#[test]
fn an_unqualified_column_must_be_allowed_in_every_candidate_table() {
    // `note` is granted in tickets but not in customers: it could be either.
    let sql = "SELECT note FROM customers c JOIN tickets t ON t.id = c.id";
    let o = eval(Postgres, sql, &agent());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(denied(&o), vec!["customers.note:read"]);
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some(
            "AccessPolicy > customers.note (read): `note` is unqualified and may belong to several tables; qualify the column"
        )
    );
    // Qualified, it is exactly one of them.
    assert_allowed("SELECT t.note FROM customers c JOIN tickets t ON t.id = c.id");
    // Allowed in both: fine unqualified.
    assert_allowed("SELECT name FROM customers c JOIN orders o ON o.customer_id = c.id");
    // A correlated subquery sees the outer relations too.
    assert_denied(
        "SELECT id FROM tickets WHERE EXISTS (SELECT 1 FROM customers WHERE note = 'x')",
        "customers.note:read",
    );
}

// ── writes ──────────────────────────────────────────────────────────────────

#[test]
fn writes_need_read_write_on_every_target() {
    for sql in [
        "UPDATE tickets SET status = 'closed' WHERE id = $1",
        "UPDATE tickets SET status = 'x', note = $2 WHERE id = $1 RETURNING id, status",
        "INSERT INTO tickets (id, status) VALUES ($1, $2) RETURNING id",
        "INSERT INTO tickets (id, status) SELECT id, 'new' FROM orders",
        "INSERT INTO jobs VALUES (1, 'a')",
        "DELETE FROM jobs WHERE id = 1",
        "INSERT INTO jobs (id, state) VALUES (1, 'a') ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state",
        "COPY jobs FROM STDIN",
        "COPY tickets (id, status) FROM STDIN",
        "WITH d AS (DELETE FROM jobs WHERE id = 1 RETURNING id) SELECT id FROM d",
        "MERGE INTO jobs j USING orders o ON j.id = o.id WHEN MATCHED THEN UPDATE SET state = 'x' WHEN NOT MATCHED THEN INSERT (id, state) VALUES (o.id, 'y')",
        "UPDATE tickets t SET status = 'x' FROM orders o WHERE o.id = t.id",
        "SELECT id FROM tickets FOR UPDATE",
        "LOCK TABLE jobs",
        // 3.8.1 (contract v3.3): DELETE is a table-level write, whatever the
        // entry's column list.
        "DELETE FROM tickets WHERE id = 1",
        "MERGE INTO tickets t USING orders o ON t.id = o.id WHEN MATCHED THEN DELETE",
    ] {
        assert_allowed(sql);
    }
    for (sql, want) in [
        // a read-only table
        ("UPDATE orders SET total = 0 WHERE id = 1", "orders:write"),
        ("DELETE FROM orders WHERE id = 1", "orders:write"),
        ("INSERT INTO orders (id) VALUES (1)", "orders:write"),
        ("COPY orders FROM STDIN", "orders:write"),
        ("LOCK TABLE orders", "orders:write"),
        (
            "WITH d AS (DELETE FROM orders RETURNING id) SELECT id FROM d",
            "orders:write",
        ),
        (
            "MERGE INTO orders o USING jobs j ON o.id = j.id WHEN MATCHED THEN DELETE",
            "orders:write",
        ),
        ("EXPLAIN ANALYZE DELETE FROM orders", "orders:write"),
        // a column that is not granted
        (
            "INSERT INTO tickets (id, priority) VALUES (1, 2)",
            "tickets.priority:write",
        ),
        (
            "UPDATE tickets SET priority = 1 WHERE id = 1",
            "tickets.priority:write",
        ),
        (
            "INSERT INTO tickets (id, status) VALUES (1, 'a') ON CONFLICT (id) DO UPDATE SET priority = 1",
            "tickets.priority:write",
        ),
        (
            "COPY tickets (id, priority) FROM STDIN",
            "tickets.priority:write",
        ),
        (
            "MERGE INTO tickets t USING jobs j ON t.id = j.id WHEN NOT MATCHED THEN INSERT (id, priority) VALUES (j.id, 1)",
            "tickets.priority:write",
        ),
        // every column: no column list
        (
            "INSERT INTO tickets VALUES (1, 'a', 'b')",
            "tickets.*:write",
        ),
        ("COPY tickets FROM STDIN", "tickets.*:write"),
        // DELETE reads its WHERE
        (
            "DELETE FROM tickets WHERE priority = 1",
            "tickets.priority:read",
        ),
        // a row lock is a write
        ("SELECT id FROM orders FOR UPDATE", "orders:write"),
        ("SELECT id FROM orders FOR SHARE", "orders:write"),
        // a table that is not granted at all
        ("INSERT INTO secrets (value) VALUES ('x')", "secrets:write"),
        ("DELETE FROM secrets", "secrets:write"),
        // reads inside a write still need read
        (
            "UPDATE tickets SET status = (SELECT email FROM customers LIMIT 1)",
            "customers.email:read",
        ),
        (
            "UPDATE tickets SET status = 'x' WHERE note = (SELECT ssn FROM customers LIMIT 1)",
            "customers.ssn:read",
        ),
        (
            "DELETE FROM jobs WHERE id IN (SELECT id FROM customers WHERE email = 'x')",
            "customers.email:read",
        ),
        ("INSERT INTO jobs SELECT * FROM secrets", "secrets:read"),
        (
            "UPDATE jobs SET state = 'x' RETURNING (SELECT email FROM customers LIMIT 1)",
            "customers.email:read",
        ),
        (
            "UPDATE tickets t SET status = c.email FROM customers c WHERE c.id = t.id",
            "customers.email:read",
        ),
    ] {
        assert_denied(sql, want);
    }
}

// ── DDL and statement kinds ─────────────────────────────────────────────────

#[test]
fn ddl_is_always_denied_under_a_policy() {
    for (sql, what) in [
        ("CREATE TABLE x (id int)", "CREATE TABLE"),
        ("DROP TABLE jobs", "DROP"),
        ("ALTER TABLE jobs ADD COLUMN x int", "ALTER TABLE"),
        ("TRUNCATE jobs", "TRUNCATE"),
        ("CREATE INDEX i ON jobs (id)", "CREATE INDEX"),
        ("GRANT SELECT ON jobs TO public", "GRANT"),
        ("CREATE TABLE x AS SELECT id FROM orders", "CREATE TABLE AS"),
        ("SELECT id INTO newt FROM orders", "SELECT INTO"),
        ("CREATE VIEW v AS SELECT id FROM orders", "CREATE VIEW"),
        ("DO $$ BEGIN DELETE FROM jobs; END $$", "DO"),
        (
            "CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE sql",
            "CREATE FUNCTION",
        ),
        ("COMMENT ON TABLE jobs IS 'x'", "COMMENT"),
        ("VACUUM jobs", "VACUUM"),
        ("SET ROLE admin", "SET ROLE"),
        (
            "SET SESSION AUTHORIZATION admin",
            "SET SESSION AUTHORIZATION",
        ),
        ("SET search_path = secret, public", "SET search_path"),
        ("SET SCHEMA 'secret'", "SET search_path"),
        ("ALTER SYSTEM SET work_mem = '1GB'", "ALTER SYSTEM"),
        (
            "EXPLAIN ANALYZE CREATE TABLE x AS SELECT 1",
            "CREATE TABLE AS",
        ),
    ] {
        let o = eval(Postgres, sql, &agent());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert_eq!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE), "{sql}");
        assert!(
            o.access_denied.contains(&DeniedRef {
                schema: None,
                table: what.into(),
                column: None,
                needed: Needed::Ddl,
            }),
            "{sql}: {:?}",
            denied(&o)
        );
    }
    let o = eval(Postgres, "CREATE TABLE x (id int)", &agent());
    assert_eq!(
        o.ast_node_path.as_deref(),
        Some("AccessPolicy > CREATE TABLE (ddl): denied for this identity")
    );
    // Even an identity with every table granted read/write.
    let all = allow(vec![entry("jobs", &["*"], ReadWrite)]);
    assert_denied_on(Postgres, "DROP TABLE jobs", &all, "DROP:ddl");
}

#[test]
fn session_and_transaction_statements_are_allowed() {
    for sql in [
        "BEGIN",
        "START TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT s1",
        "RELEASE SAVEPOINT s1",
        "ROLLBACK TO SAVEPOINT s1",
        "SET statement_timeout = 0",
        "SET TIME ZONE 'UTC'",
        "SET application_name = 'agent'",
        "RESET statement_timeout",
        "RESET ALL",
        "SHOW search_path",
        "SHOW transaction_isolation",
        "DECLARE c CURSOR FOR SELECT id FROM orders",
        "FETCH 10 FROM c",
        "CLOSE c",
        "LISTEN ch",
        "NOTIFY ch",
        "UNLISTEN ch",
        "DISCARD ALL",
        "CALL refresh_stats()",
    ] {
        assert_allowed(sql);
    }
    // The arguments of CALL are read.
    assert_denied(
        "CALL refresh_stats((SELECT email FROM customers LIMIT 1))",
        "customers.email:read",
    );
    // SQL-level EXECUTE is denied outright (3.8.1, see
    // `sql_level_prepared_statements_are_denied`).
    assert_denied("EXECUTE p((SELECT value FROM secrets))", "EXECUTE:ddl");
    assert_denied_on(
        Mysql,
        "CALL p((SELECT email FROM customers LIMIT 1))",
        &agent(),
        "customers.email:read",
    );
    assert_allowed_on(Mysql, "CALL p(1, 'x')", &agent());
    // set_config is SET.
    assert_denied(
        "SELECT set_config('search_path', 'secret', false)",
        "SET search_path:ddl",
    );
    assert_denied("SELECT set_config($1, $2, false)", "set_config:ddl");
    assert_allowed("SELECT set_config('application_name', 'agent', false)");
    // The analysed statement of DECLARE still counts; PREPARE is denied.
    assert_denied("PREPARE p AS SELECT email FROM customers", "PREPARE:ddl");
    assert_denied("DECLARE c CURSOR FOR SELECT * FROM secrets", "secrets:read");
}

// ── catalogue ───────────────────────────────────────────────────────────────

#[test]
fn catalogue_reads_are_denied_unless_the_schema_is_listed() {
    // A schema-less entry for a table called `tables` does not open
    // information_schema.tables, nor does one called `pg_class` open the catalogue.
    let mut p = agent();
    p.entries.push(entry("tables", &["*"], Read));
    p.entries.push(entry("pg_class", &["*"], Read));
    for (sql, want) in [
        (
            "SELECT * FROM information_schema.tables",
            "information_schema.tables:read",
        ),
        (
            "SELECT table_name FROM information_schema.columns",
            "information_schema.columns:read",
        ),
        ("SELECT relname FROM pg_class", "pg_catalog.pg_class:read"),
        (
            "SELECT * FROM pg_catalog.pg_roles",
            "pg_catalog.pg_roles:read",
        ),
        ("SELECT * FROM pg_tables", "pg_catalog.pg_tables:read"),
        (
            "SELECT usename FROM pg_stat_activity",
            "pg_catalog.pg_stat_activity:read",
        ),
        (
            "SELECT id FROM orders UNION SELECT oid::int FROM pg_class",
            "pg_catalog.pg_class:read",
        ),
        (
            "SELECT id FROM orders WHERE EXISTS (SELECT 1 FROM \"information_schema\".\"tables\")",
            "information_schema.tables:read",
        ),
    ] {
        assert_denied_on(Postgres, sql, &p, want);
    }
    // Listed with its schema: allowed.
    let mut p = agent();
    p.entries.push(in_schema(
        "information_schema",
        entry("tables", &["*"], Read),
    ));
    p.entries.push(in_schema(
        "pg_catalog",
        entry("pg_class", &["relname"], Read),
    ));
    assert_allowed_on(
        Postgres,
        "SELECT table_name FROM information_schema.tables",
        &p,
    );
    assert_allowed_on(Postgres, "SELECT relname FROM pg_class", &p);
    assert_denied_on(
        Postgres,
        "SELECT relacl FROM pg_class",
        &p,
        "pg_catalog.pg_class.relacl:read",
    );

    // MySQL
    for (sql, want) in [
        ("SELECT * FROM mysql.user", "mysql.user:read"),
        (
            "SELECT * FROM performance_schema.threads",
            "performance_schema.threads:read",
        ),
        ("SELECT * FROM sys.processlist", "sys.processlist:read"),
        (
            "SELECT TABLE_NAME FROM information_schema.TABLES",
            "information_schema.TABLES:read",
        ),
        // SHOW reads the catalogue: the information_schema view it mirrors.
        ("SHOW TABLES", "information_schema.TABLES:read"),
        ("SHOW DATABASES", "information_schema.SCHEMATA:read"),
        (
            "SHOW COLUMNS FROM customers",
            "information_schema.COLUMNS:read",
        ),
        (
            "SHOW CREATE TABLE customers",
            "information_schema.TABLES:read",
        ),
    ] {
        assert_denied_on(Mysql, sql, &agent(), want);
    }
    for sql in [
        "SHOW VARIABLES LIKE 'version'",
        "SHOW STATUS",
        "SHOW WARNINGS",
        "SELECT @@version",
        "SELECT @@version, id FROM customers",
        "SELECT @@SESSION.sql_mode, id FROM customers",
    ] {
        assert_allowed_on(Mysql, sql, &agent());
    }
    for (sql, what) in [
        ("SHOW GRANTS", "SHOW GRANTS"),
        ("SHOW PROCESSLIST", "SHOW PROCESSLIST"),
    ] {
        assert_denied_on(Mysql, sql, &agent(), &format!("{what}:ddl"));
    }
    // DESCRIBE reads the table's structure: every column.
    assert_denied_on(Mysql, "DESCRIBE customers", &agent(), "customers.*:read");
    assert_allowed_on(Mysql, "DESCRIBE orders", &agent());
}

// ── name resolution ─────────────────────────────────────────────────────────

#[test]
fn schemas_resolve_conservatively() {
    let public_orders = allow(vec![in_schema("public", entry("orders", &["*"], Read))]);
    assert_allowed_on(Postgres, "SELECT id FROM orders", &public_orders);
    assert_allowed_on(Postgres, "SELECT id FROM public.orders", &public_orders);
    assert_denied_on(
        Postgres,
        "SELECT id FROM other.orders",
        &public_orders,
        "other.orders:read",
    );
    // MySQL has no default schema the engine can see: unqualified names only
    // match schema-less entries.
    let db_orders = allow(vec![in_schema("shop", entry("orders", &["*"], Read))]);
    assert_allowed_on(Mysql, "SELECT id FROM shop.orders", &db_orders);
    assert_denied_on(Mysql, "SELECT id FROM orders", &db_orders, "orders:read");
    // A schema-less entry is the default schema's table only (3.8.1, see
    // `an_entry_without_a_schema_matches_only_the_default_schema`).
    assert_denied_on(
        Postgres,
        "SELECT id FROM other.orders",
        &agent(),
        "other.orders:read",
    );
    assert_denied_on(
        Mysql,
        "SELECT id FROM shop.orders",
        &agent(),
        "shop.orders:read",
    );
    // Identifiers compare the way each dialect compares them (3.8.1, see
    // `postgres_identifiers_fold_unless_quoted` and
    // `mysql_table_names_compare_exactly_and_column_names_do_not`).
    assert_allowed_on(Postgres, "SELECT Name FROM Customers", &agent());
    assert_allowed_on(Mysql, "SELECT `ID`, Name FROM `customers`", &agent());
}

// ── the other dialects ──────────────────────────────────────────────────────

#[test]
fn mysql_applies_the_same_derivation() {
    let p = agent();
    for sql in [
        "SELECT `id`, `name` FROM `customers` WHERE `id` = ?",
        "SELECT c.id, o.total FROM customers c JOIN orders o ON o.customer_id = c.id ORDER BY o.total LIMIT 10",
        "SELECT * FROM orders",
        "SELECT COUNT(*) FROM customers",
        "UPDATE tickets SET status = 'closed' WHERE id = 1",
        "INSERT INTO tickets (id, status) VALUES (1, 'a') ON DUPLICATE KEY UPDATE status = VALUES(status)",
        "DELETE FROM jobs WHERE id = 1 LIMIT 1",
        // DELETE: a table-level write, whatever the column list (v3.3).
        "DELETE FROM tickets WHERE id = 1",
        "DELETE t FROM tickets t JOIN orders o ON o.id = t.id",
        "SELECT LOWER(name) AS n FROM customers ORDER BY n",
        "BEGIN",
        "SET NAMES utf8mb4",
        "SET autocommit = 1",
        "SET @@SESSION.sql_auto_is_null = 0",
    ] {
        assert_allowed_on(Mysql, sql, &p);
    }
    for (sql, want) in [
        ("SELECT `email` FROM `customers`", "customers.email:read"),
        ("SELECT email AS e FROM customers", "customers.email:read"),
        ("SELECT LOWER(email) FROM customers", "customers.email:read"),
        (
            "SELECT id FROM customers WHERE email = 'x'",
            "customers.email:read",
        ),
        (
            "SELECT id FROM customers ORDER BY email",
            "customers.email:read",
        ),
        (
            "SELECT id FROM customers GROUP BY email",
            "customers.email:read",
        ),
        (
            "SELECT o.id FROM orders o JOIN customers c ON c.email = o.email",
            "customers.email:read",
        ),
        (
            "SELECT o.id FROM orders o JOIN customers c USING (email)",
            "customers.email:read",
        ),
        (
            "SELECT id FROM orders WHERE EXISTS (SELECT 1 FROM customers c WHERE c.email = 'x')",
            "customers.email:read",
        ),
        (
            "SELECT (SELECT email FROM customers LIMIT 1)",
            "customers.email:read",
        ),
        (
            "WITH x AS (SELECT email FROM customers) SELECT 1 FROM x",
            "customers.email:read",
        ),
        (
            "SELECT id FROM orders UNION SELECT email FROM customers",
            "customers.email:read",
        ),
        (
            "SELECT id FROM (SELECT id, email FROM customers) s",
            "customers.email:read",
        ),
        ("SELECT * FROM customers", "customers.*:read"),
        ("SELECT c.* FROM customers c", "customers.*:read"),
        ("SELECT COUNT(*) FROM secrets", "secrets:read"),
        // `"email"` may be the column under ANSI_QUOTES (as 085).
        (
            "SELECT id FROM customers WHERE \"email\" = 'x'",
            "customers.email:read",
        ),
        ("UPDATE orders SET total = 0 WHERE id = 1", "orders:write"),
        ("UPDATE tickets SET priority = 1", "tickets.priority:write"),
        (
            "UPDATE tickets t JOIN orders o ON o.id = t.id SET o.total = 0",
            "orders:write",
        ),
        ("DELETE FROM orders WHERE id = 1", "orders:write"),
        ("SELECT id FROM orders FOR UPDATE", "orders:write"),
        (
            "INSERT INTO tickets VALUES (1, 'a', 'b')",
            "tickets.*:write",
        ),
        (
            "INSERT INTO tickets (id, status) VALUES (1, 'a') ON DUPLICATE KEY UPDATE priority = 1",
            "tickets.priority:write",
        ),
        ("LOCK TABLES orders WRITE", "orders:write"),
        ("CREATE TABLE x (id INT)", "CREATE TABLE:ddl"),
        ("DROP TABLE jobs", "DROP:ddl"),
        ("TRUNCATE TABLE jobs", "TRUNCATE:ddl"),
        ("ALTER TABLE jobs ADD COLUMN x INT", "ALTER TABLE:ddl"),
        ("USE other_db", "USE:ddl"),
        ("GRANT SELECT ON orders TO agent", "GRANT:ddl"),
    ] {
        assert_denied_on(Mysql, sql, &p, want);
    }
}

#[test]
fn mysql_text_is_read_the_way_mysql_executes_it() {
    // The 3.7.0 MySQL normalization runs first: an executable comment is
    // part of the statement MySQL runs, so the predicate inside it counts.
    for sql in [
        "SELECT id FROM customers /*!50000 WHERE email = 'x' */",
        "SELECT id FROM customers /*! WHERE email = 'x' */",
    ] {
        let o = eval(Mysql, sql, &agent());
        assert_eq!(o.decision, Decision::Block, "{sql}: {o:?}");
        assert!(
            denied(&o).contains(&"customers.email:read".to_string()),
            "{sql}: {:?}",
            denied(&o)
        );
    }
    assert_allowed_on(
        Mysql,
        "SELECT id FROM customers /* WHERE email = 'x' */",
        &agent(),
    );
}

#[test]
fn oracle_and_sql_server_apply_the_same_derivation() {
    for d in [Oracle, MsSql] {
        assert_allowed_on(d, "SELECT id, name FROM customers WHERE id = 1", &agent());
        assert_denied_on(
            d,
            "SELECT email FROM customers",
            &agent(),
            "customers.email:read",
        );
        assert_denied_on(
            d,
            "SELECT id FROM customers WHERE email = 'x'",
            &agent(),
            "customers.email:read",
        );
        assert_denied_on(d, "SELECT * FROM customers", &agent(), "customers.*:read");
        assert_denied_on(d, "UPDATE orders SET total = 0", &agent(), "orders:write");
        assert_denied_on(d, "DROP TABLE jobs", &agent(), "DROP:ddl");
    }
    // Oracle pseudo-columns are not columns.
    assert_allowed_on(
        Oracle,
        "SELECT id, ROWNUM FROM customers WHERE ROWNUM < 10",
        &agent(),
    );
    let dbo = allow(vec![in_schema("dbo", entry("orders", &["*"], Read))]);
    assert_allowed_on(MsSql, "SELECT id FROM orders", &dbo);
    assert_denied_on(
        MsSql,
        "SELECT * INTO copy FROM orders",
        &dbo,
        "SELECT INTO:ddl",
    );
}

// ── an empty allowlist ──────────────────────────────────────────────────────

#[test]
fn an_identity_with_no_grants_can_touch_no_table() {
    let none = allow(Vec::new());
    for d in [Postgres, Mysql] {
        assert_denied_on(d, "SELECT * FROM orders", &none, "orders:read");
        assert_denied_on(d, "SELECT count(*) FROM orders", &none, "orders:read");
        assert_denied_on(d, "INSERT INTO jobs (id) VALUES (1)", &none, "jobs:write");
        assert_allowed_on(d, "SELECT 1", &none);
        assert_allowed_on(d, "COMMIT", &none);
    }
}

// ── precedence with VERICTO-085 (design §6.1) ───────────────────────────────

#[derive(Clone, Copy, Debug)]
enum TagCase {
    Block,
    Mask,
    Flag,
    NoTag,
}

fn precedence_case(tag: TagCase, allowed: bool, mode: AccessMode) -> EvaluationOutcome {
    let cols: &[&str] = if allowed { &["id", "email"] } else { &["id"] };
    let p = AccessPolicy {
        mode,
        ..allow(vec![entry("customers", cols, Read)])
    };
    let tags = match tag {
        TagCase::NoTag => Vec::new(),
        t => vec![SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy: match t {
                TagCase::Block => SensitivePolicy::Block,
                TagCase::Mask => SensitivePolicy::Mask,
                _ => SensitivePolicy::Flag,
            },
            mask_style: MaskStyle::Email,
        }],
    };
    let policy = EnforcementPolicy {
        sensitive_columns: tags,
        access_policy: Some(p),
        ..EnforcementPolicy::default()
    };
    crate::evaluate("SELECT id, email FROM customers", Postgres, &[], &policy)
}

/// (tag, allowed, mode) → (decision, flat rule code, rewritten?, violation
/// codes, denied?)
type Row = (
    TagCase,
    bool,
    AccessMode,
    Decision,
    Option<&'static str>,
    bool,
    &'static [&'static str],
    bool,
);

#[test]
fn precedence_with_sensitive_columns_follows_the_design_table() {
    use AccessMode::{Enforce, Observe};
    use Decision::{Allow as A, Block as B, Flag as F};
    const S: &str = "VERICTO-085";
    const X: &str = "VERICTO-087";
    // (tag, allowed, mode) → (decision, flat rule code, rewritten?, violation codes, denied?)
    #[rustfmt::skip]
    let table: &[Row] = &[
        (TagCase::Block, true,  Enforce, B, Some(S), false, &[S],    false),
        (TagCase::Block, true,  Observe, B, Some(S), false, &[S],    false),
        (TagCase::Block, false, Enforce, B, Some(S), false, &[S, X], true),
        (TagCase::Block, false, Observe, B, Some(S), false, &[S, X], true),
        (TagCase::Mask,  true,  Enforce, F, Some(S), true,  &[S],    false),
        (TagCase::Mask,  true,  Observe, F, Some(S), true,  &[S],    false),
        (TagCase::Mask,  false, Enforce, B, Some(X), false, &[X, S], true),
        (TagCase::Mask,  false, Observe, F, Some(S), true,  &[S, X], true),
        (TagCase::NoTag, true,  Enforce, A, None,    false, &[],     false),
        (TagCase::NoTag, true,  Observe, A, None,    false, &[],     false),
        (TagCase::NoTag, false, Enforce, B, Some(X), false, &[X],    true),
        (TagCase::NoTag, false, Observe, F, Some(X), false, &[X],    true),
        (TagCase::Flag,  true,  Enforce, F, Some(S), false, &[S],    false),
        (TagCase::Flag,  true,  Observe, F, Some(S), false, &[S],    false),
        (TagCase::Flag,  false, Enforce, B, Some(X), false, &[X, S], true),
        (TagCase::Flag,  false, Observe, F, Some(S), false, &[S, X], true),
    ];
    for &(tag, allowed, mode, decision, code, rewritten, codes, has_denied) in table {
        let o = precedence_case(tag, allowed, mode);
        let ctx = format!("{tag:?} allowed={allowed} {mode:?}: {o:?}");
        assert_eq!(o.decision, decision, "{ctx}");
        assert_eq!(o.rule_code.as_deref(), code, "{ctx}");
        assert_eq!(o.rewritten_query.is_some(), rewritten, "{ctx}");
        let got: Vec<&str> = o.violations.iter().map(|v| v.rule_code.as_str()).collect();
        assert_eq!(got, codes, "{ctx}");
        assert_eq!(!o.access_denied.is_empty(), has_denied, "{ctx}");
        if let Some(v) = o.violations.iter().find(|v| v.rule_code == X) {
            let want = if mode == Observe {
                EnforcementAction::Flag
            } else {
                EnforcementAction::Block
            };
            assert_eq!(v.action, want, "{ctx}");
        }
    }
    // Allowed + mask: the 085 rewrite, unchanged by the allowlist.
    let o = precedence_case(TagCase::Mask, true, Enforce);
    assert_eq!(
        o.rewritten_query.as_deref(),
        Some(
            "SELECT id, regexp_replace(email::text, '^(.)[^@]*(@.*)?$', E'\\\\1***\\\\2') AS email FROM customers"
        )
    );
    // The tagged column is still reported for the audit trail.
    assert_eq!(
        precedence_case(TagCase::Mask, false, Enforce)
            .sensitive_columns
            .len(),
        1
    );
}

#[test]
fn precedence_holds_on_mysql_with_its_rewrite() {
    let p = allow(vec![entry("customers", &["id", "email"], Read)]);
    let policy = EnforcementPolicy {
        sensitive_columns: vec![SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy: SensitivePolicy::Mask,
            mask_style: MaskStyle::Full,
        }],
        access_policy: Some(p),
        ..EnforcementPolicy::default()
    };
    let o = crate::evaluate("SELECT id, email FROM customers", Mysql, &[], &policy);
    assert_eq!(o.decision, Decision::Flag, "{o:?}");
    assert!(o.rewritten_query.is_some(), "{o:?}");
    let o = crate::evaluate(
        "SELECT id, email FROM customers WHERE ssn = 'x'",
        Mysql,
        &[],
        &policy,
    );
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert!(
        o.rewritten_query.is_none(),
        "a denied query is never forwarded, masked or not"
    );
}

#[test]
fn the_access_verdict_is_a_floor_over_the_rules() {
    use crate::rules::engine::{Rule, RuleType, Severity};
    let rule = |code: &str, sev| Rule {
        rule_id: code.into(),
        code: code.into(),
        severity: sev,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    };
    let rules = vec![
        rule("VERICTO-001", Severity::Critical),
        rule("VERICTO-050", Severity::Medium),
    ];
    // A WHERE-less DELETE on a granted table: the rule still blocks.
    let o = crate::evaluate("DELETE FROM jobs", Postgres, &rules, &with(agent()));
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-001"));
    // A flagged rule and a denied table: the denial blocks and leads.
    let o = crate::evaluate(
        "SELECT value FROM secrets",
        Postgres,
        &rules,
        &with(agent()),
    );
    assert_eq!(o.decision, Decision::Block);
    assert_eq!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE));
    let codes: Vec<&str> = o.violations.iter().map(|v| v.rule_code.as_str()).collect();
    assert_eq!(codes, vec![ACCESS_RULE_CODE, "VERICTO-050"]);
    // Listing VERICTO-087 in the rules slice is a no-op.
    let o = crate::evaluate(
        "SELECT value FROM secrets",
        Postgres,
        &[rule(ACCESS_RULE_CODE, Severity::Critical)],
        &EnforcementPolicy::default(),
    );
    assert_eq!(o.decision, Decision::Allow);
}

// ── observe mode and monitor_mode ───────────────────────────────────────────

#[test]
fn observe_mode_flags_and_never_blocks() {
    let p = AccessPolicy {
        mode: AccessMode::Observe,
        ..agent()
    };
    for sql in [
        "SELECT * FROM secrets",
        "SELECT email FROM customers",
        "DROP TABLE jobs",
        "UPDATE orders SET total = 0",
    ] {
        let o = eval(Postgres, sql, &p);
        assert_eq!(o.decision, Decision::Flag, "{sql}: {o:?}");
        assert_eq!(o.action, Some(EnforcementAction::Flag));
        assert_eq!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE));
        assert!(!o.access_denied.is_empty(), "observe still records: {sql}");
    }
    assert_allowed_on(Postgres, "SELECT id FROM customers", &p);
    // monitor_mode never blocks either.
    let policy = EnforcementPolicy {
        monitor_mode: true,
        ..with(agent())
    };
    let o = crate::evaluate("SELECT * FROM secrets", Postgres, &[], &policy);
    assert_eq!(o.decision, Decision::Flag);
    assert_eq!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE));
}

// ── parse errors ────────────────────────────────────────────────────────────

#[test]
fn parse_errors_fail_closed_under_an_enforced_policy() {
    let bad = "SELEC email FROM customers";
    let o = eval(Postgres, bad, &agent());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some("VERICTO-PARSE-ERROR"));
    assert_eq!(
        with(agent()).effective_parse_error(),
        ParseErrorAction::Block
    );
    // Observe keeps the host's choice (fail-open default: flag).
    let observe = AccessPolicy {
        mode: AccessMode::Observe,
        ..agent()
    };
    assert_eq!(eval(Postgres, bad, &observe).decision, Decision::Flag);
    assert_eq!(
        with(observe).effective_parse_error(),
        ParseErrorAction::AllowReport
    );
    // MySQL syntax sqlparser rejects cannot smuggle a read past an allowlist.
    let o = eval(
        Mysql,
        "SELECT email FROM customers INTO OUTFILE '/tmp/x'",
        &agent(),
    );
    assert_eq!(o.decision, Decision::Block, "{o:?}");
}

#[test]
fn analysis_too_deep_fails_closed() {
    let mut sql = String::from("SELECT id FROM orders WHERE id = ");
    for _ in 0..60 {
        sql.push_str("(SELECT ");
    }
    sql.push('1');
    for _ in 0..60 {
        sql.push(')');
    }
    let o = eval(Postgres, &sql, &agent());
    assert_eq!(o.decision, Decision::Block, "{o:?}");
}

// ── None: no change, and no cost ────────────────────────────────────────────

/// Queries of every kind, for the "no policy = 3.7.0" checks.
const MIXED: &[(&str, Dialect)] = &[
    ("SELECT * FROM secrets", Postgres),
    ("SELECT email FROM customers WHERE id = $1", Postgres),
    ("DELETE FROM orders", Postgres),
    ("DROP TABLE jobs", Postgres),
    ("UPDATE t SET a = 1 WHERE id = 1 OR 1 = 1", Postgres),
    ("SELEC broken", Postgres),
    ("SELECT * FROM mysql.user", Mysql),
    ("DELETE FROM orders /*! WHERE id = 1 */", Mysql),
    ("SHOW TABLES", Mysql),
    ("SELECT * FROM customers", MsSql),
];

#[test]
fn no_policy_means_exactly_todays_outcome() {
    use crate::rules::engine::{Rule, RuleType, Severity};
    let rules: Vec<Rule> = ["VERICTO-001", "VERICTO-010", "VERICTO-050", "VERICTO-090"]
        .iter()
        .map(|c| Rule {
            rule_id: c.to_string(),
            code: c.to_string(),
            severity: Severity::Critical,
            default_action: EnforcementAction::Block,
            rule_type: RuleType::Standard,
            ast_condition_yaml: None,
        })
        .collect();
    for &(sql, d) in MIXED {
        let base = EnforcementPolicy::default();
        assert!(base.access_policy.is_none());
        let o = crate::evaluate(sql, d, &rules, &base);
        assert!(o.access_denied.is_empty(), "{sql}");
        assert!(
            o.violations.iter().all(|v| v.rule_code != ACCESS_RULE_CODE),
            "{sql}"
        );
    }
    // The policy JSON without the field is the 3.7.0 JSON.
    let json = serde_json::to_value(EnforcementPolicy::default()).unwrap();
    assert!(json.get("access_policy").is_none(), "{json}");
    let back: EnforcementPolicy = serde_json::from_value(json).unwrap();
    assert_eq!(back, EnforcementPolicy::default());
}

#[test]
fn the_analysis_never_runs_without_a_policy() {
    use crate::access::ANALYSES;
    ANALYSES.with(|n| n.set(0));
    for &(sql, d) in MIXED {
        let _ = crate::evaluate(sql, d, &[], &EnforcementPolicy::default());
    }
    assert_eq!(ANALYSES.with(|n| n.get()), 0, "zero cost: never entered");
    let _ = eval(Postgres, "SELECT 1", &agent());
    assert_eq!(ANALYSES.with(|n| n.get()), 1);
}

// ── determinism and JSON ────────────────────────────────────────────────────

#[test]
fn verdict_is_deterministic_regardless_of_entry_order() {
    let sql = "SELECT email, ssn, s.value FROM customers c, secrets s, admin_users a WHERE a.x = 1";
    let a = eval(Postgres, sql, &agent());
    let mut rev = agent();
    rev.entries.reverse();
    let b = eval(Postgres, sql, &rev);
    assert_eq!(a.ast_node_path, b.ast_node_path);
    assert_eq!(a.access_denied, b.access_denied);
    assert_eq!(
        denied(&a),
        vec![
            "admin_users:read",
            "customers.email:read",
            "customers.ssn:read",
            "secrets:read"
        ]
    );
    assert_eq!(
        a.ast_node_path.as_deref(),
        Some("AccessPolicy > admin_users (read) (+3 more)")
    );
}

#[test]
fn json_shape_round_trips() {
    let json = serde_json::json!({
        "mode": "enforce",
        "ddl": "deny",
        "entries": [
            {"schema": "public", "table": "orders", "columns": "*", "access": "read"},
            {"schema": null, "table": "customers", "columns": ["id", "name"], "access": "read"},
            {"table": "tickets", "columns": ["id", "status"], "access": "read_write"}
        ]
    });
    let p: AccessPolicy = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(p.mode, AccessMode::Enforce);
    assert_eq!(p.entries[0].columns, AccessColumns::AllColumns);
    assert_eq!(p.entries[0].schema.as_deref(), Some("public"));
    assert_eq!(p.entries[1].schema, None);
    assert_eq!(p.entries[2].access, ReadWrite);
    let again: AccessPolicy = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
    assert_eq!(again, p);
    assert_eq!(serde_json::to_value(&p.entries[0]).unwrap()["columns"], "*");

    // Inside the enforcement policy.
    let ep: EnforcementPolicy = serde_json::from_value(serde_json::json!({
        "critical": "block", "high": "block", "medium": "flag", "low": "monitor",
        "informational": "monitor", "parse_error": "allow_report", "monitor_mode": false,
        "access_policy": json
    }))
    .unwrap();
    assert_eq!(ep.access_policy, Some(p));

    let d = DeniedRef {
        schema: Some("public".into()),
        table: "customers".into(),
        column: Some("email".into()),
        needed: Needed::Read,
    };
    assert_eq!(
        serde_json::to_string(&d).unwrap(),
        r#"{"schema":"public","table":"customers","column":"email","needed":"read"}"#
    );
}

#[test]
fn unknown_values_deserialize_fail_safe() {
    let p: AccessPolicy = serde_json::from_value(serde_json::json!({
        "mode": "whatever",
        "ddl": "allow",
        "entries": [
            {"table_name": "a", "columns": "id", "access": "admin"},
            {"schema_name": "s", "table": "b", "columns": ["x"], "access": "RW"},
            {"table": "c"}
        ]
    }))
    .unwrap();
    assert_eq!(p.mode, AccessMode::Enforce, "unknown mode enforces");
    assert_eq!(p.ddl, DdlPolicy::Deny);
    assert_eq!(
        p.entries[0].columns,
        AccessColumns::List(vec!["id".into()]),
        "never widened to *"
    );
    assert_eq!(
        p.entries[0].access, Read,
        "unknown access never grants writes"
    );
    assert_eq!(p.entries[1].access, ReadWrite);
    assert_eq!(p.entries[1].schema.as_deref(), Some("s"));
    assert_eq!(p.entries[2].columns, AccessColumns::List(Vec::new()));
    assert_eq!(p.entries[2].access, Read);
    let empty: AccessPolicy = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(empty, allow(Vec::new()));
}

#[test]
fn the_proxy_selects_the_policy_of_the_session_user() {
    let map: AccessPolicyMap = serde_json::from_value(serde_json::json!({
        "support_agent": {"mode": "enforce", "entries": [{"table": "orders", "columns": "*"}]},
        "reporting_bot": {"mode": "observe", "entries": []},
        "*": {"entries": []}
    }))
    .unwrap();
    assert_eq!(map.for_user("support_agent").unwrap().entries.len(), 1);
    assert_eq!(
        map.for_user("reporting_bot").unwrap().mode,
        AccessMode::Observe
    );
    assert!(
        map.for_user("Support_Agent").unwrap().entries.is_empty(),
        "exact match, else the default"
    );
    let no_default: AccessPolicyMap =
        serde_json::from_value(serde_json::json!({"support_agent": {}})).unwrap();
    assert!(
        no_default.for_user("app").is_none(),
        "no policy: today's behaviour"
    );
    assert!(AccessPolicyMap::default().for_user("x").is_none());
}

// ── session boilerplate (drivers and ORMs, on every connection) ─────────────

/// Connection-setup statements of the drivers and ORMs: Django, Rails,
/// Hibernate, Prisma, SQLAlchemy (the 3.7.0 ORM corpus and their drivers),
/// psycopg and JDBC defaults. Some of them sqlparser 0.52 rejects.
const SESSION_SETUP: &[(Dialect, &str)] = &[
    // Django (mysqlclient)
    (
        Mysql,
        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
    ),
    (Mysql, "SET NAMES utf8mb4"),
    (Mysql, "SET autocommit=0"),
    // Rails (mysql2 / pg)
    (Mysql, "BEGIN"),
    (Mysql, "COMMIT"),
    (Mysql, "SAVEPOINT active_record_1"),
    (Mysql, "RELEASE SAVEPOINT active_record_1"),
    (Mysql, "ROLLBACK TO SAVEPOINT active_record_1"),
    (Postgres, "SET client_encoding TO 'UTF8'"),
    (Postgres, "SET intervalstyle = iso_8601"),
    // Hibernate (MySQL Connector/J, pgjdbc)
    (Mysql, "set session transaction read only"),
    (Mysql, "set session transaction read write"),
    (Mysql, "SET autocommit=1"),
    (Mysql, "SET CHARACTER SET utf8mb4"),
    (Mysql, "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"),
    (Postgres, "SET extra_float_digits = 3"),
    (Postgres, "SET application_name = 'PostgreSQL JDBC Driver'"),
    (
        Postgres,
        "SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED",
    ),
    (Postgres, "SET DateStyle = 'ISO, MDY'"),
    // Prisma
    (Mysql, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"),
    (Mysql, "SET time_zone = '+00:00'"),
    (Mysql, "START TRANSACTION"),
    (Postgres, "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"),
    // SQLAlchemy
    (Mysql, "ROLLBACK"),
    (
        Mysql,
        "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
    ),
    (Postgres, "BEGIN ISOLATION LEVEL REPEATABLE READ"),
    (Postgres, "SET TIME ZONE 'UTC'"),
    // psycopg
    (Postgres, "BEGIN"),
    (Postgres, "COMMIT"),
    (Postgres, "ROLLBACK"),
    (Postgres, "SET statement_timeout = 0"),
    (Postgres, "SET lock_timeout = '5s'"),
    (Postgres, "SET idle_in_transaction_session_timeout = 0"),
    (Postgres, "SET LOCAL statement_timeout = '1s'"),
    (Postgres, "SAVEPOINT sp1"),
    (Postgres, "RELEASE SAVEPOINT sp1"),
    (Postgres, "ROLLBACK TO SAVEPOINT sp1"),
    (Postgres, "SET datestyle TO 'ISO'"),
    // JDBC / Connector/J defaults
    (Mysql, "SET autocommit = 1;"),
    (Mysql, "set autocommit=1, time_zone = '+00:00'"),
    (Mysql, "START TRANSACTION READ ONLY"),
    (Mysql, "SET TRANSACTION READ WRITE"),
    // Rails (mysql2) connection setup: sql_mode built from the current one.
    (
        Mysql,
        r"SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
    ),
    (
        Mysql,
        "SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'",
    ),
    (Mysql, "SET sql_mode = 'TRADITIONAL'"),
    (Mysql, "SET @@sql_mode = ''"),
    // Connector/J, mysqlclient, PyMySQL defaults
    (Mysql, "SET character_set_results = NULL"),
    (Mysql, "SET character_set_client = utf8mb4"),
    (
        Mysql,
        "SET character_set_connection = utf8mb4, collation_connection = 'utf8mb4_0900_ai_ci'",
    ),
    (Mysql, "SET SESSION wait_timeout = 28800"),
    (Mysql, "SET interactive_timeout = 28800"),
    (Mysql, "SET net_read_timeout = 30, net_write_timeout = 60"),
    (Mysql, "SET max_execution_time = 1000"),
    (Mysql, "SET sql_select_limit = DEFAULT"),
    (Mysql, "SET session_track_schema = 1"),
    (
        Mysql,
        "SET SESSION transaction_isolation = 'READ-COMMITTED'",
    ),
    (Mysql, "SET tx_isolation = 'REPEATABLE-READ'"),
    // pgjdbc / psycopg / SQLAlchemy tuning
    (Postgres, "SET work_mem = '64MB'"),
    (Postgres, "SET maintenance_work_mem = '256MB'"),
    (Postgres, "SET temp_buffers = '16MB'"),
    (Postgres, "SET idle_session_timeout = 0"),
    (Postgres, "SET bytea_output = 'hex'"),
    (Postgres, "SET standard_conforming_strings = on"),
];

#[test]
fn session_boilerplate_is_allowed_for_an_identity_with_no_grants() {
    let none = allow(Vec::new());
    for &(d, sql) in SESSION_SETUP {
        let base = crate::evaluate(sql, d, &[], &EnforcementPolicy::default());
        let o = eval(d, sql, &none);
        assert_ne!(o.decision, Decision::Block, "{d:?} {sql}: {o:?}");
        assert_eq!(
            o.decision, base.decision,
            "{d:?} {sql}: same as without an allowlist"
        );
        assert_eq!(o.rule_code, base.rule_code, "{d:?} {sql}");
        assert!(o.access_denied.is_empty(), "{d:?} {sql}");
        // The host-side resolution agrees (proxy and sidecar parse themselves).
        assert_eq!(
            with(none.clone()).effective_parse_error_for(sql, d),
            ParseErrorAction::AllowReport,
            "{d:?} {sql}"
        );
    }
    // Not session boilerplate: a parse error still blocks under enforce.
    assert_eq!(
        with(none.clone()).effective_parse_error_for("SELEC 1", Postgres),
        ParseErrorAction::Block
    );
    assert_eq!(
        with(none).effective_parse_error_for("SET GLOBAL max_connections = 1", Mysql),
        ParseErrorAction::Block
    );
}

#[test]
fn session_statements_that_widen_access_stay_denied() {
    let none = allow(Vec::new());
    for (d, sql) in [
        (Postgres, "SET ROLE admin"),
        (Mysql, "SET ROLE admin"),
        (Postgres, "SET SESSION AUTHORIZATION admin"),
        (Postgres, "SET search_path = secret"),
        (Postgres, "SET SESSION search_path TO secret, public"),
        (
            Postgres,
            "SELECT set_config('search_path', 'secret', false)",
        ),
        (Mysql, "USE other_db"),
        // sql_mode changes lexing (ANSI_QUOTES, NO_BACKSLASH_ESCAPES).
        (Mysql, "SET sql_mode = 'ANSI_QUOTES'"),
        (Mysql, "SET SESSION sql_mode = 'NO_BACKSLASH_ESCAPES'"),
        (
            Mysql,
            "SET @@SESSION.sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')",
        ),
        (Mysql, "SET sql_mode = 'ANSI'"),
        (Mysql, "SET sql_mode = 'PIPES_AS_CONCAT'"),
        (Mysql, "SET sql_mode = 'ORACLE'"),
        (Mysql, "SET sql_mode = 'traditional, ansi_quotes'"),
        (Mysql, "SET sql_mode = CONCAT('ANSI_', 'QUOTES')"),
        (Mysql, "SET sql_mode = CONCAT(@@sql_mode, 'X')"),
        (
            Mysql,
            "SET sql_mode = REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', '')",
        ),
        (Mysql, "SET sql_mode = CONCAT(@@sql_mode, (SELECT ',ANSI'))"),
        (Mysql, "SET sql_mode = @x"),
        (Mysql, "SET @@GLOBAL.sql_mode = ''"),
        (
            Mysql,
            "SET @@SESSION.sql_mode = '', @@SESSION.foreign_key_checks = 0",
        ),
        // Unknown settings: deny by default, including dangerous ones.
        (Postgres, "SET session_replication_role = replica"),
        (Postgres, "SET default_transaction_read_only = off"),
        (Postgres, "SET check_function_bodies = off"),
        (Postgres, "SET standard_conforming_strings = off"),
        (Postgres, "SET standard_conforming_strings TO false"),
        (Mysql, "SET foreign_key_checks = 0"),
        (Mysql, "SET unique_checks = 0"),
        (Mysql, "SET sql_log_bin = 0"),
        (Mysql, "SET SESSION sql_safe_updates = 0"),
        (Mysql, "SET work_mem = '1GB', @v = (SELECT 1)"),
        // Server-wide.
        (Mysql, "SET GLOBAL max_connections = 1"),
        (Mysql, "SET @@GLOBAL.time_zone = '+00:00'"),
        (Mysql, "SET PERSIST time_zone = '+00:00'"),
        (Mysql, "SET PERSIST_ONLY time_zone = '+00:00'"),
        // Computed values.
        (Mysql, "SET @v = (SELECT email FROM customers LIMIT 1)"),
        (Mysql, "SET time_zone = (SELECT '+00:00')"),
        (Mysql, "SET time_zone = CONCAT('+0', '0:00')"),
        (Mysql, "SET autocommit = 1, @v = (SELECT 1 FROM secrets)"),
        // One statement only.
        (Mysql, "SET NAMES utf8mb4; DROP TABLE jobs"),
        (Postgres, "SET statement_timeout = 0; SELECT * FROM secrets"),
        (Mysql, "SET autocommit = 1; SELECT * FROM secrets"),
    ] {
        let o = eval(d, sql, &none);
        assert_eq!(o.decision, Decision::Block, "{d:?} {sql}: {o:?}");
        let p = with(none.clone());
        if sql.contains(';')
            || sql.contains("GLOBAL")
            || sql.contains("PERSIST")
            || sql.contains("sql_mode")
        {
            assert_eq!(
                p.effective_parse_error_for(sql, d),
                ParseErrorAction::Block,
                "{sql}"
            );
        }
    }
}

#[test]
fn session_statements_change_nothing_without_a_policy() {
    for &(d, sql) in SESSION_SETUP {
        let p = EnforcementPolicy::default();
        assert_eq!(
            p.effective_parse_error_for(sql, d),
            p.effective_parse_error(),
            "{sql}"
        );
        let o = crate::evaluate(sql, d, &[], &p);
        assert!(o.access_denied.is_empty());
        assert_ne!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE));
    }
}

// ── 3.8.1: default schema, identifier case, SQL-level prepared statements ───

fn quoted(e: AccessEntry) -> AccessEntry {
    AccessEntry {
        table: format!("\"{}\"", e.table),
        ..e
    }
}

#[test]
fn an_entry_without_a_schema_matches_only_the_default_schema() {
    // Postgres: a schema-less entry is `public`'s table.
    let p = agent();
    for sql in [
        "SELECT id FROM orders",
        "SELECT id FROM public.orders",
        "SELECT id FROM PUBLIC.orders",
        "UPDATE public.tickets SET status = 'x' WHERE id = 1",
    ] {
        assert_allowed_on(Postgres, sql, &p);
    }
    for (sql, want) in [
        ("SELECT id FROM other.orders", "other.orders:read"),
        ("SELECT count(*) FROM archive.orders", "archive.orders:read"),
        (
            "UPDATE archive.tickets SET status = 'x' WHERE id = 1",
            "archive.tickets:write",
        ),
        // The same table name in two schemas: only `public`'s is granted.
        (
            "SELECT a.id FROM public.orders a JOIN archive.orders b ON b.id = a.id",
            "archive.orders:read",
        ),
        (
            "SELECT id FROM orders WHERE id IN (SELECT o.id FROM archive.orders o)",
            "archive.orders:read",
        ),
    ] {
        assert_denied_on(Postgres, sql, &p, want);
    }
    // An entry naming a schema keeps working as in 3.8.0, and grants only it.
    let sales = allow(vec![in_schema("sales", entry("orders", &["*"], Read))]);
    assert_allowed_on(Postgres, "SELECT id FROM sales.orders", &sales);
    assert_denied_on(Postgres, "SELECT id FROM orders", &sales, "orders:read");
    assert_denied_on(
        Postgres,
        "SELECT id FROM archive.orders",
        &sales,
        "archive.orders:read",
    );
    // Both schemas granted: both readable, the join too.
    let both = allow(vec![
        entry("orders", &["*"], Read),
        in_schema("archive", entry("orders", &["id"], Read)),
    ]);
    assert_allowed_on(
        Postgres,
        "SELECT a.id, a.total FROM public.orders a JOIN archive.orders b ON b.id = a.id",
        &both,
    );
    assert_denied_on(
        Postgres,
        "SELECT b.total FROM archive.orders b",
        &both,
        "archive.orders.total:read",
    );

    // SQL Server: `dbo`.
    assert_allowed_on(MsSql, "SELECT id FROM dbo.orders", &p);
    assert_allowed_on(MsSql, "SELECT id FROM orders", &p);
    assert_denied_on(
        MsSql,
        "SELECT id FROM sales.orders",
        &p,
        "sales.orders:read",
    );

    // MySQL: the session's database, i.e. unqualified names only (the engine
    // cannot see which database is current).
    assert_allowed_on(Mysql, "SELECT id FROM orders", &p);
    assert_denied_on(Mysql, "SELECT id FROM shop.orders", &p, "shop.orders:read");
    assert_denied_on(
        Mysql,
        "SELECT o.id FROM orders o JOIN other_db.orders x ON x.id = o.id",
        &p,
        "other_db.orders:read",
    );
    let shop = allow(vec![
        entry("orders", &["*"], Read),
        in_schema("shop", entry("orders", &["*"], Read)),
    ]);
    assert_allowed_on(Mysql, "SELECT id FROM shop.orders", &shop);
    assert_allowed_on(Mysql, "SELECT id FROM orders", &shop);
    assert_denied_on(
        Mysql,
        "SELECT id FROM other_db.orders",
        &shop,
        "other_db.orders:read",
    );

    // Oracle: the user's schema, which the engine cannot see either.
    assert_allowed_on(Oracle, "SELECT id FROM orders", &p);
    assert_denied_on(Oracle, "SELECT id FROM hr.orders", &p, "hr.orders:read");
}

#[test]
fn postgres_identifiers_fold_unless_quoted() {
    let p = agent(); // `customers` (id, name), unquoted
    // Unquoted in the query: folded to lower case, the entry's table.
    for sql in [
        "SELECT id, name FROM Customers",
        "SELECT ID, NAME FROM CUSTOMERS",
        "SELECT c.Id FROM Public.Customers c",
    ] {
        assert_allowed_on(Postgres, sql, &p);
    }
    // Quoted mixed case: a different table (and column) from the lower-case
    // entry.
    assert_denied_on(
        Postgres,
        "SELECT id FROM \"Customers\"",
        &p,
        "Customers:read",
    );
    assert_denied_on(
        Postgres,
        "SELECT \"Name\" FROM customers",
        &p,
        "customers.Name:read",
    );
    assert_denied_on(
        Postgres,
        "SELECT id FROM \"Public\".customers",
        &p,
        "Public.customers:read",
    );
    // An entry written unquoted folds too: `Customers` is `customers`.
    let folded = allow(vec![entry("Customers", &["ID"], Read)]);
    assert_allowed_on(Postgres, "SELECT id FROM customers", &folded);
    assert_denied_on(
        Postgres,
        "SELECT id FROM \"Customers\"",
        &folded,
        "Customers:read",
    );
    // A quoted entry compares exactly: that is how the dashboard sends a
    // case-sensitive name.
    let exact = allow(vec![
        quoted(entry("Customers", &["id", "\"Name\""], Read)),
        in_schema("\"Sales\"", entry("orders", &["*"], Read)),
    ]);
    assert_allowed_on(Postgres, "SELECT id, \"Name\" FROM \"Customers\"", &exact);
    assert_allowed_on(Postgres, "SELECT * FROM \"Sales\".orders", &exact);
    assert_denied_on(
        Postgres,
        "SELECT id FROM customers",
        &exact,
        "customers:read",
    );
    assert_denied_on(
        Postgres,
        "SELECT name FROM \"Customers\"",
        &exact,
        "Customers.name:read",
    );
    assert_denied_on(
        Postgres,
        "SELECT * FROM sales.orders",
        &exact,
        "sales.orders:read",
    );
    // Prisma on Postgres quotes every name: its mixed-case model tables need
    // a quoted entry; its lower-case ones match either way.
    let prisma = "SELECT \"public\".\"User\".\"id\", \"public\".\"User\".\"email\" FROM \"public\".\"User\" WHERE \"public\".\"User\".\"id\" = $1 LIMIT $2 OFFSET $3";
    let user = |t: &str| allow(vec![entry(t, &["id", "email"], Read)]);
    assert_allowed_on(Postgres, prisma, &user("\"User\""));
    assert_denied_on(Postgres, prisma, &user("User"), "public.User:read");
    assert_allowed_on(
        Postgres,
        "SELECT \"public\".\"orders\".\"id\" FROM \"public\".\"orders\"",
        &agent(),
    );
    // An embedded quote is doubled, as in SQL.
    let odd = allow(vec![entry("\"we\"\"ird\"", &["*"], Read)]);
    assert_allowed_on(Postgres, "SELECT * FROM \"we\"\"ird\"", &odd);
}

#[test]
fn mysql_table_names_compare_exactly_and_column_names_do_not() {
    let p = agent();
    // Columns: case-insensitive, as MySQL compares them.
    assert_allowed_on(Mysql, "SELECT ID, `Name` FROM customers", &p);
    // Tables: exact (`lower_case_table_names=0` keeps `Customers` and
    // `customers` apart), backticks or not.
    for (sql, want) in [
        ("SELECT id FROM Customers", "Customers:read"),
        ("SELECT id FROM `CUSTOMERS`", "CUSTOMERS:read"),
        (
            "UPDATE Tickets SET status = 'x' WHERE id = 1",
            "Tickets:write",
        ),
    ] {
        assert_denied_on(Mysql, sql, &p, want);
    }
    // An entry spelled as the table is stored matches it, and only it.
    let seq = allow(vec![entry("Users", &["id", "email"], Read)]);
    assert_allowed_on(Mysql, "SELECT `id`, `EMAIL` FROM `Users` AS `User`", &seq);
    assert_denied_on(Mysql, "SELECT id FROM users", &seq, "users:read");
    // `information_schema` compares case-insensitively, as MySQL does.
    let mut cat = agent();
    cat.entries.push(in_schema(
        "information_schema",
        entry("TABLES", &["*"], Read),
    ));
    assert_allowed_on(
        Mysql,
        "SELECT table_name FROM information_schema.tables",
        &cat,
    );
    assert_allowed_on(
        Mysql,
        "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES",
        &cat,
    );
    assert_allowed_on(Mysql, "SHOW TABLES", &cat);
    // Database names compare exactly too (they are directories, like tables).
    let shop = allow(vec![in_schema("shop", entry("orders", &["*"], Read))]);
    assert_denied_on(
        Mysql,
        "SELECT id FROM SHOP.orders",
        &shop,
        "SHOP.orders:read",
    );

    // SQL Server and Oracle: unchanged, ASCII case-insensitive.
    assert_allowed_on(MsSql, "SELECT ID, Name FROM [Customers]", &p);
    assert_allowed_on(MsSql, "SELECT id FROM DBO.CUSTOMERS", &p);
    assert_allowed_on(Oracle, "SELECT ID, NAME FROM CUSTOMERS", &p);
    assert_allowed_on(Oracle, "SELECT \"ID\" FROM \"CUSTOMERS\"", &p);
}

#[test]
fn sql_level_prepared_statements_are_denied() {
    // The engine cannot know which statement an EXECUTE runs: the name is
    // bound in the session, possibly by an earlier call, or by text the
    // engine never sees (MySQL `PREPARE s FROM @sql`).
    let p = agent();
    for (sql, want) in [
        (
            "PREPARE p AS SELECT id FROM customers WHERE id = $1",
            "PREPARE:ddl",
        ),
        ("PREPARE p (int) AS SELECT * FROM secrets", "PREPARE:ddl"),
        ("EXECUTE p(1)", "EXECUTE:ddl"),
        ("EXECUTE p", "EXECUTE:ddl"),
        ("EXPLAIN EXECUTE p(1)", "EXECUTE:ddl"),
        ("DEALLOCATE p", "DEALLOCATE:ddl"),
        ("DEALLOCATE PREPARE ALL", "DEALLOCATE:ddl"),
    ] {
        assert_denied_on(Postgres, sql, &p, want);
    }
    // MySQL's `PREPARE s FROM '…'` does not parse (sqlparser reads only
    // `PREPARE s AS …`): a parse error, which blocks under an enforced policy.
    let o = eval(Mysql, "PREPARE s FROM 'SELECT id FROM customers'", &p);
    assert_eq!(o.decision, Decision::Block, "{o:?}");
    for (sql, want) in [
        ("PREPARE s AS SELECT id FROM customers", "PREPARE:ddl"),
        ("EXECUTE s", "EXECUTE:ddl"),
        ("EXECUTE s USING @a, @b", "EXECUTE:ddl"),
        ("DEALLOCATE PREPARE s", "DEALLOCATE:ddl"),
    ] {
        assert_denied_on(Mysql, sql, &p, want);
    }
    // SQL Server's EXEC is the same statement (`EXEC sp_executesql @sql`).
    assert_denied_on(MsSql, "EXEC refresh_stats", &p, "EXECUTE:ddl");
    // Observe mode reports them.
    let observe = AccessPolicy {
        mode: AccessMode::Observe,
        ..agent()
    };
    let o = eval(Postgres, "EXECUTE p(1)", &observe);
    assert_eq!(o.decision, Decision::Flag, "{o:?}");
    assert_eq!(o.rule_code.as_deref(), Some(ACCESS_RULE_CODE));
    // Without a policy nothing changes.
    for (d, sql) in [
        (Postgres, "PREPARE p AS SELECT 1"),
        (Postgres, "EXECUTE p"),
        (Postgres, "DEALLOCATE p"),
        (Mysql, "EXECUTE s"),
    ] {
        let o = crate::evaluate(sql, d, &[], &EnforcementPolicy::default());
        assert_eq!(o.decision, Decision::Allow, "{d:?} {sql}: {o:?}");
    }
}

fn with_default(schema: &str, p: AccessPolicy) -> AccessPolicy {
    AccessPolicy {
        default_schema: Some(schema.into()),
        ..p
    }
}

#[test]
fn the_host_can_name_the_default_schema() {
    // MySQL: a name qualified with the connection's database is the default
    // schema, so Prisma's `db`.`User` matches an entry without a schema.
    let p = with_default(
        "db",
        allow(vec![
            entry("User", &["*"], ReadWrite),
            entry("Post", &["*"], ReadWrite),
            entry("users", &["id", "email"], Read),
        ]),
    );
    for sql in [
        "SELECT `db`.`User`.`id`, `db`.`User`.`email` FROM `db`.`User` WHERE `db`.`User`.`id` = ? LIMIT ? OFFSET ?",
        "INSERT INTO `db`.`User` (`email`,`name`) VALUES (?,?)",
        "UPDATE `db`.`User` SET `name` = ? WHERE (`db`.`User`.`id` = ? AND 1=1)",
        "DELETE FROM `db`.`Post` WHERE (`db`.`Post`.`id` IN (?,?) AND 1=1)",
        "SELECT `db`.`users`.`email` FROM `db`.`users` WHERE `db`.`users`.`id` = ? LIMIT ? OFFSET ?",
        "SELECT `id` FROM `User`",
    ] {
        assert_allowed_on(Mysql, sql, &p);
    }
    // Any other qualifier still needs an entry naming it; the comparison is
    // exact, like MySQL database names.
    assert_denied_on(Mysql, "SELECT id FROM other.User", &p, "other.User:read");
    assert_denied_on(Mysql, "SELECT id FROM DB.User", &p, "DB.User:read");
    // The catalogue is never the default schema's.
    let cat = with_default(
        "information_schema",
        allow(vec![entry("TABLES", &["*"], Read)]),
    );
    assert_denied_on(
        Mysql,
        "SELECT * FROM information_schema.TABLES",
        &cat,
        "information_schema.TABLES:read",
    );
    // Absent: 3.8.1 without it (qualified names need an entry naming them).
    let absent = AccessPolicy {
        default_schema: None,
        ..p.clone()
    };
    assert_denied_on(
        Mysql,
        "SELECT `db`.`User`.`id` FROM `db`.`User`",
        &absent,
        "db.User:read",
    );
    assert_allowed_on(Mysql, "SELECT `id` FROM `User`", &absent);

    // Postgres: replaces `public` for unqualified and qualified names.
    let app = with_default("app", agent());
    assert_allowed_on(Postgres, "SELECT id FROM orders", &app);
    assert_allowed_on(Postgres, "SELECT id FROM app.orders", &app);
    assert_denied_on(
        Postgres,
        "SELECT id FROM public.orders",
        &app,
        "public.orders:read",
    );
    assert_allowed_on(Postgres, "SELECT id FROM public.orders", &agent());
    // SQL Server: replaces `dbo`.
    let sales = with_default("sales", agent());
    assert_allowed_on(MsSql, "SELECT id FROM sales.orders", &sales);
    assert_allowed_on(MsSql, "SELECT id FROM orders", &sales);
    assert_denied_on(
        MsSql,
        "SELECT id FROM dbo.orders",
        &sales,
        "dbo.orders:read",
    );

    // JSON: optional, and absent by default.
    let j: AccessPolicy = serde_json::from_str(r#"{"default_schema": "db"}"#).unwrap();
    assert_eq!(j.default_schema.as_deref(), Some("db"));
    let j: AccessPolicy = serde_json::from_str("{}").unwrap();
    assert_eq!(j.default_schema, None);
    assert!(
        !serde_json::to_string(&j)
            .unwrap()
            .contains("default_schema")
    );
}

// ── 3.8.1 (contract v3.3): session boilerplate is never forced to block ─────

/// A `block` and a `mask` tag on `customers` (they force parse errors to
/// block, VERICTO-085).
fn protective_tags() -> Vec<SensitiveColumn> {
    vec![
        SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "ssn".into(),
            policy: SensitivePolicy::Block,
            mask_style: MaskStyle::Full,
        },
        SensitiveColumn {
            schema: None,
            table: "customers".into(),
            column: "email".into(),
            policy: SensitivePolicy::Mask,
            mask_style: MaskStyle::Full,
        },
    ]
}

#[test]
fn session_boilerplate_is_not_blocked_by_tags_an_allowlist_or_both() {
    let tags_only = EnforcementPolicy {
        sensitive_columns: protective_tags(),
        ..EnforcementPolicy::default()
    };
    let policy_only = with(allow(Vec::new()));
    let both = EnforcementPolicy {
        sensitive_columns: protective_tags(),
        ..with(allow(Vec::new()))
    };
    for (name, p) in [
        ("tags only", &tags_only),
        ("policy only", &policy_only),
        ("both", &both),
    ] {
        for &(d, sql) in SESSION_SETUP {
            let o = crate::evaluate(sql, d, &[], p);
            assert_ne!(o.decision, Decision::Block, "{name}: {d:?} {sql}: {o:?}");
            assert!(o.access_denied.is_empty(), "{name}: {d:?} {sql}");
            // The host-side resolution agrees (proxy and sidecar parse
            // themselves): the host's choice, not a forced block.
            assert_eq!(
                p.effective_parse_error_for(sql, d),
                p.parse_error,
                "{name}: {d:?} {sql}"
            );
        }
        // A host that chose to block parse errors still blocks them.
        let strict = EnforcementPolicy {
            parse_error: ParseErrorAction::Block,
            ..p.clone()
        };
        assert_eq!(
            strict.effective_parse_error_for(
                "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
                Mysql
            ),
            ParseErrorAction::Block,
            "{name}"
        );
    }
    // Django's isolation level on a tagged MySQL workspace: sqlparser rejects
    // it; the host's parse_error (allow and report) stands.
    let o = crate::evaluate(
        "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
        Mysql,
        &[],
        &tags_only,
    );
    assert_eq!(o.decision, Decision::Flag, "{o:?}");
}

#[test]
fn unparseable_statements_off_the_session_list_still_block_with_tags() {
    let tags_only = EnforcementPolicy {
        sensitive_columns: protective_tags(),
        ..EnforcementPolicy::default()
    };
    for (d, sql) in [
        (Postgres, "SELEC ssn FROM customers"),
        (Mysql, "SELECT ssn FROM customers LOCK IN SHARE MODE"),
        (Mysql, "SET GLOBAL max_connections = 1"),
        (Mysql, "SET NAMES utf8mb4; SELEC ssn FROM customers"),
    ] {
        let o = crate::evaluate(sql, d, &[], &tags_only);
        assert_eq!(o.decision, Decision::Block, "{d:?} {sql}: {o:?}");
        assert_eq!(
            tags_only.effective_parse_error_for(sql, d),
            ParseErrorAction::Block,
            "{d:?} {sql}"
        );
    }
}
