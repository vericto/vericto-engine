//! Regression corpus: queries shaped like the ones Rails (ActiveRecord +
//! mysql2), Hibernate, Django, Prisma and Sequelize send to MySQL, including
//! string literals with backslash escapes and quotes, and the comments some of
//! them add. The full outcome of every query (every field, under several
//! policies, with and without tags) must stay exactly what it was before the
//! MySQL lexical normalization: `tests/fixtures/mysql_orm_corpus.golden` was
//! written by this test on the commit before it.
//!
//! The same queries also run on Postgres, together with the MySQL-only
//! constructs, to show the Postgres path is untouched.
//!
//! Regenerate (only when an outcome change is intended and reviewed):
//! `VERICTO_CORPUS_BLESS=1 cargo test --test mysql_orm_corpus`.

use vericto_engine::{
    AccessPolicy, Decision, Dialect, EnforcementAction, EnforcementPolicy, MaskStyle,
    ParseErrorAction, Rule, RuleType, SensitiveColumn, SensitivePolicy, Severity, evaluate,
};

const GOLDEN: &str = "tests/fixtures/mysql_orm_corpus.golden";

/// MySQL as the ORMs send it.
const ORM: &[&str] = &[
    // ── Rails / ActiveRecord (mysql2 escapes with backslashes) ─────────────
    r"SELECT `users`.* FROM `users` WHERE `users`.`id` = 1 LIMIT 1",
    r"SELECT `users`.* FROM `users` WHERE `users`.`email` = 'o\'brien@example.com' LIMIT 1",
    r#"SELECT `users`.`id`, `users`.`email` FROM `users` WHERE `users`.`name` = 'Jo\\hn' AND `users`.`role` = 'it\'s \"fine\"' LIMIT 10"#,
    r"INSERT INTO `users` (`name`, `email`, `created_at`, `updated_at`) VALUES ('O\'Reilly', 'a@b.c', '2024-01-01 00:00:00', '2024-01-01 00:00:00')",
    r"INSERT INTO `notes` (`body`) VALUES ('C:\\temp\\'), ('line1\nline2'), ('tab\there'), ('it''s')",
    r"UPDATE `users` SET `users`.`name` = 'D\'Arcy', `users`.`updated_at` = '2024-01-02 10:00:00' WHERE `users`.`id` = 5",
    r"DELETE FROM `users` WHERE `users`.`id` = 5",
    r"SELECT `posts`.* FROM `posts` WHERE `posts`.`user_id` = 3 /*application:Blog,controller:posts,action:index*/",
    r"SELECT `posts`.`id` FROM `posts` WHERE `posts`.`user_id` = 3 LIMIT 5 /*action='index',application='Blog',controller='posts'*/",
    r"SELECT COUNT(*) FROM `posts` WHERE `posts`.`published` = TRUE",
    r"SELECT 1 AS one FROM `users` WHERE `users`.`email` = 'x@y.z' LIMIT 1",
    r"SELECT `users`.* FROM `users` WHERE (name LIKE '%50\%%' ESCAPE '\\') LIMIT 20",
    r"SELECT `users`.* FROM `users` WHERE `users`.`id` IN (1, 2, 3)",
    r"BEGIN",
    r"COMMIT",
    r"SAVEPOINT active_record_1",
    r"RELEASE SAVEPOINT active_record_1",
    r"SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
    r"SELECT `users`.`email` FROM `users` WHERE `users`.`id` = 9 LIMIT 1",
    // ── Hibernate 6 ───────────────────────────────────────────────────────
    r"select u1_0.id,u1_0.email,u1_0.name from users u1_0 where u1_0.id=?",
    r"/* select u from User u where u.name = :name */ select u1_0.id,u1_0.name from users u1_0 where u1_0.name=?",
    r"/* <criteria> */ select u1_0.id from users u1_0 where u1_0.name like ? escape '\\' limit ?",
    r"insert into users (email,name,id) values (?,?,?)",
    r"update users set email=?,name=? where id=?",
    r"delete from users where id=?",
    r"select next_val as id_val from hibernate_sequence for update",
    r"update hibernate_sequence set next_val= ? where next_val=?",
    r"select u1_0.id from users u1_0 order by u1_0.id limit ?,?",
    r"select u1_0.email from users u1_0 join orders o1_0 on u1_0.id=o1_0.user_id where o1_0.total>? limit ?",
    r"select count(*) from users u1_0",
    // ── Django (mysqlclient escapes with backslashes) ────────────────────
    r"SELECT `auth_user`.`id`, `auth_user`.`username` FROM `auth_user` WHERE `auth_user`.`username` = 'it\'s' LIMIT 21",
    r"SELECT `app_item`.`id` FROM `app_item` WHERE `app_item`.`name` LIKE '%50\\%%' LIMIT 21",
    r"INSERT INTO `django_session` (`session_key`, `session_data`, `expire_date`) VALUES ('abc', 'e30:1\'x', '2024-01-01 00:00:00.000000')",
    r"UPDATE `auth_user` SET `last_login` = '2024-01-01 00:00:00.000000' WHERE `auth_user`.`id` = 1",
    r"DELETE FROM `django_session` WHERE `django_session`.`expire_date` < '2024-01-01 00:00:00'",
    r"SELECT (1) AS `a` FROM `auth_user` WHERE `auth_user`.`id` = 1 LIMIT 1",
    r"SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
    r#"SELECT `app_doc`.`id` FROM `app_doc` WHERE JSON_EXTRACT(`app_doc`.`data`, '$."key"') = JSON_EXTRACT('"v\\\"q"', '$') LIMIT 21"#,
    r#"UPDATE `app_doc` SET `data` = '{\"a\": \"b\\\\c\"}' WHERE `app_doc`.`id` = 2"#,
    r"SELECT `users`.`email`, `users`.`name` FROM `users` WHERE `users`.`id` = 4 LIMIT 21",
    // ── Prisma ───────────────────────────────────────────────────────────
    r"SELECT `db`.`User`.`id`, `db`.`User`.`email` FROM `db`.`User` WHERE `db`.`User`.`id` = ? LIMIT ? OFFSET ?",
    r"INSERT INTO `db`.`User` (`email`,`name`) VALUES (?,?)",
    r"UPDATE `db`.`User` SET `name` = ? WHERE (`db`.`User`.`id` = ? AND 1=1)",
    r"DELETE FROM `db`.`Post` WHERE (`db`.`Post`.`id` IN (?,?) AND 1=1)",
    r"SELECT COUNT(*) AS `_count._all` FROM (SELECT `db`.`User`.`id` FROM `db`.`User` WHERE 1=1 LIMIT ? OFFSET ?) AS `sub`",
    r"SELECT `db`.`users`.`email` FROM `db`.`users` WHERE `db`.`users`.`id` = ? LIMIT ? OFFSET ?",
    // ── Sequelize (escapes with backslashes, often a trailing `;`) ───────
    r"SELECT `id`, `email`, `createdAt` FROM `Users` AS `User` WHERE `User`.`email` = 'o\'neil@example.com' LIMIT 1;",
    r"INSERT INTO `Users` (`id`,`email`,`createdAt`,`updatedAt`) VALUES (DEFAULT,?,?,?);",
    r#"UPDATE `Users` SET `bio`='line1\nline2 \"quoted\" \\ end',`updatedAt`='2024-01-01 00:00:00' WHERE `id` = 4"#,
    r"DELETE FROM `Users` WHERE `id` = 4",
    r"SELECT `User`.`id`, `Posts`.`id` AS `Posts.id` FROM `Users` AS `User` LEFT OUTER JOIN `Posts` AS `Posts` ON `User`.`id` = `Posts`.`userId`;",
    r"START TRANSACTION;",
    r"SELECT `id` FROM `Users` AS `User` WHERE `User`.`name` LIKE '%a\\_b%' LIMIT 5;",
    r"SELECT `users`.`email` AS `email` FROM `users` AS `users` WHERE `users`.`id` = 3;",
];

/// The constructs MySQL and sqlparser read differently, for the Postgres half.
const CONSTRUCTS: &[&str] = &[
    "/*! DELETE FROM accounts */",
    "/*!50000 DELETE FROM accounts */",
    "DELETE FROM accounts /*!99999 WHERE id = 1 */",
    "DELETE FROM accounts WHERE id = 1 --1 OR 1 = 1",
    "SELECT 1 /* /* */ DELETE FROM accounts */",
    "/*! DELETE FROM accounts",
    r"SELECT 'a\'; DELETE FROM accounts; -- '",
    r"SELECT id FROM accounts WHERE name = 'x\' OR 1 = 1 -- ' LIMIT 1",
];

fn rule(code: &str, sev: Severity) -> Rule {
    Rule {
        rule_id: format!("id-{code}"),
        code: code.into(),
        severity: sev,
        default_action: EnforcementAction::Block,
        rule_type: RuleType::Standard,
        ast_condition_yaml: None,
    }
}

fn ruleset() -> Vec<Rule> {
    use Severity::*;
    [
        ("VERICTO-001", Critical),
        ("VERICTO-003", Critical),
        ("VERICTO-010", Critical),
        ("VERICTO-011", Critical),
        ("VERICTO-012", Critical),
        ("VERICTO-030", Critical),
        ("VERICTO-042", Critical),
        ("VERICTO-080", Critical),
        ("VERICTO-081", Critical),
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
        ("VERICTO-050", Medium),
        ("VERICTO-051", Medium),
        ("VERICTO-061", Medium),
        ("VERICTO-060", Low),
    ]
    .into_iter()
    .map(|(c, s)| rule(c, s))
    .collect()
}

fn tag(table: &str, column: &str, policy: SensitivePolicy, style: MaskStyle) -> SensitiveColumn {
    SensitiveColumn {
        schema: None,
        table: table.into(),
        column: column.into(),
        policy,
        mask_style: style,
    }
}

fn policies() -> Vec<(&'static str, EnforcementPolicy)> {
    vec![
        ("default", EnforcementPolicy::default()),
        (
            "fail-closed",
            EnforcementPolicy {
                parse_error: ParseErrorAction::Block,
                ..EnforcementPolicy::default()
            },
        ),
        (
            "monitor",
            EnforcementPolicy {
                monitor_mode: true,
                ..EnforcementPolicy::default()
            },
        ),
        (
            "tags",
            EnforcementPolicy {
                sensitive_columns: vec![
                    tag("users", "email", SensitivePolicy::Mask, MaskStyle::Email),
                    tag("User", "email", SensitivePolicy::Mask, MaskStyle::Last4),
                    tag("Users", "email", SensitivePolicy::Flag, MaskStyle::Full),
                    tag("users", "ssn", SensitivePolicy::Block, MaskStyle::Full),
                ],
                ..EnforcementPolicy::default()
            },
        ),
    ]
}

fn render() -> String {
    let rules = ruleset();
    let mut out = String::new();
    let cases = ORM.iter().map(|q| (Dialect::Mysql, *q)).chain(
        ORM.iter()
            .chain(CONSTRUCTS)
            .map(|q| (Dialect::Postgres, *q)),
    );
    for (dialect, sql) in cases {
        for (name, policy) in policies() {
            let o = evaluate(sql, dialect, &rules, &policy);
            // 3.8.0 added `access_denied`, always empty without an
            // `access_policy` (asserted here). The golden file is the 3.7.0
            // one, byte for byte: everything else must be unchanged.
            assert!(o.access_denied.is_empty(), "{sql}");
            let line = format!("{o:?}").replace(", access_denied: []", "");
            out.push_str(&format!("{dialect:?}\t{name}\t{sql:?}\t{line}\n"));
        }
    }
    out
}

#[test]
fn orm_corpus_outcomes_are_unchanged() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    let got = render();
    if std::env::var_os("VERICTO_CORPUS_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path).expect("golden file");
    let (got_lines, want_lines): (Vec<_>, Vec<_>) = (got.lines().collect(), want.lines().collect());
    assert_eq!(got_lines.len(), want_lines.len(), "corpus size changed");
    let diffs: Vec<String> = got_lines
        .iter()
        .zip(&want_lines)
        .filter(|(g, w)| g != w)
        .map(|(g, w)| format!("- {w}\n+ {g}"))
        .collect();
    assert!(
        diffs.is_empty(),
        "{} outcomes changed:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Every table the corpus touches, granted read/write on every column, the way
/// the ORMs name them: unqualified (the default schema), and, for Prisma,
/// qualified with the MySQL database name `db` (since 3.8.1 a schema-less
/// entry is the default schema's table only, and on MySQL that is the
/// unqualified name: the engine cannot see the session's database).
fn permissive() -> AccessPolicy {
    let mut entries = schema_less_entries();
    entries.extend(PRISMA_DB_TABLES.iter().map(
        |t| serde_json::json!({"schema": "db", "table": t, "columns": "*", "access": "read_write"}),
    ));
    serde_json::from_value(serde_json::json!({ "mode": "enforce", "entries": entries })).unwrap()
}

/// The tables Prisma qualifies with the database name in the corpus.
const PRISMA_DB_TABLES: &[&str] = &["User", "Post", "users"];

fn schema_less_entries() -> Vec<serde_json::Value> {
    let tables = [
        "users",
        "notes",
        "posts",
        "orders",
        "hibernate_sequence",
        "auth_user",
        "app_item",
        "django_session",
        "app_doc",
        "User",
        "Post",
        "Users",
        "Posts",
        "accounts",
    ];
    tables
        .iter()
        .map(|t| serde_json::json!({"table": t, "columns": "*", "access": "read_write"}))
        .collect()
}

/// 3.8.1: with schema-less entries only (the 3.8.0 corpus policy) and no
/// `default_schema` from the host, exactly
/// the queries that qualify a table with a database name change — Prisma's
/// `` `db`.`User` `` on MySQL — and they change to a VERICTO-087 denial of
/// that qualified table. Every unqualified ORM query keeps its decision.
#[test]
fn schema_less_entries_do_not_cover_a_database_qualified_name() {
    let rules = ruleset();
    let policy = EnforcementPolicy {
        access_policy: Some(
            serde_json::from_value(
                serde_json::json!({ "mode": "enforce", "entries": schema_less_entries() }),
            )
            .unwrap(),
        ),
        ..EnforcementPolicy::default()
    };
    let mut changed = Vec::new();
    for sql in ORM {
        let base = evaluate(sql, Dialect::Mysql, &rules, &EnforcementPolicy::default());
        let o = evaluate(sql, Dialect::Mysql, &rules, &policy);
        if o.decision != base.decision || !o.access_denied.is_empty() {
            assert_eq!(o.decision, Decision::Block, "{sql}");
            assert!(
                o.access_denied
                    .iter()
                    .all(|d| d.schema.as_deref() == Some("db")),
                "{sql}: {:?}",
                o.access_denied
            );
            changed.push(*sql);
        }
    }
    let qualified: Vec<&str> = ORM
        .iter()
        .copied()
        .filter(|q| q.contains("`db`."))
        .collect();
    assert_eq!(changed, qualified);
    assert_eq!(changed.len(), 6);

    // With the host naming the connection's database (`default_schema`), a
    // name qualified with it is the default schema's: the same schema-less
    // entries cover all of them, and no ORM decision changes.
    let host = EnforcementPolicy {
        access_policy: Some(
            serde_json::from_value(serde_json::json!({
                "mode": "enforce",
                "default_schema": "db",
                "entries": schema_less_entries(),
            }))
            .unwrap(),
        ),
        ..EnforcementPolicy::default()
    };
    for sql in ORM {
        let base = evaluate(sql, Dialect::Mysql, &rules, &EnforcementPolicy::default());
        let o = evaluate(sql, Dialect::Mysql, &rules, &host);
        assert_eq!(o.decision, base.decision, "{sql}: {:?}", o.access_denied);
        assert!(o.access_denied.is_empty(), "{sql}: {:?}", o.access_denied);
    }
}

/// An agent granted every table its ORM uses gets exactly the decision it
/// gets with no allowlist: the allowlist adds no false positive on ORM
/// traffic (transaction control, session settings — including the ones the
/// parser rejects, such as Django's `SET SESSION TRANSACTION ISOLATION LEVEL`
/// —, upserts, joins, aliases, `SELECT … FOR UPDATE`, counts over derived
/// tables).
#[test]
fn a_permissive_allowlist_changes_no_orm_decision() {
    let rules = ruleset();
    let mut diffs = Vec::new();
    for (dialect, sql) in ORM
        .iter()
        .map(|q| (Dialect::Mysql, *q))
        .chain(ORM.iter().map(|q| (Dialect::Postgres, *q)))
    {
        let base = evaluate(sql, dialect, &rules, &EnforcementPolicy::default());
        let policy = EnforcementPolicy {
            access_policy: Some(permissive()),
            ..EnforcementPolicy::default()
        };
        let o = evaluate(sql, dialect, &rules, &policy);
        // The MySQL corpus replayed on Postgres: MySQL syntax does not parse
        // there, and a parse error blocks under an enforced allowlist —
        // except session boilerplate (here Rails' `SET @@SESSION.sql_mode`),
        // which keeps the host's parse-error choice.
        if dialect == Dialect::Postgres && base.rule_code.as_deref() == Some("VERICTO-PARSE-ERROR")
        {
            let boilerplate =
                policy.effective_parse_error_for(sql, dialect) == ParseErrorAction::AllowReport;
            let want = if boilerplate {
                base.decision
            } else {
                Decision::Block
            };
            assert_eq!(o.decision, want, "{sql}");
            continue;
        }
        if o.decision != base.decision || !o.access_denied.is_empty() {
            diffs.push(format!(
                "{dialect:?} {sql}: {:?} -> {:?} {:?} {:?}",
                base.decision, o.decision, o.ast_node_path, o.access_denied
            ));
        }
    }
    assert!(diffs.is_empty(), "{}", diffs.join("\n"));
}
