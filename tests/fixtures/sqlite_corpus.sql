-- SQLite corpus (tests/sqlite_corpus.rs). Written for this repository (no third-party text):
-- the statements SQLite applications send, in the shapes the common ORMs and migration tools
-- emit (Django, Rails, Prisma, Drizzle, Alembic, Sequelize, Knex, TypeORM, goose), the queries
-- applications run (UPSERT, RETURNING, WITH RECURSIVE, window and JSON functions, FTS5, every
-- quoting style and placeholder), pragmas, transactions and maintenance, and the dangerous
-- statements the rules must catch. Every entry was checked with sqlite3 3.51 (`EXPLAIN <entry>`
-- reports no syntax error). Entries are separated by a line holding only `----`; each starts with
-- a `-- source:` line naming its group.
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS "django_migrations" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "app" varchar(255) NOT NULL, "name" varchar(255) NOT NULL, "applied" datetime NOT NULL)
----
-- source: orm-ddl
CREATE TABLE "auth_user" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "password" varchar(128) NOT NULL, "last_login" datetime NULL, "is_superuser" bool NOT NULL, "username" varchar(150) NOT NULL UNIQUE, "email" varchar(254) NOT NULL, "date_joined" datetime NOT NULL)
----
-- source: orm-ddl
CREATE TABLE "blog_post" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "title" varchar(200) NOT NULL, "body" text NOT NULL, "author_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED)
----
-- source: orm-ddl
CREATE INDEX "blog_post_author_id_dd7a8485" ON "blog_post" ("author_id")
----
-- source: orm-ddl
CREATE UNIQUE INDEX "blog_tag_post_id_name_uniq" ON "blog_tag" ("post_id", "name")
----
-- source: orm-ddl
ALTER TABLE "blog_post" ADD COLUMN "published_at" datetime NULL
----
-- source: orm-ddl
CREATE TABLE "new__blog_post" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "title" varchar(300) NOT NULL, "body" text NOT NULL, "author_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED)
----
-- source: orm-ddl
INSERT INTO "new__blog_post" ("id", "title", "body", "author_id") SELECT "id", "title", "body", "author_id" FROM "blog_post"
----
-- source: orm-ddl
ALTER TABLE "new__blog_post" RENAME TO "blog_post"
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS "schema_migrations" ("version" varchar NOT NULL PRIMARY KEY)
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS "ar_internal_metadata" ("key" varchar NOT NULL PRIMARY KEY, "value" varchar, "created_at" datetime(6) NOT NULL, "updated_at" datetime(6) NOT NULL)
----
-- source: orm-ddl
CREATE TABLE "articles" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "title" varchar, "body" text, "created_at" datetime(6) NOT NULL, "updated_at" datetime(6) NOT NULL)
----
-- source: orm-ddl
CREATE INDEX "index_articles_on_title" ON "articles" ("title")
----
-- source: orm-ddl
INSERT INTO "schema_migrations" ("version") VALUES ('20261014120000')
----
-- source: orm-ddl
CREATE TABLE "User" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "email" TEXT NOT NULL, "name" TEXT, "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)
----
-- source: orm-ddl
CREATE UNIQUE INDEX "User_email_key" ON "User"("email")
----
-- source: orm-ddl
CREATE TABLE "Post" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "title" TEXT NOT NULL, "authorId" INTEGER NOT NULL, CONSTRAINT "Post_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE)
----
-- source: orm-ddl
PRAGMA defer_foreign_keys=ON
----
-- source: orm-ddl
CREATE TABLE "new_User" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "email" TEXT NOT NULL, "name" TEXT NOT NULL DEFAULT '')
----
-- source: orm-ddl
INSERT INTO "new_User" ("email", "id", "name") SELECT "email", "id", coalesce("name", '') AS "name" FROM "User"
----
-- source: orm-ddl
ALTER TABLE "new_User" RENAME TO "User"
----
-- source: orm-ddl
PRAGMA foreign_keys=ON
----
-- source: orm-ddl
PRAGMA defer_foreign_keys=OFF
----
-- source: orm-ddl
CREATE TABLE `users` (`id` integer PRIMARY KEY NOT NULL, `name` text NOT NULL, `email` text NOT NULL, `created_at` integer DEFAULT (unixepoch()) NOT NULL)
----
-- source: orm-ddl
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`)
----
-- source: orm-ddl
CREATE TABLE `__new_users` (`id` integer PRIMARY KEY NOT NULL, `name` text NOT NULL, `email` text NOT NULL)
----
-- source: orm-ddl
INSERT INTO `__new_users`("id", "name", "email") SELECT "id", "name", "email" FROM `users`
----
-- source: orm-ddl
ALTER TABLE `__new_users` RENAME TO `users`
----
-- source: orm-ddl
CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL, CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num))
----
-- source: orm-ddl
INSERT INTO alembic_version (version_num) VALUES ('ae1027a6acf')
----
-- source: orm-ddl
UPDATE alembic_version SET version_num='27c6a30d7c24' WHERE alembic_version.version_num = 'ae1027a6acf'
----
-- source: orm-ddl
CREATE TABLE account (id INTEGER NOT NULL, name VARCHAR(50) NOT NULL, description VARCHAR(200), PRIMARY KEY (id))
----
-- source: orm-ddl
CREATE TABLE _alembic_tmp_account (id INTEGER NOT NULL, name VARCHAR(50) NOT NULL, PRIMARY KEY (id))
----
-- source: orm-ddl
INSERT INTO _alembic_tmp_account (id, name) SELECT account.id, account.name FROM account
----
-- source: orm-ddl
ALTER TABLE _alembic_tmp_account RENAME TO account
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS `SequelizeMeta` (`name` VARCHAR(255) NOT NULL UNIQUE PRIMARY KEY)
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS `Tasks` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `title` VARCHAR(255), `done` TINYINT(1) DEFAULT 0, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL)
----
-- source: orm-ddl
CREATE TABLE `knex_migrations` (`id` integer not null primary key autoincrement, `name` varchar(255), `batch` integer, `migration_time` datetime)
----
-- source: orm-ddl
CREATE TABLE "migrations" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "timestamp" bigint NOT NULL, "name" varchar NOT NULL)
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS goose_db_version (id INTEGER PRIMARY KEY AUTOINCREMENT, version_id INTEGER NOT NULL, is_applied INTEGER NOT NULL, tstamp TIMESTAMP DEFAULT (datetime('now')))
----
-- source: orm-ddl
CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL, tags TEXT CHECK (json_valid(tags))) STRICT
----
-- source: orm-ddl
CREATE TABLE kv (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID
----
-- source: orm-ddl
CREATE TABLE line_items (order_id INTEGER NOT NULL, sku TEXT NOT NULL, qty INTEGER NOT NULL CHECK (qty > 0), price REAL NOT NULL, total REAL GENERATED ALWAYS AS (qty * price) VIRTUAL, PRIMARY KEY (order_id, sku))
----
-- source: orm-ddl
CREATE TEMP TABLE IF NOT EXISTS import_batch (id INTEGER, payload TEXT)
----
-- source: orm-ddl
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY COLLATE NOCASE, value TEXT NOT NULL DEFAULT '')
----
-- source: orm-ddl
CREATE VIEW IF NOT EXISTS recent_posts AS SELECT id, title FROM blog_post WHERE published_at > datetime('now', '-7 days')
----
-- source: orm-ddl
CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(title, body, content='docs', content_rowid='id')
----
-- source: orm-ddl
CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN INSERT INTO docs_fts(rowid, title, body) VALUES (new.id, new.title, new.body); END
----
-- source: orm-ddl
CREATE TRIGGER articles_touch AFTER UPDATE ON articles FOR EACH ROW BEGIN UPDATE articles SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id; END
----
-- source: orm-ddl
DROP INDEX IF EXISTS "index_articles_on_title"
----
-- source: orm-ddl
DROP VIEW IF EXISTS recent_posts
----
-- source: orm-ddl
ALTER TABLE articles RENAME COLUMN body TO content
----
-- source: orm-ddl
DROP TABLE IF EXISTS "blog_post"
----
-- source: orm-ddl
DROP TRIGGER IF EXISTS docs_ai
----
-- source: app-dml
INSERT INTO users (name, email) VALUES (?, ?)
----
-- source: app-dml
INSERT INTO users (name, email) VALUES (?1, ?2) RETURNING id
----
-- source: app-dml
INSERT INTO users (id, name, email) VALUES (:id, :name, :email) ON CONFLICT(id) DO UPDATE SET name = excluded.name, email = excluded.email
----
-- source: app-dml
INSERT INTO page_views (path, day, hits) VALUES ($path, date('now'), 1) ON CONFLICT(path, day) DO UPDATE SET hits = hits + 1
----
-- source: app-dml
INSERT INTO tags (name) VALUES (@name) ON CONFLICT DO NOTHING
----
-- source: app-dml
INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', 'dark')
----
-- source: app-dml
INSERT OR IGNORE INTO tags (name) VALUES ('sqlite')
----
-- source: app-dml
REPLACE INTO settings (key, value) VALUES ('lang', 'es')
----
-- source: app-dml
INSERT INTO audit_log (actor, action, at) SELECT actor, action, at FROM import_batch WHERE at > ? LIMIT 1000
----
-- source: app-dml
INSERT INTO events (kind, payload) VALUES ('signup', json_object('user', 7, 'plan', 'pro'))
----
-- source: app-dml
INSERT INTO counters DEFAULT VALUES
----
-- source: app-dml
UPDATE users SET name = ? WHERE id = ?
----
-- source: app-dml
UPDATE OR IGNORE users SET email = lower(email) WHERE id = ?1
----
-- source: app-dml
UPDATE users SET last_seen = unixepoch() WHERE id = :id RETURNING last_seen
----
-- source: app-dml
UPDATE line_items SET qty = qty + 1 FROM orders WHERE orders.id = line_items.order_id AND orders.status = 'open'
----
-- source: app-dml
UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id IN (SELECT user_id FROM bans WHERE until > unixepoch())
----
-- source: app-dml
DELETE FROM sessions WHERE expires_at < unixepoch()
----
-- source: app-dml
DELETE FROM sessions WHERE user_id = ? RETURNING id
----
-- source: app-dml
DELETE FROM jobs WHERE id IN (SELECT id FROM jobs WHERE done = 1 ORDER BY id LIMIT 500)
----
-- source: queries
SELECT id, name, email FROM users WHERE id = ? LIMIT 1
----
-- source: queries
SELECT "User"."id", "User"."email" FROM "User" WHERE "User"."email" = ? LIMIT 1 OFFSET 0
----
-- source: queries
SELECT `users`.`id`, `users`.`name` FROM `users` WHERE `users`.`id` = ? LIMIT 1
----
-- source: queries
SELECT [id], [name] FROM [users] WHERE [id] = ? LIMIT 1
----
-- source: queries
SELECT u.id, count(p.id) AS posts FROM users u LEFT JOIN posts p ON p.author_id = u.id GROUP BY u.id HAVING count(p.id) > 5 ORDER BY posts DESC LIMIT 20
----
-- source: queries
SELECT id, title FROM posts WHERE author_id = ? ORDER BY created_at DESC LIMIT 10 OFFSET 20
----
-- source: queries
SELECT id, title FROM posts ORDER BY id LIMIT 10, 20
----
-- source: queries
WITH RECURSIVE tree(id, parent_id, depth) AS (SELECT id, parent_id, 0 FROM categories WHERE parent_id IS NULL UNION ALL SELECT c.id, c.parent_id, t.depth + 1 FROM categories c JOIN tree t ON c.parent_id = t.id) SELECT id, depth FROM tree LIMIT 1000
----
-- source: queries
WITH RECURSIVE days(d) AS (SELECT date('now', '-6 days') UNION ALL SELECT date(d, '+1 day') FROM days WHERE d < date('now')) SELECT d FROM days LIMIT 7
----
-- source: queries
WITH totals AS (SELECT user_id, sum(amount) AS spent FROM payments WHERE status = 'paid' GROUP BY user_id) SELECT user_id, spent FROM totals ORDER BY spent DESC LIMIT 10
----
-- source: queries
SELECT id, amount, sum(amount) OVER (PARTITION BY user_id ORDER BY created_at ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running FROM payments WHERE user_id = ? LIMIT 100
----
-- source: queries
SELECT id, rank() OVER w AS r, lag(amount) OVER w AS prev FROM payments WHERE user_id = ? WINDOW w AS (ORDER BY created_at) LIMIT 100
----
-- source: queries
SELECT id, row_number() OVER (ORDER BY score DESC) AS pos FROM players WHERE league = ? LIMIT 50
----
-- source: queries
SELECT json_extract(payload, '$.user.id') AS uid, payload ->> '$.kind' AS kind FROM events WHERE id = ? LIMIT 1
----
-- source: queries
SELECT e.id, j.key, j.value FROM events e, json_each(e.payload) j WHERE e.id = ? LIMIT 100
----
-- source: queries
SELECT json_group_array(name) AS names FROM tags WHERE post_id = ? LIMIT 1
----
-- source: queries
SELECT json_object('id', id, 'name', name) AS doc FROM users WHERE id = ? LIMIT 1
----
-- source: queries
SELECT rowid, title FROM docs_fts WHERE docs_fts MATCH ? ORDER BY rank LIMIT 20
----
-- source: queries
SELECT highlight(docs_fts, 0, '<b>', '</b>') AS t FROM docs_fts WHERE docs_fts MATCH 'sqlite' LIMIT 10
----
-- source: queries
SELECT strftime('%Y-%m', created_at) AS month, count(*) AS n FROM orders WHERE created_at >= date('now', 'start of month', '-11 months') GROUP BY month ORDER BY month LIMIT 12
----
-- source: queries
SELECT id FROM files WHERE name GLOB '*.sql' LIMIT 100
----
-- source: queries
SELECT id FROM users WHERE email LIKE ? ESCAPE '\' LIMIT 50
----
-- source: queries
SELECT iif(qty > 10, 'bulk', 'single') AS kind, ifnull(note, '') AS note FROM line_items WHERE order_id = ? LIMIT 100
----
-- source: queries
SELECT id, CAST(price * 100 AS INTEGER) AS cents FROM products WHERE id = ? LIMIT 1
----
-- source: queries
SELECT id, hex(randomblob(16)) AS token FROM users WHERE id = ? LIMIT 1
----
-- source: queries
SELECT printf('%05d', id) AS code, typeof(price) AS t FROM products WHERE id = ? LIMIT 1
----
-- source: queries
SELECT id FROM users WHERE id = ? UNION SELECT id FROM admins WHERE id = ? LIMIT 2
----
-- source: queries
SELECT EXISTS (SELECT 1 FROM users WHERE email = ?) AS taken
----
-- source: queries
SELECT count(*) FROM users WHERE deleted_at IS NULL
----
-- source: queries
SELECT max(version_id) FROM goose_db_version
----
-- source: queries
SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 500
----
-- source: queries
SELECT name, type FROM pragma_table_info('users') LIMIT 100
----
-- source: queries
SELECT a.id FROM users AS a INDEXED BY users_email_unique WHERE a.email = ? LIMIT 1
----
-- source: queries
SELECT id FROM users NOT INDEXED WHERE id = ? LIMIT 1
----
-- source: queries
SELECT COUNT(*) AS n FROM orders o JOIN users u USING (user_id) WHERE u.plan = 'pro'
----
-- source: queries
EXPLAIN QUERY PLAN SELECT id FROM users WHERE email = ? LIMIT 1
----
-- source: pragma-tx
PRAGMA foreign_keys = ON
----
-- source: pragma-tx
PRAGMA journal_mode = WAL
----
-- source: pragma-tx
PRAGMA synchronous = NORMAL
----
-- source: pragma-tx
PRAGMA busy_timeout = 5000
----
-- source: pragma-tx
PRAGMA cache_size = -64000
----
-- source: pragma-tx
PRAGMA temp_store = MEMORY
----
-- source: pragma-tx
PRAGMA mmap_size = 268435456
----
-- source: pragma-tx
PRAGMA user_version
----
-- source: pragma-tx
PRAGMA user_version = 7
----
-- source: pragma-tx
PRAGMA application_id = 1234
----
-- source: pragma-tx
PRAGMA table_info(users)
----
-- source: pragma-tx
PRAGMA table_xinfo("User")
----
-- source: pragma-tx
PRAGMA index_list('users')
----
-- source: pragma-tx
PRAGMA index_info(users_email_unique)
----
-- source: pragma-tx
PRAGMA foreign_key_list(posts)
----
-- source: pragma-tx
PRAGMA foreign_key_check
----
-- source: pragma-tx
PRAGMA integrity_check
----
-- source: pragma-tx
PRAGMA quick_check(10)
----
-- source: pragma-tx
PRAGMA wal_checkpoint(TRUNCATE)
----
-- source: pragma-tx
PRAGMA optimize
----
-- source: pragma-tx
PRAGMA main.page_count
----
-- source: pragma-tx
PRAGMA compile_options
----
-- source: pragma-tx
BEGIN
----
-- source: pragma-tx
BEGIN DEFERRED TRANSACTION
----
-- source: pragma-tx
BEGIN IMMEDIATE
----
-- source: pragma-tx
BEGIN EXCLUSIVE
----
-- source: pragma-tx
COMMIT
----
-- source: pragma-tx
COMMIT TRANSACTION
----
-- source: pragma-tx
END
----
-- source: pragma-tx
ROLLBACK
----
-- source: pragma-tx
SAVEPOINT batch_1
----
-- source: pragma-tx
RELEASE SAVEPOINT batch_1
----
-- source: pragma-tx
ROLLBACK TO SAVEPOINT batch_1
----
-- source: pragma-tx
ANALYZE
----
-- source: pragma-tx
ANALYZE main.users
----
-- source: pragma-tx
VACUUM
----
-- source: pragma-tx
REINDEX
----
-- source: pragma-tx
REINDEX users_email_unique
----
-- source: pragma-tx
DETACH DATABASE reports
----
-- source: dangerous
ATTACH DATABASE '/tmp/exfil.db' AS exfil
----
-- source: dangerous
ATTACH 'file:other.db?mode=ro' AS other
----
-- source: dangerous
ATTACH DATABASE ':memory:' AS scratch
----
-- source: dangerous
PRAGMA writable_schema = ON
----
-- source: dangerous
PRAGMA trusted_schema = ON
----
-- source: dangerous
PRAGMA foreign_keys = OFF
----
-- source: dangerous
PRAGMA ignore_check_constraints = 1
----
-- source: dangerous
PRAGMA journal_mode = OFF
----
-- source: dangerous
PRAGMA synchronous = OFF
----
-- source: dangerous
PRAGMA query_only = 0
----
-- source: dangerous
PRAGMA schema_version = 1
----
-- source: dangerous
SELECT load_extension('/tmp/evil.so')
----
-- source: dangerous
SELECT writefile('/tmp/users.csv', group_concat(email, char(10))) FROM users
----
-- source: dangerous
VACUUM INTO '/tmp/copy.db'
----
-- source: dangerous
VACUUM main INTO '/tmp/main.db'
----
-- source: dangerous
DELETE FROM users
----
-- source: dangerous
UPDATE users SET is_superuser = 1
----
-- source: dangerous
DELETE FROM users WHERE '1'
----
-- source: dangerous
SELECT id FROM users WHERE name = '' OR '1' LIMIT 1
----
-- source: dangerous
SELECT 1 WHERE 1 = LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000/2))))
----
-- source: dangerous
DROP TABLE users
----
-- source: dangerous
CREATE TABLE users_backup AS SELECT * FROM users
----
-- source: dangerous
CREATE TRIGGER wipe AFTER INSERT ON audit_log BEGIN DELETE FROM audit_log; END
