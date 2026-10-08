// Test support for tests/mysql_mask_equivalence.rs: runs SQL against a real
// MySQL with the `mysql2` driver and prints the results as JSON.
//
// stdin:  {"config": {host, port, user, password, ssl?, database?},
//          "requests": [{"sql": "...", "params": [..] | null}]}
//   params = null  → text protocol (COM_QUERY, multi-statement allowed)
//   params = [...] → binary protocol (COM_STMT_PREPARE + COM_STMT_EXECUTE)
// stdout: [{"ok": true, "columns": [...], "rows": [[string|null, ...]]}
//          | {"ok": false, "error": "..."}]
//
// Needs `mysql2` resolvable, e.g. NODE_PATH=/path/to/node_modules.
'use strict';
const mysql = require('mysql2/promise');

function cell(v) {
  if (v === null || v === undefined) return null;
  if (Buffer.isBuffer(v)) return v.toString('utf8');
  return String(v);
}

(async () => {
  const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
  const conn = await mysql.createConnection({
    ...input.config,
    multipleStatements: true,
    dateStrings: true,
    supportBigNumbers: true,
    bigNumberStrings: true,
    charset: 'utf8mb4',
  });
  const out = [];
  for (const r of input.requests) {
    try {
      const opts = { sql: r.sql, rowsAsArray: true };
      const [rows, fields] = r.params === null || r.params === undefined
        ? await conn.query(opts)
        : await conn.execute(opts, r.params);
      // A multi-statement text query returns one result per statement: keep
      // the last result set.
      let rs = rows, fs = fields;
      const multi = Array.isArray(fields) && fields.length > 0 &&
        (Array.isArray(fields[0]) || fields[0] === undefined);
      if (multi) {
        rs = rows[rows.length - 1];
        fs = fields[fields.length - 1];
      }
      const columns = Array.isArray(fs) ? fs.map((f) => f.name) : [];
      out.push({
        ok: true,
        columns,
        rows: Array.isArray(fs) && Array.isArray(rs) ? rs.map((row) => row.map(cell)) : [],
      });
    } catch (e) {
      out.push({ ok: false, error: String(e && e.message) });
    }
  }
  await conn.end();
  process.stdout.write(JSON.stringify(out));
})().catch((e) => {
  process.stderr.write(String(e && e.stack) + '\n');
  process.exit(2);
});
