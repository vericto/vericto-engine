# Third-party notices

This inventory describes the direct dependencies of `vericto-engine` 5.0.0 as
resolved on 2026-11-02. It does not replace the controlling license text of a
dependency or the complete dependency graph of a particular build.

A binary distributor must generate and review the inventory for the exact
`Cargo.lock`, target, features and artifact it ships. Transitive dependencies
can change without an edit to this file.

## Runtime dependencies

| Component | Version reviewed | Declared license | Project |
|---|---:|---|---|
| pg_query | 6.2.0 | MIT | https://github.com/pganalyze/pg_query.rs |
| sqlparser | 0.63.0 | Apache-2.0 | https://github.com/apache/datafusion-sqlparser-rs |
| serde | 1.0.228 | MIT OR Apache-2.0 | https://github.com/serde-rs/serde |
| serde_json | 1.0.150 | MIT OR Apache-2.0 | https://github.com/serde-rs/json |
| serde_norway | 0.9.42 | MIT OR Apache-2.0 | https://github.com/cafkafk/serde-yaml |
| regex | 1.13.1 | MIT OR Apache-2.0 | https://github.com/rust-lang/regex |
| tracing | 0.1.44 | MIT | https://github.com/tokio-rs/tracing |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | https://github.com/dtolnay/thiserror |

`pg_query` compiles libpg_query and PostgreSQL source into supported builds.
Those portions retain their upstream copyright notices and licenses, including
the PostgreSQL License and permissive notices in individual files. They are
not relicensed as Vericto code. Review the exact pg_query source package and
include its applicable notices with every distributed binary.

## Development and test dependencies

Development-only dependencies include `proptest` (MIT OR Apache-2.0), `cel`
(MIT) and `criterion` (Apache-2.0 OR MIT). They are not intended to be included
in the published library, but a distributor must check its own artifact.

## Repository fixtures

`tests/fixtures/snowflake_corpus.sql` contains third-party SQL statements used
as test input. The complete notices and license texts supplied for that fixture
are in `tests/fixtures/snowflake_corpus.LICENSES`.

## Release procedure

For every release and commercial artifact:

1. resolve and commit or preserve the exact `Cargo.lock` used for the build;
2. run `cargo deny check` and `cargo audit`;
3. generate an SBOM for the final artifact;
4. generate a notice bundle from the complete resolved dependency graph;
5. inspect native code and build-script outputs, especially pg_query;
6. include all required license texts and attribution notices next to the
   binary, container, installer or download; and
7. state in any commercial license that third-party components remain under
   their own terms.

`deny.toml` is a policy gate for declared SPDX identifiers. It does not by
itself generate notices, inspect every embedded source file or satisfy a
binary distributor's attribution obligations.
