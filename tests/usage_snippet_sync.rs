//! Guard: the dependency snippet in the crate-level docs must name this repo and
//! this version.
//!
//! The snippet is a ```toml block, so unlike the Rust example below it in
//! `lib.rs` it is never compiled — nothing catches it going stale. It did: it
//! pointed at the pre-transfer `donkan168/vericto-engine` URL and `tag =
//! "v2.1.0"` while the crate was at 3.2.1, and it is the line downstream repos
//! copy to depend on the engine, so a wrong tag silently pins them to an old
//! parser.
//!
//! Mirrors the approach of `rule_catalogue_sync.rs`: the sources are pulled in at
//! compile time via `include_str!`, so the test needs no filesystem access and
//! works from any working directory.

const LIB_SRC: &str = include_str!("../src/lib.rs");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// The `vericto-engine = { git = "…", tag = "…" }` line inside the doc snippet.
fn snippet_dependency_line() -> &'static str {
    LIB_SRC
        .lines()
        .map(str::trim_start)
        .filter_map(|l| l.strip_prefix("//!"))
        .map(str::trim)
        .find(|l| l.starts_with("vericto-engine = {"))
        .expect(
            "no `vericto-engine = { … }` line found in the lib.rs doc snippet — \
             did the Usage section move or change shape?",
        )
}

/// Value of a top-level `key = "value"` in Cargo.toml.
fn manifest_value(key: &str) -> &'static str {
    CARGO_TOML
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key} = ")))
        .map(|v| v.trim().trim_matches('"'))
        .unwrap_or_else(|| panic!("Cargo.toml has no top-level `{key}`"))
}

#[test]
fn usage_snippet_names_this_repository() {
    let line = snippet_dependency_line();
    let repository = manifest_value("repository");

    assert!(
        line.contains(&format!("git = \"{repository}\"")),
        "the lib.rs usage snippet does not point at Cargo.toml's `repository`\n  \
         snippet:    {line}\n  \
         repository: {repository}"
    );
}

#[test]
fn usage_snippet_pins_the_current_version() {
    let line = snippet_dependency_line();
    // Read from the manifest rather than CARGO_PKG_VERSION so the failure message
    // can show both sides, and so the test covers the manifest being the source
    // of truth for the release tag.
    let version = manifest_value("version");
    let expected = format!("tag = \"v{version}\"");

    assert!(
        line.contains(&expected),
        "the lib.rs usage snippet pins a different version than Cargo.toml.\n  \
         Bump the snippet's tag together with the version.\n  \
         snippet:  {line}\n  \
         expected: {expected}"
    );
}
