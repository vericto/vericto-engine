//! Guard: every dependency snippet a consumer might copy must name this repo and
//! this version.
//!
//! The snippet is a ```toml block, so unlike the Rust example below it in
//! `lib.rs` it is never compiled — nothing catches it going stale. It did: it
//! pointed at the pre-transfer `donkan168/vericto-engine` URL and `tag =
//! "v2.1.0"` while the crate was at 3.2.1, and it is the line downstream repos
//! copy to depend on the engine, so a wrong tag silently pins them to an old
//! parser.
//!
//! The README carries the same snippet, and covering only `lib.rs` left that copy
//! unguarded: it sat at `tag = "v3.1.0"` while the crate was at 3.2.5 — four
//! releases behind, with the guard green the whole time. The README is the more
//! likely of the two to be copied, so both are checked here against the same
//! manifest values.
//!
//! Mirrors the approach of `rule_catalogue_sync.rs`: the sources are pulled in at
//! compile time via `include_str!`, so the test needs no filesystem access and
//! works from any working directory.

const LIB_SRC: &str = include_str!("../src/lib.rs");
const README_SRC: &str = include_str!("../README.md");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

/// Every `vericto-engine = { git = "…", tag = "…" }` line a consumer could copy,
/// labelled by the file it came from so a failure names the stale one.
///
/// `lib.rs` carries it inside `//!` doc comments; the README carries it as a bare
/// line in a ```toml fence. Stripping an optional `//!` prefix handles both.
fn snippet_dependency_lines() -> Vec<(&'static str, &'static str)> {
    let find = |src: &'static str| -> Vec<&'static str> {
        src.lines()
            .map(str::trim_start)
            .map(|l| l.strip_prefix("//!").unwrap_or(l))
            .map(str::trim)
            .filter(|l| l.starts_with("vericto-engine = {"))
            .collect()
    };

    let mut out = Vec::new();
    for (label, src) in [("src/lib.rs", LIB_SRC), ("README.md", README_SRC)] {
        let found = find(src);
        assert!(
            !found.is_empty(),
            "no `vericto-engine = {{ … }}` line found in {label} — \
             did the Usage section move or change shape?"
        );
        out.extend(found.into_iter().map(|line| (label, line)));
    }
    out
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
    let repository = manifest_value("repository");

    for (label, line) in snippet_dependency_lines() {
        assert!(
            line.contains(&format!("git = \"{repository}\"")),
            "the {label} usage snippet does not point at Cargo.toml's `repository`\n  \
             snippet:    {line}\n  \
             repository: {repository}"
        );
    }
}

#[test]
fn usage_snippet_pins_the_current_version() {
    // Read from the manifest rather than CARGO_PKG_VERSION so the failure message
    // can show both sides, and so the test covers the manifest being the source
    // of truth for the release tag.
    let version = manifest_value("version");
    let expected = format!("tag = \"v{version}\"");

    for (label, line) in snippet_dependency_lines() {
        assert!(
            line.contains(&expected),
            "the {label} usage snippet pins a different version than Cargo.toml.\n  \
             Bump every snippet's tag together with the version.\n  \
             snippet:  {line}\n  \
             expected: {expected}"
        );
    }
}
