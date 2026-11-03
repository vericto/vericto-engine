// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Release-law metadata must change together instead of creating two licenses
//! for one version or accepting signatures against a different CLA.

use std::fs;

fn root(path: &str) -> String {
    fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
        .unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
}

#[test]
fn version_5_is_the_first_agpl_release_everywhere() {
    let version = env!("CARGO_PKG_VERSION");
    let major: u64 = version.split('.').next().unwrap().parse().unwrap();
    assert!(
        major >= 5,
        "AGPL metadata must not be published as version 4.7.1"
    );

    let readme = root("README.md");
    assert!(readme.contains(&format!("tag = \"v{version}\"")));
    assert!(readme.contains(&format!("crate's version (`\"{version}\"`)")));
    assert!(readme.contains(&format!("`\"standard@{version}\"`)")));

    let licensing = root("LICENSING.md");
    assert!(licensing.contains("`vericto-engine` version 5.0.0 and later"));
    assert!(!licensing.contains("or under a license compatible with it"));

    let history = root("LICENSE_HISTORY.md");
    assert!(history.contains("tag `v5.0.0`"));
    assert!(history.contains("64e13ef36631ddecf15f9ba4862642e00bbed109"));
}

#[test]
fn public_license_is_the_unmodified_agpl() {
    let license = root("LICENSE");
    assert!(license.starts_with("                    GNU AFFERO GENERAL PUBLIC LICENSE\n"));
    assert!(license.contains("Version 3, 19 November 2007"));
    assert!(license.contains("Everyone is permitted to copy and distribute verbatim copies\n"));
    assert!(license.contains("of this license document, but changing it is not allowed."));
}

#[test]
fn cla_workflow_uses_the_permanent_v1_1_document_and_record() {
    let index = root("CLA.md");
    assert!(index.contains("[ICLA version 1.1](legal/cla/1.1.md)"));
    assert!(root("legal/cla/1.1.md").contains("Version 1.1"));
    assert!(root("legal/cla/1.0.md").contains("Version 1.0"));

    let workflow = root(".github/workflows/cla.yml");
    assert!(workflow.contains("const claPath = \"legal/cla/1.1.md\";"));
    assert!(workflow.contains("signatures/v1.1/cla.json"));
    assert!(
        workflow.contains(
            "const allowedBots = new Set([\"dependabot[bot]\", \"github-actions[bot]\"]);"
        )
    );
    assert!(workflow.contains("context.payload.comment.body === signatureSentence"));
    assert!(!workflow.contains("contains(github.event.comment.body"));
    assert!(workflow.contains("github.paginate(github.rest.pulls.listCommits"));
    assert!(workflow.contains("github.paginate(github.rest.issues.listComments"));
    assert!(workflow.contains("Co-authored-by:"));
    assert!(workflow.contains("commit.commit.verification?.verified !== true"));
    assert!(workflow.contains("cla_document_sha256: claDocumentSha256"));
    assert!(workflow.contains("entry.cla_version === claVersion"));
    assert!(!workflow.contains("contributor-assistant/github-action"));
    assert!(!workflow.contains("allowlist: vericto,donkan168"));
}

#[test]
fn notices_do_not_pretend_dependencies_disappear_from_binaries() {
    let notice = root("NOTICE");
    assert!(notice.contains("compiled artifact"));
    assert!(notice.contains("The contents of this NOTICE file are informational"));
    assert!(root("THIRD_PARTY_NOTICES.md").contains("pg_query"));
}
