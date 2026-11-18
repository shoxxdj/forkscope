//! File comparison: additions, deletions, renames, binaries, EOL.

mod common;
use common::*;
use forkscope::config::Config;
use forkscope::diff::ChangeStatus;

/// Scenario 7: fork sources with added and deleted files.
#[test]
fn added_and_deleted_files() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    remove(&client, "docs/guide.md");
    remove(&client, "src/feature.py");
    write(&client, "src/new_module.py", "def new_one():\n    return 'n'\n");
    write(&client, "scripts/deploy.sh", "#!/bin/sh\necho deploy\n");

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c4);
    let s = &r.diff.stats;
    assert_eq!((s.added, s.deleted, s.modified, s.renamed, s.moved), (2, 2, 0, 0, 0));
    let d = status_of(&r, "src/feature.py").unwrap();
    assert_eq!(d.status, ChangeStatus::Deleted);
    assert!(d.old_sha256.is_some() && d.new_sha256.is_none());
    assert_eq!(d.lines_removed, 2);
    let a = status_of(&r, "src/new_module.py").unwrap();
    assert_eq!(a.status, ChangeStatus::Added);
    assert_eq!(a.lines_added, 2);
    assert_eq!(a.new_sha256.as_deref().unwrap().len(), 64);
}

/// Scenario 9: renames and moves detected without Git information.
#[test]
fn renames_without_git_information() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    // exact rename
    std::fs::rename(client.join("src/feature.py"), client.join("src/features_v2.py")).unwrap();
    // exact move
    std::fs::create_dir_all(client.join("lib")).unwrap();
    std::fs::rename(client.join("src/views.py"), client.join("lib/views.py")).unwrap();
    // rename + modification (similarity)
    let util = std::fs::read_to_string(client.join("src/util.py")).unwrap();
    std::fs::remove_file(client.join("src/util.py")).unwrap();
    write(
        &client,
        "src/helpers.py",
        &util.replace("return x + 3", "return x + 300"),
    );

    let r = analyze(&client, &up, &tmp.path().join("out"));
    let f = status_of(&r, "src/features_v2.py").unwrap();
    assert_eq!(f.status, ChangeStatus::Renamed);
    assert_eq!(f.old_path.as_deref(), Some("src/feature.py"));
    assert_eq!(f.similarity, Some(1.0));
    let v = status_of(&r, "lib/views.py").unwrap();
    assert_eq!(v.status, ChangeStatus::Moved);
    assert_eq!(v.old_path.as_deref(), Some("src/views.py"));
    let h = status_of(&r, "src/helpers.py").unwrap();
    assert_eq!(h.status, ChangeStatus::Renamed);
    assert_eq!(h.old_path.as_deref(), Some("src/util.py"));
    assert!(h.similarity.unwrap() > 0.9 && h.similarity.unwrap() < 1.0);
    assert_eq!((h.lines_added, h.lines_removed), (1, 1));
    assert_eq!(
        r.diff.stats.added + r.diff.stats.deleted,
        0,
        "no false addition/deletion"
    );
}

/// Limit: a file that is too different is not considered renamed.
#[test]
fn rename_threshold_is_respected() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    remove(&client, "src/feature.py");
    write(&client, "src/other.py", "import os\n\nclass Something:\n    pass\n");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(status_of(&r, "src/other.py").unwrap().status, ChangeStatus::Added);
    assert_eq!(status_of(&r, "src/feature.py").unwrap().status, ChangeStatus::Deleted);
}

/// Binaries, line endings, configurable extensions.
#[test]
fn binary_eol_and_extensions() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    std::fs::write(client.join("tool.bin"), [0u8, 1, 2, 3, 0, 255, 10, 13]).unwrap();
    let readme = std::fs::read_to_string(client.join("README.md")).unwrap();
    write(&client, "README.md", &readme.replace('\n', "\r\n"));

    let r = analyze(&client, &up, &tmp.path().join("out"));
    let b = status_of(&r, "tool.bin").unwrap();
    assert!(b.is_binary);
    assert!(b.hunks.is_empty());
    assert!(b.diff_file.is_none());
    let m = status_of(&r, "README.md").unwrap();
    assert!(m.eol_only, "only line endings differ");
    assert_eq!(m.lines_added + m.lines_removed, 0);
    assert!(r
        .security
        .findings
        .iter()
        .any(|f| f.rule_id == "FILE-003" && f.file == "tool.bin"));

    let mut cfg = Config::default();
    cfg.diff.include_extensions = vec!["py".into()];
    let r2 = analyze_with(&client, &up, &tmp.path().join("out2"), |o| o.config = cfg);
    assert!(r2.diff.files.iter().all(|c| c.path.ends_with(".py")));
    assert!(status_of(&r2, "README.md").is_none());
}

/// Reports are written and consistent (Markdown sections, versioned JSON, schema).
#[test]
fn reports_are_written() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    write(
        &client,
        "src/auth.py",
        &AUTH_PY.replace(
            "    if not check_password(user, password):\n        raise PermissionDenied()\n",
            "",
        ),
    );
    commit(&client, "Client", "simplification");
    let out = tmp.path().join("out");
    let r = analyze_with(&client, &up, &out, |o| o.full_diff = true);
    let md = std::fs::read_to_string(out.join("forkscope-report.md")).unwrap();
    for n in 1..=13 {
        assert!(md.contains(&format!("## {n}. ")), "section {n} manquante");
    }
    assert!(md.contains("```") || md.contains("````diff"));
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("forkscope-report.json")).unwrap()).unwrap();
    assert_eq!(json["schema_version"], forkscope::report::SCHEMA_VERSION);
    assert_eq!(json["reference"]["commit"]["hash"], up.c2.as_str());
    assert!(
        json["diff"]["files"][0]["hunks"].is_array(),
        "--full-diff includes the hunks"
    );
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("forkscope-report.schema.json")).unwrap()).unwrap();
    assert_eq!(schema["title"], "ForkScopeReport");
    assert!(out.join("diffs/src/auth.py.diff").is_file());
    let list = std::fs::read_to_string(out.join("changed-files.txt")).unwrap();
    assert!(
        list.lines()
            .any(|l| l.starts_with("M  src/auth.py") && l.trim_end().ends_with("fork")),
        "{list}"
    );
    let csv = std::fs::read_to_string(out.join("changed-files.csv")).unwrap();
    assert!(csv.starts_with("status,path,former_path,origin"));
    assert_eq!(csv.lines().count(), 2, "header + 1 file");
    assert!(md.contains("### Changed files"));
    assert_eq!(r.diff.stats.modified, 1);

    // Without --full-diff, hunks are not in the JSON.
    let out2 = tmp.path().join("out2");
    analyze(&client, &up, &out2);
    let json2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out2.join("forkscope-report.json")).unwrap()).unwrap();
    assert!(json2["diff"]["files"][0].get("hunks").is_none());
}
