//! Reference estimation without usable history: rewritten history,
//! sources without Git, intermediate commit, ambiguities and limits.

mod common;
use common::*;
use forkscope::config::Config;
use forkscope::git::history::HistoryMode;
use forkscope::git::reference::{Certainty, ReferenceMethod};
use forkscope::report::ClientMode;

/// Scenario 5: rewritten history (squashed import of v1.0, then update to v1.1 + changes).
#[test]
fn rewritten_history() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    std::fs::create_dir_all(&client).unwrap();
    git(&client, &["init", "-q", "-b", "main"]);
    export_tree(&up.dir, "v1.0", &client);
    commit(&client, "Client", "import the project");
    export_tree(&up.dir, "v1.1", &client);
    write(
        &client,
        "src/views.py",
        &VIEWS_PY.replace("    if not request.user.is_admin:\n        return forbidden()\n", ""),
    );
    let last = commit(&client, "Client", "update");

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.client.mode, ClientMode::RewrittenHistory);
    assert_eq!(r.reference.method, ReferenceMethod::SnapshotEstimation);
    assert_eq!(
        r.reference.certainty,
        Certainty::Estimated,
        "never presented as certain"
    );
    assert!(r.reference.confidence < 100.0);
    assert_eq!(r.reference.commit.hash, up.c2, "closest content: v1.1");
    let init = r
        .reference
        .estimated_initial_base
        .as_ref()
        .expect("starting point estimate");
    assert_eq!(init.commit.hash, up.c1, "the fork's first commit matches v1.0");
    let h = r.history.as_ref().unwrap();
    assert_eq!(h.mode, HistoryMode::Rewritten);
    assert_eq!(h.client_commits_total, 2);
    // The "update" commit contains the removal of the is_admin check.
    let c = h.client_commits.iter().find(|c| c.hash == last).unwrap();
    assert!(
        c.suspicious.iter().any(|s| s.detail.contains("AUTHZ-001")),
        "{:?}",
        c.suspicious
    );
}

/// Scenario 6: sources without Git history (slightly modified copy of v1.1).
#[test]
fn sources_without_git() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.1", &client);
    write(&client, "src/net.py", &NET_PY.replace("timeout=10", "timeout=30"));
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.client.mode, ClientMode::NoGitMetadata);
    assert!(r.history.is_none());
    assert_eq!(r.reference.certainty, Certainty::Estimated);
    assert_eq!(r.reference.commit.hash, up.c2);
    assert!(r.reference.location.pointing_refs.contains(&"tag:v1.1".to_string()));
    assert!(r.reference.confidence >= 60.0, "confidence {}", r.reference.confidence);
    assert!(r.reference.reasons.iter().any(|x| x.contains("identical files")));
    assert_eq!(r.diff.stats.modified, 1);
    assert_eq!(r.diff.stats.added + r.diff.stats.deleted, 0);
    // Timeline: estimated divergence, "no history" node attached with a dashed line.
    assert!(r.timeline.divergence_estimated);
    assert_eq!(r.timeline.divergence.as_ref().unwrap().hash, up.c2);
    assert!(r.timeline.last_disk_change.is_some());
    assert!(r
        .timeline
        .graph
        .nodes
        .iter()
        .any(|n| n.kind == forkscope::git::timeline::NodeKind::Snapshot));
    assert!(r.timeline.graph.edges.iter().any(|e| e.estimated));
}

/// An intermediate (untagged) commit is found from its content.
#[test]
fn untagged_intermediate_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, &up.c3, &client);
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c3);
    assert!(r.reference.location.pointing_refs.is_empty());
    assert_eq!(
        r.reference
            .location
            .describe
            .as_deref()
            .map(|d| d.starts_with("v1.1-1-g")),
        Some(true)
    );
    assert_eq!(
        r.reference
            .location
            .first_tag_containing
            .as_deref()
            .map(|d| d.starts_with("v1.2")),
        Some(true)
    );
    assert_eq!(r.diff.stats.added + r.diff.stats.deleted + r.diff.stats.modified, 0);
    assert!(r.reference.confidence > 85.0);
}

/// Git history ignored on request: same result from the content.
#[test]
fn force_snapshot_ignores_history() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.0");
    let r = analyze_with(&client, &up, &tmp.path().join("out"), |o| o.force_snapshot = true);
    assert_eq!(r.client.mode, ClientMode::ForcedSnapshot);
    assert_eq!(r.reference.commit.hash, up.c1);
    assert_eq!(r.reference.certainty, Certainty::Estimated);
}

/// Limit: two indistinguishable commits (only a file deleted by the fork differs).
#[test]
fn ambiguous_candidates_are_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    // c5 only modifies docs/guide.md
    write(&up.dir, "docs/guide.md", "Guide v2\n");
    let c5 = commit(&up.dir, "Upstream", "docs");
    let client = tmp.path().join("client");
    export_tree(&up.dir, &c5, &client);
    remove(&client, "docs/guide.md");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let picked = r.reference.commit.hash.clone();
    assert!(picked == c5 || picked == up.c4);
    let other = if picked == c5 { &up.c4 } else { &c5 };
    assert!(
        r.reference.equivalent_commits.contains(other),
        "{:?}",
        r.reference.equivalent_commits
    );
    assert!(r.reference.confidence <= 75.0);
    assert!(r.reference.reasons.iter().any(|x| x.contains("tell them apart")));
}

/// Limit: project unrelated to the source → very low confidence and warning.
#[test]
fn unrelated_project_low_confidence() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    write(&client, "main.go", "package main\nfunc main() {}\n");
    write(&client, "go.mod", "module x\n");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert!(r.reference.confidence < 35.0, "confidence {}", r.reference.confidence);
    assert!(r.reference.warnings.iter().any(|w| w.contains("very low score")));
}

/// Excluded files (node_modules…) do not affect the estimation.
#[test]
fn excluded_dirs_do_not_affect_estimation() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.2", &client);
    for i in 0..50 {
        write(
            &client,
            &format!("node_modules/pkg{i}/index.js"),
            "module.exports = 1;\n",
        );
    }
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c4);
    assert_eq!(r.diff.stats.added, 0);
    // With node_modules re-included through the configuration, the files appear.
    let mut cfg = Config::default();
    cfg.exclude.keep_dirs = vec!["node_modules".into()];
    let r2 = analyze_with(&client, &up, &tmp.path().join("out2"), |o| o.config = cfg);
    assert_eq!(r2.diff.stats.added, 50);
    assert_eq!(r2.reference.commit.hash, up.c4);
}

/// Without history: a file backported from a newer version is recognised.
#[test]
fn backported_file_without_history() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = tmp.path().join("client");
    export_tree(&up.dir, "v1.1", &client);
    let newer = git(&up.dir, &["show", "v1.2:src/net.py"]);
    write(&client, "src/net.py", &(newer + "\n"));
    write(&client, "src/mine.py", "MINE = 1\n");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c2);
    let n = status_of(&r, "src/net.py").unwrap();
    assert_eq!(n.origin, forkscope::diff::ChangeOrigin::UpstreamNewer);
    assert_eq!(n.upstream_commit.as_deref(), Some(up.c4.as_str()));
    assert_eq!(
        status_of(&r, "src/mine.py").unwrap().origin,
        forkscope::diff::ChangeOrigin::Client
    );
    assert_eq!(r.diff.stats.client_changes, 1);
}
