//! Scenarios with fork Git history: simple fork, merges, rebase,
//! cherry-pick, uncommitted changes, fork repository never modified.

mod common;
use common::*;
use forkscope::diff::ChangeOrigin;
use forkscope::git::history::HistoryMode;
use forkscope::git::patch_id::MatchKind;
use forkscope::git::reference::{Certainty, ReferenceMethod};
use forkscope::git::timeline::{EdgeKind, Lane, NodeKind};
use forkscope::report::ClientMode;

/// Scenario 1: simple fork with two specific commits.
#[test]
fn simple_fork_two_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    write(&client, "src/views.py", &VIEWS_PY.replace("def show", "def show_v2"));
    let a = commit(&client, "Client", "rename show");
    write(&client, "src/custom.py", "def custom():\n    return 1\n");
    let b = commit(&client, "Client", "add custom");

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.client.mode, ClientMode::GitHistory);
    assert_eq!(r.reference.method, ReferenceMethod::GitAncestry);
    assert_eq!(r.reference.certainty, Certainty::Exact);
    assert_eq!(r.reference.commit.hash, up.c2, "the base must be v1.1");
    assert!(r.reference.location.pointing_refs.contains(&"tag:v1.1".to_string()));
    assert!(r
        .reference
        .location
        .containing_branches
        .contains(&"branch:main".to_string()));

    let h = r.history.as_ref().unwrap();
    assert_eq!(h.mode, HistoryMode::Ancestry);
    assert_eq!(h.client_commits_total, 2);
    assert!(r.diff.files.iter().all(|c| c.origin == ChangeOrigin::Client));
    assert_eq!(r.diff.stats.client_changes, 2);
    let hashes: Vec<&str> = h.client_commits.iter().map(|c| c.hash.as_str()).collect();
    assert_eq!(hashes, vec![b.as_str(), a.as_str()]);
    let ca = h.client_commits.iter().find(|c| c.hash == a).unwrap();
    assert_eq!(ca.files, vec!["src/views.py"]);
    assert_eq!((ca.insertions, ca.deletions), (1, 1));
    assert_eq!(ca.parents, vec![up.c2.clone()]);
    // Behind main (c3, c4) and missing security fix hint.
    assert_eq!(h.behind.iter().find(|b| b.branch == "main").unwrap().commits_behind, 2);
    assert!(h.upstream_security_hints.iter().any(|c| c.hash == up.c4));

    assert_eq!(r.diff.stats.added, 1);
    assert_eq!(r.diff.stats.modified, 1);
    assert_eq!(r.diff.stats.deleted, 0);
    let v = status_of(&r, "src/views.py").unwrap();
    assert_eq!(v.commits, vec![a.clone()]);
    assert!(v.diff_file.is_some());
    assert!(tmp.path().join("out").join(v.diff_file.as_ref().unwrap()).is_file());
}

/// Scenario 2: fork integrating several source merges.
#[test]
fn fork_with_multiple_upstream_merges() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.0");
    write(&client, "src/client_a.py", "A = 1\n");
    commit(&client, "Client", "work A");
    git_as(&client, "Client", &["merge", "-q", "--no-edit", "--no-ff", "v1.1"]);
    write(&client, "src/client_b.py", "B = 2\n");
    commit(&client, "Client", "work B");
    git_as(&client, "Client", &["merge", "-q", "--no-edit", "--no-ff", &up.c3]);

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.certainty, Certainty::Exact);
    assert_eq!(r.reference.commit.hash, up.c3, "most recent integrated base");
    assert_eq!(
        r.reference.fork_point.as_ref().unwrap().hash,
        up.c1,
        "initial starting point = v1.0"
    );
    let h = r.history.as_ref().unwrap();
    assert_eq!(h.client_commits_total, 4, "2 commits + 2 merges");
    assert_eq!(h.merge_commits, 2);
    assert_eq!(h.upstream_merges.len(), 2);
    assert_eq!(
        h.upstream_integrated_since_fork, 2,
        "c2 and c3 integrated after the fork"
    );
    // Integrated source files are not fork changes.
    assert!(status_of(&r, "src/feature.py").is_none());
    assert_eq!(r.diff.stats.added, 2);
}

/// Scenario 3: fork rebased onto a newer version.
#[test]
fn fork_with_rebase() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.0");
    write(&client, "src/client.py", "X = 1\n");
    commit(&client, "Client", "fork work");
    git_as(&client, "Client", &["rebase", "-q", "v1.2"]);

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c4, "after rebase, the base is v1.2");
    let h = r.history.unwrap();
    assert_eq!(h.client_commits_total, 1);
    assert!(
        h.rebase_indicators.iter().any(|i| i.contains("rebase")),
        "expected rebase hints: {:?}",
        h.rebase_indicators
    );
    // Limit: without reflog, the rebase would only be detectable through the date gap.
}

/// Scenario 4: cherry-pick of a source commit.
#[test]
fn fork_with_cherry_pick() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    git_as(&client, "Client", &["cherry-pick", &up.c3]);
    write(&client, "src/own.py", "OWN = True\n");
    commit(&client, "Client", "own commit");

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c2);
    let h = r.history.as_ref().unwrap();
    let picked = h
        .patch_matches
        .iter()
        .find(|m| m.upstream_commit == up.c3)
        .expect("the cherry-pick of c3 must be detected by patch-id");
    // git cherry-pick keeps the author and author date: rewritten copy.
    assert!(matches!(picked.kind, MatchKind::Rewritten | MatchKind::CherryPick));
    assert_eq!(
        h.patch_matches.iter().filter(|m| m.kind != MatchKind::Reverted).count(),
        1,
        "only c3 matches"
    );
    // Origin: feature.py comes from the source, own.py from the fork.
    let f = status_of(&r, "src/feature.py").unwrap();
    assert_eq!(f.origin, ChangeOrigin::UpstreamNewer);
    assert_eq!(f.upstream_commit.as_deref(), Some(up.c3.as_str()));
    assert_eq!(status_of(&r, "src/own.py").unwrap().origin, ChangeOrigin::Client);
}

/// Fork commit that reverts a source commit.
#[test]
fn reverted_upstream_commit_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    git_as(&client, "Client", &["revert", "--no-edit", &up.c4]);
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let h = r.history.unwrap();
    assert!(h
        .patch_matches
        .iter()
        .any(|m| m.kind == MatchKind::Reverted && m.upstream_commit == up.c4));
    assert!(r.recommendations.iter().any(|x| x.contains("reverted")));
}

/// Scenario 8: uncommitted local changes.
#[test]
fn uncommitted_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    write(&client, "README.md", "# Project modified locally\n");
    write(&client, "src/staged.py", "S = 1\n");
    git_as(&client, "Client", &["add", "src/staged.py"]);
    write(&client, "scratch.txt", "brouillon\n");
    write(&client, ".gitignore", "*.log\n");
    write(&client, "debug.log", "trace\n");
    remove(&client, "docs/guide.md");

    let r = analyze(&client, &up, &tmp.path().join("out"));
    assert_eq!(r.reference.commit.hash, up.c4);
    let wt = &r.history.as_ref().unwrap().working_tree;
    assert!(wt.available);
    assert!(wt
        .staged
        .iter()
        .any(|e| e.path == "src/staged.py" && e.change == "added"));
    assert!(wt
        .unstaged
        .iter()
        .any(|e| e.path == "README.md" && e.change == "modified"));
    assert!(wt
        .unstaged
        .iter()
        .any(|e| e.path == "docs/guide.md" && e.change == "deleted"));
    assert!(wt.untracked.contains(&"scratch.txt".to_string()));
    assert!(
        wt.ignored.contains(&"debug.log".to_string()),
        "debug.log is ignored by .gitignore: {:?}",
        wt
    );
    // The diff covers the actual content on disk.
    assert_eq!(
        status_of(&r, "README.md").unwrap().status,
        forkscope::diff::ChangeStatus::Modified
    );
    assert_eq!(
        status_of(&r, "docs/guide.md").unwrap().status,
        forkscope::diff::ChangeStatus::Deleted
    );
    assert!(status_of(&r, "scratch.txt").unwrap().untracked);
    for p in ["README.md", "scratch.txt", "docs/guide.md", "src/staged.py"] {
        assert_eq!(status_of(&r, p).unwrap().origin, ChangeOrigin::Uncommitted, "{p}");
    }
    assert_eq!(r.history.unwrap().client_commits_total, 0);
}

/// The fork repository is never modified (files, index or refs).
#[test]
fn client_repository_is_never_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    write(&client, "src/x.py", "X = 1\n");
    commit(&client, "Client", "x");
    write(&client, "README.md", "local\n");
    // trapped hook: must never run
    write(
        &client,
        ".git/hooks/reference-transaction",
        "#!/bin/sh\ntouch \"$GIT_DIR/../PWNED\"\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = client.join(".git/hooks/reference-transaction");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    git_as(
        &client,
        "Client",
        &["config", "core.fsmonitor", "touch FSMONITOR_RAN; false"],
    );
    let before = fingerprint(&client);
    let _ = analyze(&client, &up, &tmp.path().join("out"));
    let after = fingerprint(&client);
    assert_eq!(before, after, "the fork repository was modified");
    assert!(!client.join("PWNED").exists());
    assert!(!client.join("FSMONITOR_RAN").exists());
}

/// Divergent branches and fork-specific tags.
#[test]
fn divergent_branches_and_client_tags() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    git_as(&client, "Client", &["checkout", "-q", "-b", "experimental"]);
    write(&client, "src/exp.py", "E = 1\n");
    commit(&client, "Client", "experiment");
    git_as(&client, "Client", &["tag", "client-1.0"]);
    git_as(&client, "Client", &["checkout", "-q", "main"]);

    let r = analyze(&client, &up, &tmp.path().join("out"));
    let h = r.history.unwrap();
    let exp = h.branches.iter().find(|b| b.name == "experimental").unwrap();
    assert!(exp.divergent);
    assert_eq!(exp.commits_not_in_head, 1);
    assert!(h.tags.iter().any(|t| t.name == "client-1.0" && !t.matches_upstream));
    assert!(h.tags.iter().any(|t| t.name == "v1.0" && t.matches_upstream));
}

/// A file rolled back to an older source version is distinguished from a fork change.
#[test]
fn file_rolled_back_to_older_upstream_version() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.2");
    write(&client, "src/net.py", NET_PY); // v1.0 version: undoes the c4 fix
    write(&client, "src/views.py", &VIEWS_PY.replace("ok()", "done()"));
    commit(&client, "Client", "refactoring");
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let n = status_of(&r, "src/net.py").unwrap();
    assert_eq!(n.origin, ChangeOrigin::UpstreamOlder);
    assert_eq!(n.upstream_commit.as_deref(), Some(up.c1.as_str()));
    assert!(r
        .security
        .findings
        .iter()
        .any(|f| f.rule_id == "ORIGIN-001" && f.file == "src/net.py"));
    assert_eq!(status_of(&r, "src/views.py").unwrap().origin, ChangeOrigin::Client);
    assert_eq!(r.diff.stats.client_changes, 1);
}

/// Timeline: key dates and divergence graph (simple fork).
#[test]
fn timeline_simple_fork() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.1");
    write(&client, "src/a.py", "A = 1\n");
    let a = commit(&client, "Client", "a");
    write(&client, "src/b.py", "B = 1\n");
    let b = commit(&client, "Client", "b");
    write(&client, "notes.txt", "local\n");
    let out = tmp.path().join("out");
    let r = analyze(&client, &up, &out);
    let tl = &r.timeline;
    assert!(!tl.divergence_estimated);
    assert_eq!(tl.divergence.as_ref().unwrap().hash, up.c2);
    assert_eq!(tl.first_fork_commit.as_ref().unwrap().hash, a);
    assert_eq!(tl.last_fork_commit.as_ref().unwrap().hash, b);
    assert_eq!(tl.source_tip.as_ref().unwrap().hash, up.c4);
    assert!(tl.last_disk_change.as_ref().unwrap().path == "notes.txt");
    let g = &tl.graph;
    let div = g.nodes.iter().find(|n| n.divergence).unwrap();
    assert_eq!((div.id.as_str(), div.lane), (up.c2.as_str(), Lane::Source));
    assert!(g
        .edges
        .iter()
        .any(|e| e.kind == EdgeKind::BranchOff && e.from == up.c2 && e.to == a));
    assert!(
        g.nodes.iter().any(|n| n.kind == NodeKind::Worktree),
        "\"uncommitted\" node"
    );
    // chronological order consistent with the edges
    let pos = |id: &str| g.nodes.iter().position(|n| n.id == id).unwrap();
    assert!(pos(&up.c2) < pos(&a) && pos(&a) < pos(&b));
    let svg = std::fs::read_to_string(out.join("divergence-graph.svg")).unwrap();
    assert!(svg.starts_with("<svg") && svg.contains(&up.c2[..10]));
    let md = std::fs::read_to_string(out.join("forkscope-report.md")).unwrap();
    assert!(md.contains("### Key dates") && md.contains("Fork divergence") && md.contains("![Divergence graph"));
    // Terminology: fork / source in the JSON
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("forkscope-report.json")).unwrap()).unwrap();
    assert!(json.get("fork").is_some() && json.get("source").is_some() && json.get("client").is_none());
    assert_eq!(json["history"]["fork_commits_total"], 2);
}

/// Timeline with source integrations (merges): divergence = first starting point.
#[test]
fn timeline_with_merges() {
    let tmp = tempfile::tempdir().unwrap();
    let up = make_upstream(tmp.path());
    let client = clone_at(&up, tmp.path(), "client", "v1.0");
    write(&client, "src/x.py", "X = 1\n");
    commit(&client, "Client", "x");
    git_as(&client, "Client", &["merge", "-q", "--no-edit", "--no-ff", "v1.1"]);
    git_as(&client, "Client", &["merge", "-q", "--no-edit", "--no-ff", &up.c3]);
    let r = analyze(&client, &up, &tmp.path().join("out"));
    let tl = &r.timeline;
    assert_eq!(tl.divergence.as_ref().unwrap().hash, up.c1);
    assert_eq!(tl.reference.as_ref().unwrap().hash, up.c3);
    let merges: Vec<_> = tl.graph.edges.iter().filter(|e| e.kind == EdgeKind::Merge).collect();
    assert_eq!(merges.len(), 2);
    assert!(merges.iter().any(|e| e.from == up.c2) && merges.iter().any(|e| e.from == up.c3));
    let ascii = forkscope::report::graph::ascii(tl);
    assert!(ascii.contains("DIVERGENCE") && ascii.contains("◉"), "{ascii}");
}
