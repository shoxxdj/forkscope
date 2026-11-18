//! Analysis of the fork's Git history.

use super::patch_id::{match_commits, PatchMatch};
use super::reference::{display_ref, ReferenceResult, UPSTREAM_REVS};
use super::repository::{ClientLayout, TempRepo};
use crate::analysis::rules::{Category, Severity};
use crate::diff::files::{PathFilter, Snapshot};
use crate::diff::{parse_unified_diff, FileChange};
use crate::utils::short;
use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;

/// Reason why a commit is considered suspicious.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SuspicionReason {
    pub category: Category,
    pub severity: Severity,
    pub detail: String,
}

/// Commit specific to the fork.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CommitInfo {
    pub hash: String,
    pub short: String,
    pub parents: Vec<String>,
    pub author: String,
    pub author_date: String,
    pub committer: String,
    pub committer_date: String,
    pub subject: String,
    pub message: String,
    pub is_merge: bool,
    pub files_changed: usize,
    pub insertions: usize,
    pub deletions: usize,
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suspicious: Vec<SuspicionReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<Severity>,
}

/// Source commit (short form).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CommitLite {
    pub hash: String,
    pub date: String,
    pub subject: String,
}

/// How far the fork is behind a source branch.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BehindInfo {
    pub branch: String,
    pub commits_behind: usize,
}

/// Local branch of the fork.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BranchInfo {
    pub name: String,
    pub commit: String,
    pub is_head: bool,
    /// Commits missing from the source.
    #[serde(rename = "commits_not_in_source")]
    pub commits_not_upstream: usize,
    /// Commits missing from the fork's HEAD.
    pub commits_not_in_head: usize,
    /// Divergent branch: contains specific work not integrated into HEAD.
    pub divergent: bool,
}

/// Fork tag.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TagInfo {
    pub name: String,
    pub commit: String,
    /// The tag exists in the source and points to the same commit.
    #[serde(rename = "matches_source")]
    pub matches_upstream: bool,
}

/// Remote declared in the fork's configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoteInfo {
    pub name: String,
    pub url: String,
}

/// Working tree status entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StatusEntry {
    pub path: String,
    /// added | modified | deleted
    pub change: String,
}

/// Uncommitted changes and untracked files.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct WorkingTreeStatus {
    pub available: bool,
    pub staged: Vec<StatusEntry>,
    pub unstaged: Vec<StatusEntry>,
    pub untracked: Vec<String>,
    /// Untracked files ignored by `.gitignore` (present on disk).
    pub ignored: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl WorkingTreeStatus {
    pub fn is_clean(&self) -> bool {
        self.staged.is_empty() && self.unstaged.is_empty() && self.untracked.is_empty()
    }
}

/// History analysis mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMode {
    /// The fork's history descends from the source.
    Ancestry,
    /// No common commit: rewritten, squashed or imported history.
    Rewritten,
}

/// History analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HistoryAnalysis {
    pub mode: HistoryMode,
    #[serde(rename = "fork_head")]
    pub client_head: String,
    pub head_ref: Option<String>,
    #[serde(rename = "fork_commits_total")]
    pub client_commits_total: usize,
    #[serde(rename = "fork_commits")]
    pub client_commits: Vec<CommitInfo>,
    pub truncated: bool,
    pub merge_commits: usize,
    /// Fork merges that integrated source commits.
    #[serde(rename = "source_merges")]
    pub upstream_merges: Vec<String>,
    /// Source commits present in the fork's history.
    #[serde(rename = "source_commits_in_fork")]
    pub upstream_commits_in_client: usize,
    /// Source commits integrated after the fork's starting point.
    #[serde(rename = "source_integrated_since_fork")]
    pub upstream_integrated_since_fork: usize,
    #[serde(rename = "source_integrated_sample")]
    pub upstream_integrated_sample: Vec<CommitLite>,
    pub behind: Vec<BehindInfo>,
    /// Non-integrated source commits whose message mentions security (hint).
    #[serde(rename = "source_security_hints")]
    pub upstream_security_hints: Vec<CommitLite>,
    pub patch_matches: Vec<PatchMatch>,
    pub rebase_indicators: Vec<String>,
    pub branches: Vec<BranchInfo>,
    pub tags: Vec<TagInfo>,
    pub remotes: Vec<RemoteInfo>,
    pub stash_entries: usize,
    pub working_tree: WorkingTreeStatus,
    pub warnings: Vec<String>,
}

/// Reads the commits of a revision range (metadata and statistics).
pub fn read_commits(repo: &TempRepo, revs: &[String], max: usize) -> Result<Vec<CommitInfo>> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "--format=%x1e%H%x1f%P%x1f%an <%ae>%x1f%aI%x1f%cn <%ce>%x1f%cI%x1f%s%x1f%B".into(),
        format!("--max-count={max}"),
    ];
    args.extend(revs.iter().cloned());
    let meta = repo.run(&args)?;
    let mut commits: Vec<CommitInfo> = Vec::new();
    for rec in meta.split('\x1e') {
        let f: Vec<&str> = rec.splitn(8, '\x1f').collect();
        if f.len() < 8 {
            continue;
        }
        let parents: Vec<String> = f[1].split_whitespace().map(|s| s.to_string()).collect();
        commits.push(CommitInfo {
            hash: f[0].trim().to_string(),
            short: short(f[0].trim()).to_string(),
            is_merge: parents.len() > 1,
            parents,
            author: f[2].into(),
            author_date: f[3].into(),
            committer: f[4].into(),
            committer_date: f[5].into(),
            subject: f[6].into(),
            message: f[7].trim().to_string(),
            files_changed: 0,
            insertions: 0,
            deletions: 0,
            files: vec![],
            suspicious: vec![],
            max_severity: None,
        });
    }
    // Per-file statistics.
    let mut args: Vec<String> = vec![
        "log".into(),
        "--format=%x1e%H".into(),
        "--numstat".into(),
        "--no-renames".into(),
        format!("--max-count={max}"),
    ];
    args.extend(revs.iter().cloned());
    let stats = repo.run(&args)?;
    let mut by_hash: HashMap<String, (usize, usize, Vec<String>)> = HashMap::new();
    for rec in stats.split('\x1e') {
        let mut lines = rec.lines();
        let Some(h) = lines.next() else { continue };
        let entry = by_hash.entry(h.trim().to_string()).or_default();
        for l in lines {
            let f: Vec<&str> = l.splitn(3, '\t').collect();
            if f.len() == 3 {
                entry.0 += f[0].parse::<usize>().unwrap_or(0);
                entry.1 += f[1].parse::<usize>().unwrap_or(0);
                entry.2.push(f[2].to_string());
            }
        }
    }
    for c in &mut commits {
        if let Some((a, d, files)) = by_hash.remove(&c.hash) {
            c.insertions = a;
            c.deletions = d;
            c.files_changed = files.len();
            c.files = files;
        }
    }
    Ok(commits)
}

/// Patches (diffs) of the non-merge commits of a range, parsed into `FileChange`s.
pub fn commit_patches(repo: &TempRepo, revs: &[String], max: usize) -> Result<Vec<(String, Vec<FileChange>)>> {
    const MARK: &str = "\x1eFORKSCOPE-COMMIT ";
    let mut args: Vec<String> = vec![
        "log".into(),
        "-p".into(),
        "-U3".into(),
        "--no-merges".into(),
        "--no-color".into(),
        "--no-ext-diff".into(),
        "--no-textconv".into(),
        "--no-renames".into(),
        "--src-prefix=a/".into(),
        "--dst-prefix=b/".into(),
        format!("--format={}%H", MARK.replace('\x1e', "%x1e")),
        format!("--max-count={max}"),
    ];
    args.extend(revs.iter().cloned());
    let out = repo.run(&args)?;
    let mut res = Vec::new();
    for chunk in out.split(MARK).skip(1) {
        let (hash, patch) = chunk.split_once('\n').unwrap_or((chunk, ""));
        res.push((hash.trim().to_string(), parse_unified_diff(patch)));
    }
    Ok(res)
}

/// Revisions designating the fork-specific commits.
pub fn client_specific_revs(head: &str, mode: HistoryMode) -> Vec<String> {
    match mode {
        HistoryMode::Ancestry => vec![
            head.into(),
            "--not".into(),
            UPSTREAM_REVS[0].into(),
            UPSTREAM_REVS[1].into(),
        ],
        HistoryMode::Rewritten => vec![head.into()],
    }
}

/// History analysis parameters.
pub struct HistoryParams<'a> {
    pub layout: &'a ClientLayout,
    pub head: &'a str,
    pub mode: HistoryMode,
    pub reference: &'a ReferenceResult,
    pub preferred_branch: Option<&'a str>,
    pub worktree: &'a Snapshot,
    pub filter: &'a PathFilter,
    pub cfg: &'a crate::config::HistoryConfig,
}

/// Full analysis of the fork's history.
pub fn analyze_history(repo: &TempRepo, p: &HistoryParams) -> Result<HistoryAnalysis> {
    let mut warnings = Vec::new();
    let revs = client_specific_revs(p.head, p.mode);
    let rev_refs: Vec<&str> = revs.iter().map(|s| s.as_str()).collect();
    let total = repo.count(&rev_refs)?;
    let commits = read_commits(repo, &revs, p.cfg.max_client_commits)?;
    let truncated = total > commits.len();
    if truncated {
        warnings.push(format!(
            "{} fork commits detailed out of {total} (history.max_client_commits)",
            commits.len()
        ));
    }
    let specific: HashSet<&str> = commits.iter().map(|c| c.hash.as_str()).collect();
    let merge_commits = commits.iter().filter(|c| c.is_merge).count();
    let upstream_merges: Vec<String> = if p.mode == HistoryMode::Ancestry {
        commits
            .iter()
            .filter(|c| c.is_merge && c.parents.iter().skip(1).any(|pp| !specific.contains(pp.as_str())))
            .map(|c| c.hash.clone())
            .collect()
    } else {
        vec![]
    };

    let base = p.reference.commit.hash.clone();
    let (upstream_in_client, integrated, integrated_sample) = if p.mode == HistoryMode::Ancestry {
        let in_client = repo.count(&[&base])?;
        let (n, sample) = match &p.reference.fork_point {
            Some(f) if f.hash != base => {
                let range = format!("{}..{}", f.hash, base);
                let n = repo.count(&[&range])?;
                (n, lite_log(repo, &[range], 30)?)
            }
            _ => (0, vec![]),
        };
        (in_client, n, sample)
    } else {
        (0, 0, vec![])
    };

    // Lag behind the source branches.
    let mut behind = Vec::new();
    let mut branches_to_check: Vec<String> = Vec::new();
    if let Some(b) = p.preferred_branch {
        branches_to_check.push(b.to_string());
    }
    for b in &p.reference.location.containing_branches {
        if let Some(name) = b.strip_prefix("branch:") {
            if !branches_to_check.iter().any(|x| x == name) {
                branches_to_check.push(name.to_string());
            }
        }
    }
    branches_to_check.truncate(10);
    let mut hints = Vec::new();
    for b in &branches_to_check {
        let r = format!("refs/upstream/heads/{b}");
        if repo.resolve_commit(&r)?.is_none() {
            continue;
        }
        let range = format!("{base}..{r}");
        let n = repo.count(&[&range])?;
        behind.push(BehindInfo {
            branch: b.clone(),
            commits_behind: n,
        });
        if hints.is_empty() && n > 0 {
            hints = security_hints(repo, &range)?;
        }
    }

    // Patch-id matches.
    let (not_in_client, in_client): (Vec<String>, Vec<String>) = match p.mode {
        HistoryMode::Ancestry => (
            vec![
                UPSTREAM_REVS[0].into(),
                UPSTREAM_REVS[1].into(),
                "--not".into(),
                p.head.into(),
            ],
            vec![base.clone()],
        ),
        HistoryMode::Rewritten => (
            vec![UPSTREAM_REVS[0].into(), UPSTREAM_REVS[1].into()],
            vec![base.clone()],
        ),
    };
    let patch_matches = match match_commits(
        repo,
        &revs,
        &not_in_client,
        &in_client,
        p.cfg.max_client_commits,
        p.cfg.max_upstream_patch_ids,
    ) {
        Ok(m) => m,
        Err(e) => {
            warnings.push(format!("cannot compute patch-ids: {e}"));
            vec![]
        }
    };

    let rebase_indicators = rebase_indicators(p.layout, &commits, &patch_matches);
    let branches = client_branches(repo, p.head, p.layout)?;
    let tags = client_tags(repo)?;
    let remotes = p
        .layout
        .remotes
        .iter()
        .map(|(n, u)| RemoteInfo {
            name: n.clone(),
            url: u.clone(),
        })
        .collect();
    let stash_entries = p
        .layout
        .common_dir
        .as_ref()
        .and_then(|c| std::fs::read_to_string(c.join("logs/refs/stash")).ok())
        .map(|s| s.lines().count())
        .unwrap_or_else(|| usize::from(repo.resolve_commit("refs/client/stash").ok().flatten().is_some()));
    let working_tree = working_tree_status(repo, p.layout, p.head, p.worktree, p.filter);
    if let Some(gd) = &p.layout.git_dir {
        for (f, label) in [
            ("MERGE_HEAD", "merge"),
            ("CHERRY_PICK_HEAD", "cherry-pick"),
            ("REVERT_HEAD", "revert"),
            ("rebase-merge", "rebase"),
            ("rebase-apply", "rebase / am"),
            ("BISECT_LOG", "bisect"),
        ] {
            if gd.join(f).exists() {
                warnings.push(format!(
                    "Git operation in progress in the fork repository: {label} ({f}) — the working tree may contain uncommitted source changes or conflicts"
                ));
            }
        }
    }

    Ok(HistoryAnalysis {
        mode: p.mode,
        client_head: p.head.to_string(),
        head_ref: p.layout.head_ref.clone(),
        client_commits_total: total,
        client_commits: commits,
        truncated,
        merge_commits,
        upstream_merges,
        upstream_commits_in_client: upstream_in_client,
        upstream_integrated_since_fork: integrated,
        upstream_integrated_sample: integrated_sample,
        behind,
        upstream_security_hints: hints,
        patch_matches,
        rebase_indicators,
        branches,
        tags,
        remotes,
        stash_entries,
        working_tree,
        warnings,
    })
}

fn lite_log(repo: &TempRepo, revs: &[String], max: usize) -> Result<Vec<CommitLite>> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "--format=%H%x1f%cI%x1f%s".into(),
        format!("--max-count={max}"),
    ];
    args.extend(revs.iter().cloned());
    Ok(repo
        .run(&args)?
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.splitn(3, '\x1f').collect();
            (f.len() == 3).then(|| CommitLite {
                hash: f[0].into(),
                date: f[1].into(),
                subject: f[2].into(),
            })
        })
        .collect())
}

/// Non-integrated source commits whose message mentions a security fix.
/// Just a hint: commit messages are not reliable.
fn security_hints(repo: &TempRepo, range: &str) -> Result<Vec<CommitLite>> {
    let re = regex::Regex::new(
        r"(?i)\b(security|sécurité|cve-\d{4}-\d+|vuln|xss|csrf|ssrf|injection|rce|auth[a-z]*|sanitiz|escape|overflow|privilege|bypass|traversal|ghsa-)",
    )?;
    Ok(lite_log(repo, &[range.to_string()], 3000)?
        .into_iter()
        .filter(|c| re.is_match(&c.subject))
        .take(30)
        .collect())
}

fn rebase_indicators(layout: &ClientLayout, commits: &[CommitInfo], matches: &[PatchMatch]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(gd) = &layout.git_dir {
        let text = std::fs::read_to_string(gd.join("logs/HEAD")).unwrap_or_default();
        let count = |pat: &str| text.lines().filter(|l| l.contains(pat)).count();
        let (rb, cp, amend, reset) = (
            count("rebase"),
            count("cherry-pick"),
            count("commit (amend)"),
            count("reset:"),
        );
        if rb > 0 {
            out.push(format!("HEAD reflog: {rb} rebase entry(ies)"));
        }
        if cp > 0 {
            out.push(format!("HEAD reflog: {cp} cherry-pick entry(ies)"));
        }
        if amend > 0 {
            out.push(format!("HEAD reflog: {amend} amended commit(s)"));
        }
        if reset > 0 {
            out.push(format!("HEAD reflog: {reset} reset(s)"));
        }
    }
    let gap = commits
        .iter()
        .filter(|c| {
            let a = chrono::DateTime::parse_from_rfc3339(&c.author_date);
            let d = chrono::DateTime::parse_from_rfc3339(&c.committer_date);
            matches!((a, d), (Ok(a), Ok(d)) if (d - a).num_hours() > 24)
        })
        .count();
    if gap > 0 {
        out.push(format!(
            "{gap} commit(s) whose commit date is more than 24 h after the author date (likely rebase, cherry-pick or amend)"
        ));
    }
    let rewritten = matches
        .iter()
        .filter(|m| m.kind == super::patch_id::MatchKind::Rewritten)
        .count();
    if rewritten > 0 {
        out.push(format!(
            "{rewritten} source commit(s) recreated identically with a new hash"
        ));
    }
    out
}

fn client_branches(repo: &TempRepo, head: &str, layout: &ClientLayout) -> Result<Vec<BranchInfo>> {
    let mut out = Vec::new();
    let head_branch = layout.head_ref.as_deref().and_then(|r| r.strip_prefix("refs/heads/"));
    for r in repo.refs(&["refs/client/heads"])? {
        let name = r.name.trim_start_matches("refs/client/heads/").to_string();
        let not_upstream = repo.count(&[&r.commit, "--not", UPSTREAM_REVS[0], UPSTREAM_REVS[1]])?;
        let not_in_head = repo.count(&[&r.commit, "--not", head])?;
        out.push(BranchInfo {
            is_head: head_branch == Some(name.as_str()),
            divergent: not_in_head > 0
                && repo.count(&[&r.commit, "--not", head, UPSTREAM_REVS[0], UPSTREAM_REVS[1]])? > 0,
            name,
            commit: r.commit,
            commits_not_upstream: not_upstream,
            commits_not_in_head: not_in_head,
        });
    }
    Ok(out)
}

fn client_tags(repo: &TempRepo) -> Result<Vec<TagInfo>> {
    let upstream: HashMap<String, String> = repo
        .refs(&["refs/tags"])?
        .into_iter()
        .map(|r| (r.name.trim_start_matches("refs/tags/").to_string(), r.commit))
        .collect();
    Ok(repo
        .refs(&["refs/client/tags"])?
        .into_iter()
        .map(|r| {
            let name = r.name.trim_start_matches("refs/client/tags/").to_string();
            TagInfo {
                matches_upstream: upstream.get(&name) == Some(&r.commit),
                name,
                commit: r.commit,
            }
        })
        .collect())
}

/// Working tree status, computed without running Git in the fork repository:
/// HEAD (imported) vs index (read via `GIT_INDEX_FILE`) vs files on disk.
pub fn working_tree_status(
    repo: &TempRepo,
    layout: &ClientLayout,
    head: &str,
    worktree: &Snapshot,
    filter: &PathFilter,
) -> WorkingTreeStatus {
    let mut st = WorkingTreeStatus::default();
    let Some(gd) = &layout.git_dir else { return st };
    let index_path = gd.join("index");
    let head_tree: HashMap<String, String> = match repo.ls_tree(head) {
        Ok(e) => e
            .into_iter()
            .filter(|e| filter.is_file_included(&e.path) && e.kind == "blob")
            .map(|e| (e.path, e.oid))
            .collect(),
        Err(_) => return st,
    };
    let index: HashMap<String, String> = if index_path.is_file() {
        match repo.run_env(
            &["ls-files", "-s", "-z"],
            None,
            &[("GIT_INDEX_FILE", index_path.as_os_str())],
        ) {
            Ok(out) => out
                .split(|&b| b == 0)
                .filter(|r| !r.is_empty())
                .filter_map(|r| {
                    let r = String::from_utf8_lossy(r);
                    let (meta, path) = r.split_once('\t')?;
                    let f: Vec<&str> = meta.split_whitespace().collect();
                    (f.len() == 3 && f[0] != "160000" && filter.is_file_included(path))
                        .then(|| (path.to_string(), f[1].to_string()))
                })
                .collect(),
            Err(e) => {
                st.note = Some(format!("unreadable Git index ({e}): HEAD / disk comparison only"));
                head_tree.clone()
            }
        }
    } else {
        st.note = Some("no Git index: HEAD / disk comparison only".into());
        head_tree.clone()
    };
    st.available = true;
    for (p, oid) in &index {
        match head_tree.get(p) {
            None => st.staged.push(StatusEntry {
                path: p.clone(),
                change: "added".into(),
            }),
            Some(h) if h != oid => st.staged.push(StatusEntry {
                path: p.clone(),
                change: "modified".into(),
            }),
            _ => {}
        }
    }
    for p in head_tree.keys() {
        if !index.contains_key(p) {
            st.staged.push(StatusEntry {
                path: p.clone(),
                change: "deleted".into(),
            });
        }
    }
    for (p, oid) in &index {
        match worktree.entries.get(p) {
            None => st.unstaged.push(StatusEntry {
                path: p.clone(),
                change: "deleted".into(),
            }),
            Some(e) if &e.oid != oid && e.kind != crate::diff::files::EntryKind::Submodule => {
                st.unstaged.push(StatusEntry {
                    path: p.clone(),
                    change: "modified".into(),
                })
            }
            _ => {}
        }
    }
    let untracked: Vec<String> = worktree
        .files()
        .filter(|e| !index.contains_key(&e.path))
        .map(|e| e.path.clone())
        .collect();
    // Ignored files: check-ignore only reads the .gitignore files (data).
    let ignored: HashSet<String> = if untracked.is_empty() {
        HashSet::new()
    } else {
        let input: Vec<u8> = untracked
            .iter()
            .flat_map(|p| p.bytes().chain(std::iter::once(0)))
            .collect();
        let mut cmd = repo.command();
        cmd.arg("--work-tree")
            .arg(&layout.root)
            .args(["check-ignore", "--no-index", "--stdin", "-z"]);
        match super::repository::exec(cmd, Some(&input)) {
            Ok(out) => out
                .stdout
                .split(|&b| b == 0)
                .filter(|r| !r.is_empty())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .collect(),
            Err(_) => HashSet::new(),
        }
    };
    for p in untracked {
        if ignored.contains(&p) {
            st.ignored.push(p);
        } else {
            st.untracked.push(p);
        }
    }
    st.staged.sort_by(|a, b| a.path.cmp(&b.path));
    st.unstaged.sort_by(|a, b| a.path.cmp(&b.path));
    st.untracked.sort();
    st.ignored.sort();
    let _ = OsStr::new("");
    st
}

/// For each file, the fork commits that modified it.
pub fn commits_by_path(commits: &[CommitInfo]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for c in commits {
        for f in &c.files {
            map.entry(f.clone()).or_default().push(c.hash.clone());
        }
    }
    map
}

/// Readable form of an internal reference (convenience re-export).
pub fn pretty_ref(r: &str) -> String {
    display_ref(r)
}
