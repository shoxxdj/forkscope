//! Patch IDs (`git patch-id --stable`): identifies equivalent commits
//! regardless of their hash (cherry-pick, rebase, rewrite).

use super::repository::TempRepo;
use crate::utils::short;
use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Computes the patch IDs of the non-merge commits of a revision range.
/// With `reverse`, computes the patch ID of the inverted diff (revert detection).
pub fn patch_ids(repo: &TempRepo, revs: &[String], reverse: bool, max: usize) -> Result<HashMap<String, String>> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "-p".into(),
        "--no-color".into(),
        "--no-ext-diff".into(),
        "--no-textconv".into(),
        "--no-merges".into(),
        "--no-renames".into(),
        "--format=commit %H".into(),
        format!("--max-count={max}"),
    ];
    if reverse {
        // With -R, Git also swaps the a/ b/ prefixes: swap them back to
        // obtain a patch identical to that of a revert commit.
        args.extend(["-R".into(), "--src-prefix=b/".into(), "--dst-prefix=a/".into()]);
    } else {
        args.extend(["--src-prefix=a/".into(), "--dst-prefix=b/".into()]);
    }
    args.extend(revs.iter().cloned());
    let log = repo.run_bytes(&args, None)?;
    if log.is_empty() {
        return Ok(HashMap::new());
    }
    let out = repo.run_bytes(&["patch-id", "--stable"], Some(&log))?;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(p, c)| (c.trim().to_string(), p.to_string())))
        .collect())
}

/// Kind of match between a fork commit and a source commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// Same change as a source commit absent from the fork's ancestry.
    CherryPick,
    /// Same change and same author/date: source commit recreated (rebase, rewrite).
    Rewritten,
    /// Same author/date as a source commit but different content: original commit modified.
    Modified,
    /// The fork commit exactly reverts a source commit.
    Reverted,
}

impl MatchKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::CherryPick => "cherry-pick",
            Self::Rewritten => "rewritten (same content)",
            Self::Modified => "modified",
            Self::Reverted => "reverted",
        }
    }
}

/// Detected match.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PatchMatch {
    pub kind: MatchKind,
    #[serde(rename = "fork_commit")]
    pub client_commit: String,
    #[serde(rename = "source_commit")]
    pub upstream_commit: String,
    #[serde(rename = "fork_subject")]
    pub client_subject: String,
    #[serde(rename = "source_subject")]
    pub upstream_subject: String,
    pub evidence: String,
}

/// Minimal commit metadata for matching.
#[derive(Debug, Clone)]
pub struct MetaKey {
    pub hash: String,
    pub author_email: String,
    pub author_ts: String,
    pub subject: String,
}

/// Metadata of the non-merge commits of a range.
pub fn commit_keys(repo: &TempRepo, revs: &[String], max: usize) -> Result<Vec<MetaKey>> {
    let mut args: Vec<String> = vec![
        "log".into(),
        "--no-merges".into(),
        "--format=%H%x1f%ae%x1f%at%x1f%s".into(),
        format!("--max-count={max}"),
    ];
    args.extend(revs.iter().cloned());
    let out = repo.run(&args)?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\x1f').collect();
            (f.len() >= 4).then(|| MetaKey {
                hash: f[0].into(),
                author_email: f[1].to_ascii_lowercase(),
                author_ts: f[2].into(),
                subject: f[3].into(),
            })
        })
        .collect())
}

/// Matches the fork commits against a window of source commits.
///
/// * `not_in_client`: source commits absent from the fork's ancestry
///   (matches = cherry-picks or rewritten commits).
/// * `in_client`: source commits present in the ancestry (revert search).
pub fn match_commits(
    repo: &TempRepo,
    client_revs: &[String],
    not_in_client: &[String],
    in_client: &[String],
    max_client: usize,
    max_upstream: usize,
) -> Result<Vec<PatchMatch>> {
    let client_keys = commit_keys(repo, client_revs, max_client)?;
    if client_keys.is_empty() {
        return Ok(vec![]);
    }
    let client_pids = patch_ids(repo, client_revs, false, max_client)?;
    let mut by_pid: HashMap<&str, Vec<&MetaKey>> = HashMap::new();
    for k in &client_keys {
        if let Some(p) = client_pids.get(&k.hash) {
            by_pid.entry(p.as_str()).or_default().push(k);
        }
    }
    let client_by_meta: HashMap<(String, String), Vec<&MetaKey>> =
        client_keys.iter().fold(HashMap::new(), |mut m, k| {
            m.entry((k.author_email.clone(), k.author_ts.clone()))
                .or_default()
                .push(k);
            m
        });

    let mut matches: Vec<PatchMatch> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = Default::default();

    if !not_in_client.is_empty() {
        let up_keys = commit_keys(repo, not_in_client, max_upstream)?;
        let up_pids = patch_ids(repo, not_in_client, false, max_upstream)?;
        for u in &up_keys {
            let same_patch: Vec<&MetaKey> = up_pids
                .get(&u.hash)
                .and_then(|p| by_pid.get(p.as_str()))
                .cloned()
                .unwrap_or_default();
            for c in &same_patch {
                if c.hash == u.hash {
                    continue;
                }
                let same_meta = c.author_email == u.author_email && c.author_ts == u.author_ts;
                let kind = if same_meta {
                    MatchKind::Rewritten
                } else {
                    MatchKind::CherryPick
                };
                if seen.insert((c.hash.clone(), u.hash.clone())) {
                    matches.push(PatchMatch {
                        kind,
                        client_commit: c.hash.clone(),
                        upstream_commit: u.hash.clone(),
                        client_subject: c.subject.clone(),
                        upstream_subject: u.subject.clone(),
                        evidence: format!(
                            "identical patch-id{}",
                            if same_meta { " and same author/author date" } else { "" }
                        ),
                    });
                }
            }
            if same_patch.is_empty() {
                if let Some(cs) = client_by_meta.get(&(u.author_email.clone(), u.author_ts.clone())) {
                    for c in cs {
                        if c.hash != u.hash && seen.insert((c.hash.clone(), u.hash.clone())) {
                            matches.push(PatchMatch {
                                kind: MatchKind::Modified,
                                client_commit: c.hash.clone(),
                                upstream_commit: u.hash.clone(),
                                client_subject: c.subject.clone(),
                                upstream_subject: u.subject.clone(),
                                evidence: format!(
                                    "same author and author date as {} but different content",
                                    short(&u.hash)
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    if !in_client.is_empty() {
        let up_keys = commit_keys(repo, in_client, max_upstream)?;
        let rev_pids = patch_ids(repo, in_client, true, max_upstream)?;
        let subj: HashMap<&str, &str> = up_keys.iter().map(|k| (k.hash.as_str(), k.subject.as_str())).collect();
        for (u, pid) in &rev_pids {
            if let Some(cs) = by_pid.get(pid.as_str()) {
                for c in cs {
                    if seen.insert((c.hash.clone(), u.clone())) {
                        matches.push(PatchMatch {
                            kind: MatchKind::Reverted,
                            client_commit: c.hash.clone(),
                            upstream_commit: u.clone(),
                            client_subject: c.subject.clone(),
                            upstream_subject: subj.get(u.as_str()).unwrap_or(&"").to_string(),
                            evidence: "the fork commit's patch-id matches the inverted diff of the source commit"
                                .into(),
                        });
                    }
                }
            }
        }
    }
    matches.sort_by(|a, b| a.client_commit.cmp(&b.client_commit));
    Ok(matches)
}
