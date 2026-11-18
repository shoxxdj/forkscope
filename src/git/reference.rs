//! Identification of the source reference commit.
//!
//! Two strategies:
//! * **Git ancestry** (usable fork history): the base commit is
//!   determined by the ancestry relations between the fork's HEAD and the
//!   source references (`rev-list --boundary`, `merge-base --independent`).
//!   The result is exact.
//! * **Content estimation** (no history, or rewritten history):
//!   every candidate commit is scored by comparing file fingerprints
//!   (Git blob IDs), then the best candidates are refined by content
//!   similarity. The result is **always presented as an
//!   estimate**, with a confidence score and the reasons behind it.

use super::repository::{CommitMeta, TempRepo, TreeEntry};
use crate::config::ReferenceConfig;
use crate::diff::files::{ContentProvider, EntryKind, GitContent, PathFilter, Snapshot, SnapshotEntry};
use crate::diff::similarity::similarity;
use crate::utils::{basename, dirname, is_binary, short, to_normalized_text};
use anyhow::{bail, Result};
use rayon::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Identification method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceMethod {
    GitAncestry,
    SnapshotEstimation,
}

/// Certainty level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    /// Ancestry relation verified by Git.
    Exact,
    /// Statistical estimate: never treat it as certain.
    Estimated,
}

/// Commit summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CommitSummary {
    pub hash: String,
    pub short: String,
    pub author: String,
    pub author_date: String,
    pub committer_date: String,
    pub subject: String,
}

impl From<CommitMeta> for CommitSummary {
    fn from(m: CommitMeta) -> Self {
        Self {
            short: short(&m.hash).to_string(),
            hash: m.hash,
            author: format!("{} <{}>", m.author_name, m.author_email),
            author_date: m.author_date,
            committer_date: m.committer_date,
            subject: m.subject,
        }
    }
}

/// Position of the commit in the source (branches, tags).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct RefLocation {
    /// Branches/tags pointing exactly at this commit.
    pub pointing_refs: Vec<String>,
    /// Source branches containing this commit.
    pub containing_branches: Vec<String>,
    /// `git describe --tags` (closest previous tag).
    pub describe: Option<String>,
    /// First tag containing this commit (`git describe --contains`).
    pub first_tag_containing: Option<String>,
}

/// Score of a candidate commit (estimation).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Candidate {
    pub commit: String,
    pub refs: Vec<String>,
    pub score: f64,
    pub identical: usize,
    pub modified: usize,
    pub added: usize,
    pub deleted: usize,
    pub moved: usize,
    pub manifests_identical: usize,
    pub manifests_total: usize,
    /// Average similarity of the modified files (fine phase).
    pub content_similarity: Option<f64>,
    /// Structure similarity (directories).
    pub structure_similarity: Option<f64>,
    /// Internal weights: identical, modified, added, deleted (excluding moved), moved.
    #[serde(skip)]
    #[schemars(skip)]
    weights: [f64; 5],
}

/// Identification result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReferenceResult {
    pub method: ReferenceMethod,
    pub certainty: Certainty,
    pub commit: CommitSummary,
    pub location: RefLocation,
    /// Confidence (0-100).
    pub confidence: f64,
    pub confidence_level: String,
    pub reasons: Vec<String>,
    /// Initial starting point of the fork (first attached source commit).
    pub fork_point: Option<CommitSummary>,
    /// Estimate of the initial starting point (rewritten history: tree of the fork's first commit).
    pub estimated_initial_base: Option<Box<ReferenceResult>>,
    pub candidates: Vec<Candidate>,
    /// Other commits indistinguishable from the selected commit.
    pub equivalent_commits: Vec<String>,
    pub commits_scored: usize,
    pub warnings: Vec<String>,
}

/// Files whose identity is a strong version signal.
pub fn is_version_signal_file(path: &str) -> bool {
    let name = basename(path).to_ascii_lowercase();
    crate::analysis::dependencies::ecosystem_for(path).is_some()
        || name.starts_with("changelog")
        || name.starts_with("history.")
        || name.starts_with("news")
        || name.starts_with("release")
        || name == "version"
        || name == "version.txt"
        || name == "setup.py"
        || name == "setup.cfg"
        || name.ends_with(".csproj")
        || name == "package.swift"
        || name == "mix.exs"
}

/// Locates a commit in the source.
pub fn locate(repo: &TempRepo, commit: &str) -> Result<RefLocation> {
    let pointing = repo
        .run(&[
            "for-each-ref",
            "--points-at",
            commit,
            "--format=%(refname)",
            "refs/upstream/heads",
            "refs/tags",
        ])?
        .lines()
        .map(display_ref)
        .collect();
    let containing = repo
        .run(&[
            "for-each-ref",
            "--contains",
            commit,
            "--format=%(refname)",
            "refs/upstream/heads",
        ])?
        .lines()
        .map(display_ref)
        .collect();
    let describe = repo
        .try_run(&["describe", "--tags", commit])?
        .map(|s| s.trim().to_string());
    let contains = repo
        .try_run(&["describe", "--tags", "--contains", commit])?
        .map(|s| s.trim().to_string());
    Ok(RefLocation {
        pointing_refs: pointing,
        containing_branches: containing,
        describe,
        first_tag_containing: contains,
    })
}

/// Readable name of an internal reference.
pub fn display_ref(r: &str) -> String {
    if let Some(b) = r.strip_prefix("refs/upstream/heads/") {
        format!("branch:{b}")
    } else if let Some(t) = r.strip_prefix("refs/tags/") {
        format!("tag:{t}")
    } else {
        r.to_string()
    }
}

/// Git selectors of the source references.
pub const UPSTREAM_REVS: [&str; 2] = ["--glob=refs/upstream/*", "--tags"];

/// Identification by Git ancestry. Returns `None` if the fork's HEAD shares
/// no commit with the source (rewritten / imported history).
pub fn identify_by_ancestry(
    repo: &TempRepo,
    client_head: &str,
    preferred_branch: Option<&str>,
) -> Result<Option<ReferenceResult>> {
    let mut warnings = Vec::new();
    let out = repo.run(&[
        "rev-list",
        "--boundary",
        client_head,
        "--not",
        UPSTREAM_REVS[0],
        UPSTREAM_REVS[1],
    ])?;
    let mut specific = 0usize;
    let mut boundary: Vec<String> = Vec::new();
    for line in out.lines() {
        if let Some(b) = line.strip_prefix('-') {
            boundary.push(b.trim().to_string());
        } else if !line.trim().is_empty() {
            specific += 1;
        }
    }
    boundary.sort();
    boundary.dedup();

    let (base, fork) = if specific == 0 {
        // Fork HEAD = source commit (no specific commit).
        (client_head.to_string(), client_head.to_string())
    } else if boundary.is_empty() {
        return Ok(None);
    } else {
        let mut args = vec!["merge-base", "--independent"];
        args.extend(boundary.iter().map(|s| s.as_str()));
        let maximal: Vec<String> = repo
            .run(&args)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let base = choose_most_relevant(repo, &maximal, preferred_branch, &mut warnings)?;
        // Starting point: topologically oldest boundary commit
        // (fewest ancestors), then by date.
        let mut oldest: Option<((usize, i64), String)> = None;
        for b in &boundary {
            let ts: i64 = repo
                .run(&["show", "-s", "--format=%ct", b])?
                .trim()
                .parse()
                .unwrap_or(0);
            let key = (repo.count(&[b])?, ts);
            if oldest.as_ref().map(|(t, _)| key < *t).unwrap_or(true) {
                oldest = Some((key, b.clone()));
            }
        }
        (base, oldest.map(|(_, h)| h).unwrap_or_default())
    };

    let commit: CommitSummary = repo.commit_meta(&base)?.into();
    let location = locate(repo, &base)?;
    let mut reasons = vec![format!(
        "The fork's HEAD descends directly from source commit {} (ancestry verified by Git: cryptographic commit IDs).",
        short(&base)
    )];
    if specific > 0 {
        reasons.push(format!(
            "{specific} commit(s) present in the fork and absent from the source."
        ));
    } else {
        reasons.push("The fork's HEAD is itself a source commit: no specific commit.".to_string());
    }
    if fork != base && !fork.is_empty() {
        reasons.push(format!(
            "The fork started from {} and then integrated newer source commits up to {}.",
            short(&fork),
            short(&base)
        ));
    }
    if location.pointing_refs.is_empty() {
        reasons.push("No source branch or tag points exactly at this commit (intermediate commit).".to_string());
    }
    let fork_point = if fork.is_empty() {
        None
    } else {
        Some(repo.commit_meta(&fork)?.into())
    };
    Ok(Some(ReferenceResult {
        method: ReferenceMethod::GitAncestry,
        certainty: Certainty::Exact,
        commit,
        location,
        confidence: 100.0,
        confidence_level: "certain (Git ancestry)".to_string(),
        reasons,
        fork_point,
        estimated_initial_base: None,
        candidates: vec![],
        equivalent_commits: vec![],
        commits_scored: 0,
        warnings,
    }))
}

/// Among several independent bases, picks the most relevant one.
fn choose_most_relevant(
    repo: &TempRepo,
    commits: &[String],
    preferred_branch: Option<&str>,
    warnings: &mut Vec<String>,
) -> Result<String> {
    if commits.is_empty() {
        bail!("no common base found");
    }
    if commits.len() == 1 {
        return Ok(commits[0].clone());
    }
    warnings.push(format!(
        "several independent source bases ({}): the fork integrates divergent source branches",
        commits
            .iter()
            .map(|c| short(c).to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(b) = preferred_branch {
        let r = format!("refs/upstream/heads/{b}");
        for c in commits {
            if repo.is_ancestor(c, &r)? {
                return Ok(c.clone());
            }
        }
    }
    let mut best = (0i64, commits[0].clone());
    for c in commits {
        let ts: i64 = repo
            .run(&["show", "-s", "--format=%ct", c])?
            .trim()
            .parse()
            .unwrap_or(0);
        if ts > best.0 {
            best = (ts, c.clone());
        }
    }
    Ok(best.1)
}

/// Index of the fork files for the quick score.
struct ClientIndex<'a> {
    snapshot: &'a Snapshot,
    by_path: HashMap<&'a str, &'a str>,
    dirs: HashSet<String>,
}

impl<'a> ClientIndex<'a> {
    fn new(snapshot: &'a Snapshot) -> Self {
        let by_path: HashMap<&str, &str> = snapshot.files().map(|e| (e.path.as_str(), e.oid.as_str())).collect();
        let dirs = by_path.keys().map(|p| dirname(p).to_string()).collect();
        Self {
            snapshot,
            by_path,
            dirs,
        }
    }
}

/// Quick score of a tree (fingerprints only).
fn quick_score(client: &ClientIndex, tree: &[TreeEntry], filter: &PathFilter, mw: f64) -> Candidate {
    let w = |p: &str| if is_version_signal_file(p) { mw } else { 1.0 };
    let reference: HashMap<&str, &str> = tree
        .iter()
        .filter(|e| e.kind == "blob" && filter.is_file_included(&e.path))
        .map(|e| (e.path.as_str(), e.oid.as_str()))
        .collect();
    let mut c = Candidate::default();
    let (mut wi, mut wm, mut wa, mut wd, mut wmv) = (0.0, 0.0, 0.0, 0.0, 0.0);
    let mut deleted_oids: HashSet<&str> = HashSet::new();
    for (p, oid) in &reference {
        match client.by_path.get(p) {
            Some(co) if co == oid => {
                c.identical += 1;
                wi += w(p);
                if is_version_signal_file(p) {
                    c.manifests_identical += 1;
                    c.manifests_total += 1;
                }
            }
            Some(_) => {
                c.modified += 1;
                wm += w(p);
                if is_version_signal_file(p) {
                    c.manifests_total += 1;
                }
            }
            None => {
                deleted_oids.insert(oid);
                c.deleted += 1;
                wd += w(p);
            }
        }
    }
    for (p, oid) in &client.by_path {
        if !reference.contains_key(p) {
            if deleted_oids.contains(oid) {
                c.moved += 1;
                wmv += 1.0;
            } else {
                c.added += 1;
                wa += w(p);
            }
        }
    }
    // A move counts as a paired addition + deletion.
    let wd_eff = (wd - wmv).max(0.0);
    let denom = wi + wm + wa + wd_eff + wmv;
    c.score = if denom > 0.0 {
        (wi + 0.9 * wmv + 0.5 * wm) / denom
    } else {
        0.0
    };
    c.weights = [wi, wm, wa, wd_eff, wmv];
    c
}

/// Fine score: content similarity of modified files and structure similarity.
fn fine_score(
    repo: &TempRepo,
    client: &ClientIndex,
    client_src: &dyn ContentProvider,
    tree: &[TreeEntry],
    filter: &PathFilter,
    mw: f64,
    base: &Candidate,
) -> Result<Candidate> {
    let w = |p: &str| if is_version_signal_file(p) { mw } else { 1.0 };
    let reference: Vec<&TreeEntry> = tree
        .iter()
        .filter(|e| e.kind == "blob" && filter.is_file_included(&e.path))
        .collect();
    let modified: Vec<(&TreeEntry, &SnapshotEntry)> = reference
        .iter()
        .filter_map(|e| {
            let ce = client.snapshot.entries.get(&e.path)?;
            (ce.oid != e.oid && ce.kind != EntryKind::Submodule).then_some((*e, ce))
        })
        .take(800)
        .collect();
    let ref_oids: Vec<String> = modified.iter().map(|(e, _)| e.oid.clone()).collect();
    let ref_blobs = repo.read_blobs(&ref_oids)?;
    let client_entries: Vec<&SnapshotEntry> = modified.iter().map(|(_, c)| *c).collect();
    let client_blobs = client_src.load(&client_entries)?;
    let sims: Vec<(f64, f64)> = modified
        .par_iter()
        .map(|(e, c)| {
            let weight = w(&e.path);
            let (Some(a), Some(b)) = (ref_blobs.get(&e.oid), client_blobs.get(&c.path)) else {
                return (weight, 0.0);
            };
            if is_binary(a) || is_binary(b) || a.len() > 1_000_000 || b.len() > 1_000_000 {
                return (weight, 0.0);
            }
            (weight, similarity(&to_normalized_text(a), &to_normalized_text(b)))
        })
        .collect();
    let mut cand = base.clone();
    let wm_sim: f64 = sims.iter().map(|(w, s)| w * s).sum();
    let wm: f64 = sims.iter().map(|(w, _)| w).sum();
    cand.content_similarity = if sims.is_empty() { None } else { Some(wm_sim / wm) };

    let ref_dirs: HashSet<String> = reference.iter().map(|e| dirname(&e.path).to_string()).collect();
    let inter = ref_dirs.intersection(&client.dirs).count() as f64;
    let union = ref_dirs.union(&client.dirs).count() as f64;
    let structure = if union > 0.0 { inter / union } else { 1.0 };
    cand.structure_similarity = Some(structure);

    // Score recomputation: the actual similarity replaces the flat 0.5 value
    // for the evaluated modified files.
    let [wi, wm_all, wa, wd, wmv] = base.weights;
    let denom = wi + wm_all + wa + wd + wmv;
    let numer = wi + 0.9 * wmv + wm_sim + 0.5 * (wm_all - wm).max(0.0);
    let content = if denom > 0.0 { numer / denom } else { 0.0 };
    cand.score = 0.9 * content + 0.1 * structure;
    Ok(cand)
}

/// Estimates the most likely source commit for a fork snapshot.
pub fn estimate_reference(
    repo: &TempRepo,
    client: &Snapshot,
    client_src: &dyn ContentProvider,
    filter: &PathFilter,
    cfg: &ReferenceConfig,
    preferred_branch: Option<&str>,
    progress: &(dyn Fn(String) + Sync),
) -> Result<ReferenceResult> {
    let mut warnings = Vec::new();
    if client.files().count() == 0 {
        bail!("the fork contains no comparable file (check the exclusions)");
    }
    let index = ClientIndex::new(client);

    // Named references (branches/tags) per commit.
    let mut refs_by_commit: HashMap<String, Vec<String>> = HashMap::new();
    for r in repo.refs(&["refs/upstream/heads", "refs/tags"])? {
        refs_by_commit.entry(r.commit).or_default().push(display_ref(&r.name));
    }

    // Commit list (reverse chronological order) with their tree.
    let log = repo.run(&[
        "log",
        "--format=%H %T",
        "--date-order",
        &format!("--max-count={}", cfg.max_commits),
        UPSTREAM_REVS[0],
        UPSTREAM_REVS[1],
    ])?;
    let mut commits: Vec<(String, String)> = log
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(c, t)| (c.to_string(), t.to_string())))
        .collect();
    let total_upstream = repo.count(&UPSTREAM_REVS)?;
    if total_upstream > commits.len() {
        warnings.push(format!(
            "only the {} most recent source commits were walked out of {} (reference.max_commits)",
            commits.len(),
            total_upstream
        ));
    }
    // Add commits pointed to by tags/branches outside the window.
    let known: HashSet<String> = commits.iter().map(|(c, _)| c.clone()).collect();
    for c in refs_by_commit.keys() {
        if !known.contains(c) {
            if let Some(t) = repo.try_run(&["rev-parse", &format!("{c}^{{tree}}")])? {
                commits.push((c.clone(), t.trim().to_string()));
            }
        }
    }
    if commits.is_empty() {
        bail!("no source commit to compare");
    }

    // Score cache per tree.
    let mut tree_scores: HashMap<String, Candidate> = HashMap::new();
    let score_trees = |trees: Vec<String>, tree_scores: &mut HashMap<String, Candidate>| -> Result<()> {
        let todo: Vec<String> = trees
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|t| !tree_scores.contains_key(t))
            .collect();
        let results: Vec<Result<(String, Candidate)>> = todo
            .par_iter()
            .map(|t| {
                let entries = repo.ls_tree(t)?;
                Ok((t.clone(), quick_score(&index, &entries, filter, cfg.manifest_weight)))
            })
            .collect();
        for r in results {
            let (t, c) = r?;
            tree_scores.insert(t, c);
        }
        Ok(())
    };

    let n = commits.len();
    let exhaustive = n <= cfg.exhaustive_threshold;
    if exhaustive {
        progress(format!("exhaustive evaluation of {n} commits"));
        score_trees(commits.iter().map(|(_, t)| t.clone()).collect(), &mut tree_scores)?;
    } else {
        let step = (n / cfg.coarse_samples.max(1)).max(1);
        progress(format!("coarse phase: 1 commit out of {step} among {n}"));
        let mut sample: Vec<String> = commits.iter().step_by(step).map(|(_, t)| t.clone()).collect();
        sample.extend(
            commits
                .iter()
                .filter(|(c, _)| refs_by_commit.contains_key(c))
                .map(|(_, t)| t.clone()),
        );
        score_trees(sample, &mut tree_scores)?;
        // Best positions -> refine around them.
        let mut positions: Vec<(usize, f64)> = commits
            .iter()
            .enumerate()
            .filter_map(|(i, (_, t))| tree_scores.get(t).map(|c| (i, c.score)))
            .collect();
        positions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let mut refine: Vec<String> = Vec::new();
        for (pos, _) in positions.iter().take(cfg.top_candidates.max(3)) {
            let lo = pos.saturating_sub(step);
            let hi = (pos + step + 1).min(n);
            refine.extend(commits[lo..hi].iter().map(|(_, t)| t.clone()));
            // Direct (first-parent) ancestors of the candidate.
            let anc = repo.run(&[
                "log",
                "--first-parent",
                "--format=%T",
                &format!("--max-count={}", step * 2),
                &commits[*pos].0,
            ])?;
            refine.extend(anc.lines().map(|s| s.to_string()));
        }
        progress(format!("refinement phase: {} trees", refine.len()));
        score_trees(refine, &mut tree_scores)?;
    }

    // Rank commits by quick score.
    let mut ranked: Vec<(&String, &String, f64)> = commits
        .iter()
        .filter_map(|(c, t)| tree_scores.get(t).map(|s| (c, t, s.score)))
        .collect();
    ranked.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let commits_scored = ranked.len();

    // Fine phase on the best distinct trees.
    let mut fine_trees: Vec<&String> = Vec::new();
    for (_, t, _) in &ranked {
        if !fine_trees.contains(t) {
            fine_trees.push(t);
        }
        if fine_trees.len() >= cfg.top_candidates.max(2) {
            break;
        }
    }
    progress(format!("content similarity on {} candidates", fine_trees.len()));
    let mut fine: HashMap<String, Candidate> = HashMap::new();
    for t in &fine_trees {
        let entries = repo.ls_tree(t)?;
        let base = tree_scores[*t].clone();
        fine.insert(
            (*t).clone(),
            fine_score(repo, &index, client_src, &entries, filter, cfg.manifest_weight, &base)?,
        );
    }

    // Candidates: (commit, tree, final score)
    let mut finals: Vec<(String, String, Candidate)> = ranked
        .iter()
        .filter_map(|(c, t, _)| fine.get(*t).map(|f| ((*c).clone(), (*t).clone(), f.clone())))
        .collect();
    finals.sort_by(|a, b| b.2.score.partial_cmp(&a.2.score).unwrap_or(std::cmp::Ordering::Equal));
    let best_score = finals[0].2.score;
    let equivalents: Vec<&(String, String, Candidate)> = finals
        .iter()
        .filter(|(_, _, c)| (c.score - best_score).abs() < 1e-9)
        .collect();

    // Choice among equivalents: named reference, then preferred branch, then most recent.
    let preferred_ref = preferred_branch.map(|b| format!("refs/upstream/heads/{b}"));
    let mut chosen = equivalents[0];
    if let Some(e) = equivalents.iter().find(|(c, _, _)| refs_by_commit.contains_key(c)) {
        chosen = e;
    } else if let Some(pr) = &preferred_ref {
        for e in &equivalents {
            if repo.is_ancestor(&e.0, pr).unwrap_or(false) {
                chosen = e;
                break;
            }
        }
    }
    let (best_commit, best_tree, best) = chosen.clone();
    let second = finals
        .iter()
        .find(|(_, t, c)| *t != best_tree && (c.score - best_score).abs() >= 1e-9);
    let margin = second.map(|s| best.score - s.2.score).unwrap_or(best.score);

    // Confidence.
    // Confidence = half separation (gap with the best distinct candidate),
    // half absolute similarity (does the fork really look like this commit?).
    // Separation independent of project size: relative distance to the
    // best distinct candidate (d = 1 - score).
    let d1 = (1.0 - best.score).max(0.0);
    let d2 = second.map(|s| (1.0 - s.2.score).max(0.0)).unwrap_or(1.0);
    let separation = if d2 <= 1e-12 {
        0.0
    } else {
        ((d2 - d1) / d2).clamp(0.0, 1.0)
    };
    let absolute = ((best.score - 0.2) / 0.6).clamp(0.0, 1.0);
    let mut confidence = 100.0 * (0.5 * separation + 0.5 * absolute);
    let distinct_equiv_trees: HashSet<&String> = equivalents.iter().map(|(_, t, _)| t).collect();
    if distinct_equiv_trees.len() > 1 {
        confidence = confidence.min(75.0);
    }
    if best.score < 0.3 {
        warnings.push(
            "very low score: the fork does not seem derived from this source, or was deeply restructured".to_string(),
        );
    }
    // An estimate is never presented as certain.
    let confidence = ((confidence.min(95.0)) * 10.0).round() / 10.0;
    let confidence_level = match confidence {
        c if c >= 85.0 => "high",
        c if c >= 60.0 => "medium",
        c if c >= 35.0 => "low",
        _ => "very low",
    }
    .to_string();

    // Reasons.
    let compared = best.identical + best.modified + best.deleted;
    let mut reasons = vec![
        "Estimate by content comparison: this commit is NOT a certain reference.".to_string(),
        format!(
            "{} identical files out of {} source files compared ({:.1} %), {} modified, {} deleted, {} added in the fork, {} moved/renamed unchanged.",
            best.identical,
            compared,
            if compared > 0 { 100.0 * best.identical as f64 / compared as f64 } else { 0.0 },
            best.modified,
            best.deleted,
            best.added,
            best.moved
        ),
    ];
    if best.manifests_total > 0 {
        reasons.push(format!(
            "{}/{} dependency/version/changelog files identical to this commit (higher weight in the score).",
            best.manifests_identical, best.manifests_total
        ));
    }
    if let Some(s) = best.content_similarity {
        reasons.push(format!("Average similarity of modified files: {:.1} %.", s * 100.0));
    }
    if let Some(s) = best.structure_similarity {
        reasons.push(format!("Structure similarity (directories): {:.1} %.", s * 100.0));
    }
    match second {
        Some((c, _, s)) => reasons.push(format!(
            "Next best candidate: {}{} (score {:.4}, gap {:.4}).",
            short(c),
            refs_by_commit
                .get(c)
                .map(|r| format!(" [{}]", r.join(", ")))
                .unwrap_or_default(),
            s.score,
            margin
        )),
        None => reasons.push("No other distinct candidate evaluated finely.".to_string()),
    }
    reasons.push(format!(
        "{} commits evaluated ({}).",
        commits_scored,
        if exhaustive {
            "exhaustive evaluation"
        } else {
            "sampling then local refinement"
        }
    ));
    reasons.push(format!(
        "Confidence components: candidate separation {:.0} %, absolute similarity {:.0} %.",
        separation * 100.0,
        absolute * 100.0
    ));
    let equivalent_commits: Vec<String> = equivalents
        .iter()
        .map(|(c, _, _)| c.clone())
        .filter(|c| *c != best_commit)
        .take(50)
        .collect();
    if !equivalent_commits.is_empty() {
        let same_tree = equivalents
            .iter()
            .filter(|(c, t, _)| *c != best_commit && *t == best_tree)
            .count();
        reasons.push(format!(
            "{} other commit(s) get exactly the same score, {} of them with strictly identical content (same tree, e.g. merge): the fork content cannot tell them apart.",
            equivalent_commits.len(),
            same_tree
        ));
    }

    let candidates: Vec<Candidate> = finals
        .iter()
        .map(|(c, _, cand)| {
            let mut cand = cand.clone();
            cand.commit = c.clone();
            cand.refs = refs_by_commit.get(c).cloned().unwrap_or_default();
            cand
        })
        .take(10)
        .collect();

    let mut best_c = best.clone();
    best_c.commit = best_commit.clone();
    Ok(ReferenceResult {
        method: ReferenceMethod::SnapshotEstimation,
        certainty: Certainty::Estimated,
        commit: repo.commit_meta(&best_commit)?.into(),
        location: locate(repo, &best_commit)?,
        confidence,
        confidence_level,
        reasons,
        fork_point: None,
        estimated_initial_base: None,
        candidates,
        equivalent_commits,
        commits_scored,
        warnings,
    })
}

/// Estimate from the tree of a fork commit (rewritten history).
pub fn estimate_from_client_commit(
    repo: &TempRepo,
    commit: &str,
    filter: &PathFilter,
    cfg: &ReferenceConfig,
    preferred_branch: Option<&str>,
) -> Result<ReferenceResult> {
    let snap = crate::diff::files::snapshot_from_tree(repo, commit, filter)?;
    let src = GitContent { repo };
    estimate_reference(repo, &snap, &src, filter, cfg, preferred_branch, &|_| {})
}
