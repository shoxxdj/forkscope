//! Report model and output generation (Markdown, JSON, diffs).

pub mod console;
pub mod graph;
pub mod json;
pub mod markdown;

use crate::analysis::dependencies::DependencyReport;
use crate::analysis::rules::{Finding, Severity};
use crate::analysis::secrets::SecretFinding;
use crate::diff::compare::DiffStats;
use crate::diff::similarity::render_unified;
use crate::diff::FileChange;
use crate::git::history::HistoryAnalysis;
use crate::git::reference::{Certainty, ReferenceResult};
use crate::git::upstream::UpstreamInfo;
use crate::utils::safe_relative_path;
use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Version of the report's JSON schema (SemVer: major = breaking change).
pub const SCHEMA_VERSION: &str = "1.0.0";

/// Situation of the fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientMode {
    /// Git history descending from the source.
    GitHistory,
    /// Git repository with no commit in common with the source (rewritten/imported history).
    RewrittenHistory,
    /// Git repository present but unreadable or empty.
    GitHistoryUnusable,
    /// Plain source directory.
    NoGitMetadata,
    /// History ignored on request (`--force-snapshot`).
    ForcedSnapshot,
}

impl ClientMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::GitHistory => "Git repository with history linked to the source",
            Self::RewrittenHistory => "Git repository with rewritten history (no commit in common with the source)",
            Self::GitHistoryUnusable => "unusable Git repository (empty or corrupt)",
            Self::NoGitMetadata => "source directory without Git metadata",
            Self::ForcedSnapshot => "history ignored (--force-snapshot)",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReportOptions {
    pub full_diff: bool,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub force_snapshot: bool,
    pub config_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientInfo {
    pub path: String,
    pub mode: ClientMode,
    pub is_git: bool,
    pub shallow: bool,
    pub head: Option<String>,
    pub head_ref: Option<String>,
    pub files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DiffSection {
    pub stats: DiffStats,
    /// Differing files (identical files are only counted).
    pub files: Vec<FileChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecuritySection {
    /// Number of findings per severity.
    pub counts: BTreeMap<Severity, usize>,
    pub findings: Vec<Finding>,
}

/// Full ForkScope report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ForkScopeReport {
    pub schema_version: String,
    pub tool: ToolInfo,
    pub generated_at: String,
    pub duration_seconds: f64,
    pub options: ReportOptions,
    /// Analysed fork repository.
    #[serde(rename = "fork")]
    pub client: ClientInfo,
    /// Source (original) repository.
    #[serde(rename = "source")]
    pub upstream: UpstreamInfo,
    pub reference: ReferenceResult,
    /// Key dates and divergence graph.
    pub timeline: crate::git::timeline::Timeline,
    pub history: Option<HistoryAnalysis>,
    pub diff: DiffSection,
    pub security: SecuritySection,
    pub dependencies: DependencyReport,
    pub secrets: Vec<SecretFinding>,
    pub recommendations: Vec<String>,
    pub warnings: Vec<String>,
}

/// Writes one `.diff` file per text change into `<out>/diffs/` and
/// renseigne `diff_file`.
pub fn write_diffs(out: &Path, changes: &mut [FileChange]) -> Result<usize> {
    let dir = out.join("diffs");
    let mut n = 0;
    for c in changes.iter_mut() {
        if c.hunks.is_empty() {
            continue;
        }
        let Some(rel) = safe_relative_path(&c.path) else {
            continue;
        };
        let mut file = dir.join(rel);
        let name = format!(
            "{}.diff",
            file.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
        file.set_file_name(name);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let old = match c.status {
            crate::diff::ChangeStatus::Added => None,
            _ => Some(c.old_path.as_deref().unwrap_or(&c.path)),
        };
        let new = match c.status {
            crate::diff::ChangeStatus::Deleted => None,
            _ => Some(c.path.as_str()),
        };
        std::fs::write(&file, render_unified(old, new, &c.hunks))?;
        c.diff_file = Some(
            file.strip_prefix(out)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/"),
        );
        n += 1;
    }
    Ok(n)
}

/// `git status`-like status letter.
pub fn status_letter(s: crate::diff::ChangeStatus) -> char {
    use crate::diff::ChangeStatus::*;
    match s {
        Added => 'A',
        Deleted => 'D',
        Modified => 'M',
        Renamed => 'R',
        Moved => 'V',
        Identical => ' ',
    }
}

/// Changed-file list files.
pub const FILE_LIST_TXT: &str = "changed-files.txt";
pub const FILE_LIST_CSV: &str = "changed-files.csv";

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Text list of the changed files (those attributed to the fork first).
pub fn file_list_txt(r: &ForkScopeReport) -> String {
    let mut out = format!(
        "# ForkScope — files differing from source reference {} ({} files, {} attributed to the fork)\n\
         # Status: A added, D deleted, M modified, R renamed, V moved\n\
         # Columns: status, path [<- former path], origin\n",
        r.reference.commit.short,
        r.diff.files.len(),
        r.diff.stats.client_changes
    );
    let mut files: Vec<&FileChange> = r.diff.files.iter().collect();
    files.sort_by(|a, b| {
        b.origin
            .is_client()
            .cmp(&a.origin.is_client())
            .then(a.path.cmp(&b.path))
    });
    let width = files
        .iter()
        .map(|c| c.path.len() + c.old_path.as_ref().map(|o| o.len() + 3).unwrap_or(0))
        .max()
        .unwrap_or(0);
    let mut section = None;
    for c in files {
        let client = c.origin.is_client();
        if section != Some(client) {
            out.push_str(if client {
                "\n## Changes attributed to the fork\n"
            } else {
                "\n## Content coming from the source (outside the reference)\n"
            });
            section = Some(client);
        }
        let name = match &c.old_path {
            Some(o) => format!("{} <- {}", c.path, o),
            None => c.path.clone(),
        };
        out.push_str(&format!(
            "{}  {:width$}  {}\n",
            status_letter(c.status),
            name,
            c.origin.label(),
            width = width
        ));
    }
    out
}

/// Detailed CSV list of the changed files.
pub fn file_list_csv(r: &ForkScopeReport) -> String {
    let mut out = String::from(
        "status,path,former_path,origin,origin_detail,source_commit,lines_added,lines_removed,similarity,binary,untracked,fork_commits,sha256_before,sha256_after\n",
    );
    for c in &r.diff.files {
        let row = [
            c.status.label().to_string(),
            c.path.clone(),
            c.old_path.clone().unwrap_or_default(),
            c.origin.label().to_string(),
            c.origin_detail.clone().unwrap_or_default(),
            c.upstream_commit.clone().unwrap_or_default(),
            c.lines_added.to_string(),
            c.lines_removed.to_string(),
            c.similarity.map(|s| format!("{:.3}", s)).unwrap_or_default(),
            c.is_binary.to_string(),
            c.untracked.to_string(),
            c.commits.join(" "),
            c.old_sha256.clone().unwrap_or_default(),
            c.new_sha256.clone().unwrap_or_default(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// Builds the investigation recommendations.
pub fn recommendations(r: &ForkScopeReport) -> Vec<String> {
    let mut out = Vec::new();
    let crit = r.security.counts.get(&Severity::Critical).copied().unwrap_or(0);
    let high = r.security.counts.get(&Severity::High).copied().unwrap_or(0);
    if r.reference.certainty == Certainty::Estimated {
        out.push(format!(
            "Manually validate the estimated source reference ({}, confidence {:.0} % – {}) before drawing final conclusions; review the alternative candidates listed.",
            r.reference.commit.short, r.reference.confidence, r.reference.confidence_level
        ));
    }
    if crit + high > 0 {
        out.push(format!(
            "Review first the {} critical and {} high finding(s) in the \"Sensitive changes\" section: they are leads, to be confirmed by reading the code.",
            crit, high
        ));
    }
    if !r.secrets.is_empty() {
        out.push(format!(
            "{} potential secret(s) introduced: check their validity, revoke/rotate them if needed, and check the Git history (a deleted secret remains in the commits).",
            r.secrets.len()
        ));
    }
    if r.dependencies.external > 0 || r.dependencies.source_changed > 0 {
        out.push(format!(
            "{} external dependency(ies) (Git/URL/path) and {} source change(s): check the origin and integrity of these packages.",
            r.dependencies.external, r.dependencies.source_changed
        ));
    }
    if r.dependencies.added > 0 {
        out.push(format!(
            "{} dependency(ies) added: check their legitimacy (typosquatting, dependency confusion) and their known vulnerabilities with a dedicated tool (cargo audit, npm audit, pip-audit…).",
            r.dependencies.added
        ));
    }
    if let Some(h) = &r.history {
        if !h.working_tree.is_clean() {
            out.push(format!(
                "The working tree contains uncommitted changes ({} staged, {} unstaged) and {} untracked file(s): these are not in the fork's history.",
                h.working_tree.staged.len(),
                h.working_tree.unstaged.len(),
                h.working_tree.untracked.len()
            ));
        }
        if !h.working_tree.ignored.is_empty() {
            out.push(format!(
                "{} file(s) present on disk but ignored by .gitignore were analysed (e.g. .env files): check whether they are shipped.",
                h.working_tree.ignored.len()
            ));
        }
        let reverted = h
            .patch_matches
            .iter()
            .filter(|m| m.kind == crate::git::patch_id::MatchKind::Reverted)
            .count();
        if reverted > 0 {
            out.push(format!(
                "{reverted} source commit(s) were reverted by the fork: check that they are not security fixes."
            ));
        }
        if !h.upstream_security_hints.is_empty() {
            out.push(format!(
                "{} source commit(s) newer than the reference mention security in their message: check whether these fixes are missing from the fork (hint based on messages, not reliable).",
                h.upstream_security_hints.len()
            ));
        }
        if let Some(b) = h.behind.iter().find(|b| b.commits_behind > 0) {
            out.push(format!(
                "The fork is {} commit(s) behind source branch \"{}\".",
                b.commits_behind, b.branch
            ));
        }
        if h.branches.iter().any(|b| b.divergent) {
            out.push("Local fork branches contain work not integrated into HEAD: review them separately if they are deployed.".to_string());
        }
        if h.stash_entries > 0 {
            out.push(format!(
                "{} stash entry(ies) present in the fork repository (uncommitted work set aside).",
                h.stash_entries
            ));
        }
        let suspicious = h
            .client_commits
            .iter()
            .filter(|c| c.max_severity.map(|s| s >= Severity::High).unwrap_or(false))
            .count();
        if suspicious > 0 {
            out.push(format!(
                "{suspicious} fork commit(s) contain high or critical severity changes: review them commit by commit."
            ));
        }
    }
    let count = |o: crate::diff::ChangeOrigin| r.diff.stats.by_origin.get(&o).copied().unwrap_or(0);
    let older = count(crate::diff::ChangeOrigin::UpstreamOlder);
    if older > 0 {
        out.push(format!(
            "{older} file(s) were rolled back to a source version older than the reference: check that no security fix was undone (ORIGIN-001 findings)."
        ));
    }
    let up = count(crate::diff::ChangeOrigin::UpstreamNewer) + count(crate::diff::ChangeOrigin::UpstreamCherryPick);
    if up > 0 {
        out.push(format!(
            "{up} file(s) differing from the reference actually come from the source (backport, cherry-pick): the review effort can focus on the {} file(s) attributed to the fork.",
            r.diff.stats.client_changes
        ));
    }
    let und = count(crate::diff::ChangeOrigin::Undetermined);
    if und > 0 {
        out.push(format!(
            "{und} file(s) of undetermined origin (probably merge resolutions): review them as fork changes."
        ));
    }
    if r.diff.stats.binary_changed > 0 {
        out.push(format!(
            "{} binary file(s) added or modified: cannot be analysed as text, to be checked (origin, SHA-256 hashes).",
            r.diff.stats.binary_changed
        ));
    }
    if out.is_empty() {
        out.push("No priority lead detected automatically: reviewing the changed files is still required.".to_string());
    }
    out
}
