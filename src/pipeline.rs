//! Full analysis orchestration.

use crate::analysis::dependencies::{analyze_manifest, dependency_findings, ecosystem_for, summarize};
use crate::analysis::rules::{AnalysisContext, Analyzer, Category, Finding, RuleSet, Severity};
use crate::analysis::secrets::scan_changes;
use crate::analysis::security::{analyze_changes, count_by_severity, finalize, RuleAnalyzer};
use crate::config::Config;
use crate::diff::compare::compare;
use crate::diff::files::{
    snapshot_directory, snapshot_from_tree, ContentProvider, DirectoryContent, GitContent, PathFilter, SnapshotEntry,
};
use crate::git::history::{
    analyze_history, client_specific_revs, commit_patches, commits_by_path, HistoryMode, HistoryParams, SuspicionReason,
};
use crate::git::reference::{estimate_from_client_commit, estimate_reference, identify_by_ancestry, Certainty};
use crate::git::repository::{fetch_client, inspect_client, TempRepo};
use crate::git::upstream::fetch_upstream;
use crate::report::console::Progress;
use crate::report::{
    self, ClientInfo, ClientMode, DiffSection, ForkScopeReport, ReportOptions, SecuritySection, ToolInfo,
    SCHEMA_VERSION,
};
use crate::utils::short;
use anyhow::{bail, Context, Result};
use regex::Regex;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Instant;

/// Analysis options.
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub client: PathBuf,
    pub upstream: String,
    /// Output directory (nothing written if `None`).
    pub output: Option<PathBuf>,
    pub branch: Option<String>,
    pub depth: Option<u32>,
    pub full_diff: bool,
    pub write_markdown: bool,
    pub write_json: bool,
    pub config: Config,
    pub config_file: Option<PathBuf>,
    pub force_snapshot: bool,
}

impl AnalyzeOptions {
    pub fn new(client: impl Into<PathBuf>, upstream: impl Into<String>) -> Self {
        Self {
            client: client.into(),
            upstream: upstream.into(),
            output: None,
            branch: None,
            depth: None,
            full_diff: false,
            write_markdown: true,
            write_json: true,
            config: Config::default(),
            config_file: None,
            force_snapshot: false,
        }
    }
}

const STEPS: usize = 7;

/// Runs the full analysis and writes the reports if an output directory is given.
pub fn run(opts: &AnalyzeOptions, progress: &dyn Progress) -> Result<ForkScopeReport> {
    let start = Instant::now();
    let cfg = &opts.config;
    let mut warnings: Vec<String> = Vec::new();
    let warn = |w: String, warnings: &mut Vec<String>| {
        progress.warn(&w);
        warnings.push(w);
    };

    // 1. Fork
    progress.step(1, STEPS, "Reading the fork");
    let root = opts
        .client
        .canonicalize()
        .with_context(|| format!("fork not found: {}", opts.client.display()))?;
    if !root.is_dir() {
        bail!("the fork path must be a directory: {}", root.display());
    }
    let filter = PathFilter::from_config(cfg)?;
    let layout = inspect_client(&root)?;
    let (worktree, walk_warnings) = snapshot_directory(&root, &filter)?;
    for w in walk_warnings {
        warn(w, &mut warnings);
    }
    progress.done(&format!(
        "{} files — {}",
        worktree.files().count(),
        if layout.is_git() {
            "Git repository"
        } else {
            "no Git metadata"
        }
    ));

    // 2. Source
    progress.step(2, STEPS, "Fetching the source repository");
    let repo = TempRepo::new()?;
    let mut head = None;
    if layout.is_git() && !opts.force_snapshot {
        progress.detail("read-only import of the fork's objects");
        let f = fetch_client(&repo, &layout)?;
        for w in f.warnings {
            warn(w, &mut warnings);
        }
        head = f.head;
    }
    progress.detail("git fetch source");
    let upstream = fetch_upstream(&repo, &opts.upstream, opts.depth, opts.branch.as_deref())?;
    if let Some(b) = &opts.branch {
        if repo.resolve_commit(&format!("refs/upstream/heads/{b}"))?.is_none() {
            warn(format!("source branch \"{b}\" does not exist"), &mut warnings);
        }
    }
    progress.done(&format!("{} branches, {} tags", upstream.branches, upstream.tags));

    // 3. Reference
    progress.step(3, STEPS, "Identifying the source reference");
    let preferred = upstream.preferred_branch.clone();
    let detail = |m: String| progress.detail(&m);
    let (mut reference, client_mode, history_mode) = match &head {
        Some(h) => match identify_by_ancestry(&repo, h, preferred.as_deref())? {
            Some(r) => (r, ClientMode::GitHistory, Some(HistoryMode::Ancestry)),
            None => {
                progress.detail("no common commit: content-based estimation");
                let mut r = estimate_reference(
                    &repo,
                    &worktree,
                    &DirectoryContent { root: root.clone() },
                    &filter,
                    &cfg.reference,
                    preferred.as_deref(),
                    &detail,
                )?;
                let roots = repo.run(&["rev-list", "--max-parents=0", h])?;
                if let Some(first) = roots.lines().last() {
                    progress.detail("estimating the starting point (fork's first commit)");
                    match estimate_from_client_commit(
                        &repo,
                        first.trim(),
                        &filter,
                        &cfg.reference,
                        preferred.as_deref(),
                    ) {
                        Ok(init) => r.estimated_initial_base = Some(Box::new(init)),
                        Err(e) => r.warnings.push(format!("cannot estimate the starting point: {e}")),
                    }
                }
                (r, ClientMode::RewrittenHistory, Some(HistoryMode::Rewritten))
            }
        },
        None => {
            let mode = if opts.force_snapshot {
                ClientMode::ForcedSnapshot
            } else if layout.is_git() {
                ClientMode::GitHistoryUnusable
            } else {
                ClientMode::NoGitMetadata
            };
            let r = estimate_reference(
                &repo,
                &worktree,
                &DirectoryContent { root: root.clone() },
                &filter,
                &cfg.reference,
                preferred.as_deref(),
                &detail,
            )?;
            (r, mode, None)
        }
    };
    if opts.depth.is_some() && client_mode == ClientMode::RewrittenHistory {
        reference.warnings.push(
            "shallow source fetch (--depth): the lack of a common ancestor may come from the truncated history".into(),
        );
    }
    for w in &reference.warnings {
        progress.warn(w);
    }
    progress.done(&format!(
        "{} — {}",
        reference.commit.short,
        match reference.certainty {
            Certainty::Exact => "certain".to_string(),
            Certainty::Estimated => format!("estimated, confidence {:.0} %", reference.confidence),
        }
    ));

    // 4. History
    progress.step(4, STEPS, "Analysing the history");
    let mut history = match (&head, history_mode) {
        (Some(h), Some(mode)) => Some(analyze_history(
            &repo,
            &HistoryParams {
                layout: &layout,
                head: h,
                mode,
                reference: &reference,
                preferred_branch: preferred.as_deref(),
                worktree: &worktree,
                filter: &filter,
                cfg: &cfg.history,
            },
        )?),
        _ => None,
    };
    progress.done(&match &history {
        Some(h) => format!("{} specific commits", h.client_commits_total),
        None => "no usable history".into(),
    });

    // 5. Diff
    progress.step(5, STEPS, "Comparing files");
    let ref_snap = snapshot_from_tree(&repo, &reference.commit.hash, &filter)?;
    let ref_src = GitContent { repo: &repo };
    let client_src = DirectoryContent { root: root.clone() };
    let mut diff = compare(&ref_snap, &ref_src, &worktree, &client_src, &cfg.diff)?;
    if let Some(h) = &history {
        let by_path = commits_by_path(&h.client_commits);
        let untracked: std::collections::HashSet<&str> = h
            .working_tree
            .untracked
            .iter()
            .chain(h.working_tree.ignored.iter())
            .map(|s| s.as_str())
            .collect();
        for c in &mut diff.changes {
            let mut commits = by_path.get(&c.path).cloned().unwrap_or_default();
            if let Some(o) = &c.old_path {
                commits.extend(by_path.get(o).cloned().unwrap_or_default());
            }
            commits.dedup();
            c.commits = commits;
            c.untracked = untracked.contains(c.path.as_str());
        }
    }
    progress.detail("origin of changes");
    if let Err(e) = crate::git::origin::attribute_origins(
        &repo,
        &reference.commit.hash,
        &worktree,
        &mut diff.changes,
        history.as_ref(),
    ) {
        warn(format!("cannot attribute origins: {e}"), &mut warnings);
    }
    for c in &diff.changes {
        *diff.stats.by_origin.entry(c.origin).or_insert(0) += 1;
    }
    diff.stats.client_changes = diff.changes.iter().filter(|c| c.origin.is_client()).count();
    progress.done(&format!(
        "{} added, {} deleted, {} modified, {} renamed/moved — {} attributed to the fork",
        diff.stats.added,
        diff.stats.deleted,
        diff.stats.modified,
        diff.stats.renamed + diff.stats.moved,
        diff.stats.client_changes
    ));

    // 6. Analyses
    progress.step(6, STEPS, "Security, dependency and secret analyses");
    let rules = RuleSet::load(&cfg.security)?;
    let analyzers: Vec<Box<dyn Analyzer>> = vec![Box::new(RuleAnalyzer { rules: rules.clone() })];
    let mut findings: Vec<Finding> = Vec::new();
    let ctx = AnalysisContext { changes: &diff.changes };
    for a in &analyzers {
        progress.detail(&format!("analyzer {}", a.name()));
        findings.extend(a.analyze(&ctx)?);
    }

    progress.detail("dependencies");
    let mut manifests = Vec::new();
    for c in &diff.changes {
        if ecosystem_for(&c.path).is_none()
            && !c
                .old_path
                .as_deref()
                .map(|p| ecosystem_for(p).is_some())
                .unwrap_or(false)
        {
            continue;
        }
        let old_entry: Option<&SnapshotEntry> = ref_snap.entries.get(c.old_path.as_deref().unwrap_or(&c.path));
        let new_entry: Option<&SnapshotEntry> = worktree
            .entries
            .get(&c.path)
            .filter(|_| c.status != crate::diff::ChangeStatus::Deleted);
        let old = old_entry
            .map(|e| ref_src.load(&[e]))
            .transpose()?
            .and_then(|mut m| m.remove(&e_path(old_entry)));
        let new = new_entry
            .map(|e| client_src.load(&[e]))
            .transpose()?
            .and_then(|mut m| m.remove(&e_path(new_entry)));
        if let Some(m) = analyze_manifest(c, old.as_deref(), new.as_deref()) {
            if let Some(e) = &m.parse_error {
                warn(format!("{}: {e}", m.path), &mut warnings);
            }
            manifests.push(m);
        }
    }
    let dependencies = summarize(manifests);
    findings.extend(dependency_findings(&dependencies));

    progress.detail("secrets");
    let secrets = scan_changes(&diff.changes, &cfg.secrets);

    // Commit-by-commit analysis (suspicious commits + precise attribution).
    let mut precise: HashMap<(String, String), Vec<String>> = HashMap::new();
    if let (Some(h), true) = (history.as_mut(), cfg.history.analyze_commit_diffs) {
        progress.detail("analysing the fork commits");
        let revs = client_specific_revs(&h.client_head, h.mode);
        match commit_patches(&repo, &revs, cfg.history.max_client_commits) {
            Ok(patches) => {
                let mut reasons: HashMap<String, Vec<SuspicionReason>> = HashMap::new();
                for (hash, changes) in &patches {
                    let f = analyze_changes(&rules, changes);
                    let s = scan_changes(changes, &cfg.secrets);
                    let r = reasons.entry(hash.clone()).or_default();
                    for x in &f {
                        precise
                            .entry((x.rule_id.clone(), x.file.clone()))
                            .or_default()
                            .push(hash.clone());
                        if x.severity >= Severity::Low {
                            r.push(SuspicionReason {
                                category: x.category,
                                severity: x.severity,
                                detail: format!(
                                    "{} ({}{}) [{}]",
                                    x.title,
                                    x.file,
                                    x.line.map(|l| format!(":{l}")).unwrap_or_default(),
                                    x.rule_id
                                ),
                            });
                        }
                    }
                    for x in &s {
                        r.push(SuspicionReason {
                            category: Category::Secrets,
                            severity: x.severity,
                            detail: format!(
                                "{} ({}{})",
                                x.description,
                                x.file,
                                x.line.map(|l| format!(":{l}")).unwrap_or_default()
                            ),
                        });
                    }
                    let dep_files: Vec<&str> = changes
                        .iter()
                        .filter(|c| ecosystem_for(&c.path).is_some())
                        .map(|c| c.path.as_str())
                        .collect();
                    if !dep_files.is_empty() {
                        r.push(SuspicionReason {
                            category: Category::Dependencies,
                            severity: Severity::Low,
                            detail: format!("dependency files modified: {}", dep_files.join(", ")),
                        });
                    }
                    let (ins, del): (usize, usize) = changes
                        .iter()
                        .fold((0, 0), |a, c| (a.0 + c.lines_added, a.1 + c.lines_removed));
                    let deleted_files = changes
                        .iter()
                        .filter(|c| c.status == crate::diff::ChangeStatus::Deleted)
                        .count();
                    if del >= 50 && del > 3 * ins || deleted_files >= 3 {
                        r.push(SuspicionReason {
                            category: Category::Other,
                            severity: Severity::Low,
                            detail: format!("large code removal (−{del} / +{ins} lines, {deleted_files} file(s) deleted): feature possibly removed"),
                        });
                    }
                }
                let benign = Regex::new(
                    r"(?i)^\s*(fix(ed)?\s+typos?|typo|clean ?up|refactor|format(ting)?|lint|style|wip|minor|small fix|update readme|docs?\b|bump|chore|misc|tweak|\.|-|update)\b",
                )?;
                for c in &mut h.client_commits {
                    if let Some(mut r) = reasons.remove(&c.hash) {
                        r.sort_by_key(|x| std::cmp::Reverse(x.severity));
                        let max = r.first().map(|x| x.severity);
                        if max.map(|m| m >= Severity::High).unwrap_or(false)
                            && (benign.is_match(&c.subject) || c.subject.trim().len() < 8)
                        {
                            r.push(SuspicionReason {
                                category: Category::Other,
                                severity: Severity::Medium,
                                detail: format!("innocuous commit message (\"{}\") for a sensitive change: commit messages are not reliable", c.subject),
                            });
                        }
                        c.max_severity = max;
                        c.suspicious = r;
                    }
                }
            }
            Err(e) => warn(format!("cannot analyse commits: {e}"), &mut warnings),
        }
    }
    for f in &mut findings {
        if let Some(c) = precise.get(&(f.rule_id.clone(), f.file.clone())) {
            let mut c = c.clone();
            c.dedup();
            f.commits = c;
        }
    }
    // Origin: tone down findings on code coming from the source,
    // and dedicated finding for files rolled back to an older source version.
    let origins: HashMap<&str, (&crate::diff::ChangeOrigin, Option<&String>)> = diff
        .changes
        .iter()
        .map(|c| (c.path.as_str(), (&c.origin, c.upstream_commit.as_ref())))
        .collect();
    for f in &mut findings {
        if let Some((o, up)) = origins.get(f.file.as_str()) {
            if matches!(
                o,
                crate::diff::ChangeOrigin::UpstreamNewer | crate::diff::ChangeOrigin::UpstreamCherryPick
            ) {
                f.confidence = f.confidence.lower();
                f.justification.push_str(&format!(
                    " Origin: {}{} — code presumably not written by the fork.",
                    o.label(),
                    up.map(|u| format!(" ({})", short(u))).unwrap_or_default()
                ));
            }
        }
    }
    for c in diff
        .changes
        .iter()
        .filter(|c| c.origin == crate::diff::ChangeOrigin::UpstreamOlder)
    {
        findings.push(Finding {
            id: String::new(),
            rule_id: "ORIGIN-001".into(),
            title: "File rolled back to an older source version".into(),
            category: Category::Other,
            severity: Severity::Medium,
            confidence: crate::analysis::rules::Confidence::High,
            file: c.path.clone(),
            line: None,
            old_line: None,
            change: "rollback".into(),
            old_code: None,
            new_code: None,
            justification: format!(
                "{}: a source fix (possibly a security fix) may have been undone.",
                c.origin_detail.clone().unwrap_or_default()
            ),
            source: "origin".into(),
            commits: c.commits.clone(),
        });
    }
    // Default attribution: commits that touched the file.
    let file_commits: HashMap<&str, &Vec<String>> =
        diff.changes.iter().map(|c| (c.path.as_str(), &c.commits)).collect();
    for f in &mut findings {
        if f.commits.is_empty() {
            if let Some(c) = file_commits.get(f.file.as_str()) {
                f.commits = (*c).clone();
            }
        }
    }
    // Avoid duplicates: a package source already reported by the dependency analysis.
    let dep_source_files: std::collections::HashSet<String> = findings
        .iter()
        .filter(|f| f.source == "dependencies" && f.title.starts_with("Package source"))
        .map(|f| f.file.clone())
        .collect();
    findings.retain(|f| !(f.rule_id == "CONF-012" && dep_source_files.contains(&f.file)));
    let findings = finalize(findings);
    let counts: BTreeMap<Severity, usize> = count_by_severity(&findings).into_iter().collect();
    progress.done(&format!(
        "{} findings ({} critical, {} high), {} secrets",
        findings.len(),
        counts.get(&Severity::Critical).unwrap_or(&0),
        counts.get(&Severity::High).unwrap_or(&0),
        secrets.len()
    ));

    // 7. Reports
    progress.step(7, STEPS, "Generating reports");
    progress.detail("timeline and divergence graph");
    let last_disk_change = {
        let mut best: Option<(std::time::SystemTime, String)> = None;
        let mut files = 0;
        for c in diff
            .changes
            .iter()
            .filter(|c| c.origin.is_client() && c.status != crate::diff::ChangeStatus::Deleted)
        {
            if let Ok(t) = std::fs::metadata(root.join(&c.path)).and_then(|m| m.modified()) {
                files += 1;
                if best.as_ref().map(|(b, _)| t > *b).unwrap_or(true) {
                    best = Some((t, c.path.clone()));
                }
            }
        }
        best.map(|(t, path)| crate::git::timeline::DiskChange {
            date: chrono::DateTime::<chrono::Local>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            path,
            files,
        })
    };
    let uncommitted_files = history
        .as_ref()
        .map(|h| {
            let wt = &h.working_tree;
            let mut set: std::collections::HashSet<&str> = wt
                .staged
                .iter()
                .chain(wt.unstaged.iter())
                .map(|e| e.path.as_str())
                .collect();
            set.extend(wt.untracked.iter().map(|s| s.as_str()));
            set.len()
        })
        .unwrap_or(0);
    let timeline = match crate::git::timeline::build(
        &repo,
        &crate::git::timeline::TimelineParams {
            reference: &reference,
            history: history.as_ref(),
            preferred_branch: preferred.as_deref(),
            last_disk_change,
            uncommitted_files,
            fork_changes: diff.changes.iter().filter(|c| c.origin.is_client()).count(),
        },
    ) {
        Ok(t) => t,
        Err(e) => {
            warn(format!("cannot build the timeline: {e}"), &mut warnings);
            Default::default()
        }
    };
    // Written diffs (.diff files, --full-diff) never contain secrets in clear text.
    {
        use rayon::prelude::*;
        diff.changes.par_iter_mut().for_each(|c| {
            for h in &mut c.hunks {
                for l in &mut h.lines {
                    l.text = crate::analysis::secrets::mask_in_text(&l.text);
                }
            }
        });
    }
    if let Some(out) = &opts.output {
        std::fs::create_dir_all(out).with_context(|| format!("creating the output directory {}", out.display()))?;
        let diffs_dir = out.join("diffs");
        if diffs_dir.exists() {
            std::fs::remove_dir_all(&diffs_dir).ok();
        }
        report::write_diffs(out, &mut diff.changes)?;
    }
    if let Some(h) = &history {
        warnings.extend(h.warnings.iter().cloned());
    }
    let mut rep = ForkScopeReport {
        schema_version: SCHEMA_VERSION.to_string(),
        tool: ToolInfo {
            name: "forkscope".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        generated_at: chrono::Local::now().to_rfc3339(),
        duration_seconds: (start.elapsed().as_secs_f64() * 100.0).round() / 100.0,
        options: ReportOptions {
            full_diff: opts.full_diff,
            branch: opts.branch.clone(),
            depth: opts.depth,
            force_snapshot: opts.force_snapshot,
            config_file: opts.config_file.as_ref().map(|p| p.display().to_string()),
        },
        client: ClientInfo {
            path: root.display().to_string(),
            mode: client_mode,
            is_git: layout.is_git(),
            shallow: layout.shallow,
            head: head.clone(),
            head_ref: layout.head_ref.clone(),
            files: worktree.files().count(),
        },
        upstream,
        reference,
        timeline,
        history,
        diff: DiffSection {
            stats: diff.stats.clone(),
            files: diff.changes,
        },
        security: SecuritySection { counts, findings },
        dependencies,
        secrets,
        recommendations: vec![],
        warnings,
    };
    rep.recommendations = report::recommendations(&rep);
    if let Some(out) = &opts.output {
        if opts.write_markdown {
            std::fs::write(out.join(report::markdown::REPORT_FILE), report::markdown::render(&rep))?;
        }
        if opts.write_json {
            report::json::write(&rep, out, opts.full_diff)?;
        }
        std::fs::write(out.join(report::FILE_LIST_TXT), report::file_list_txt(&rep))?;
        std::fs::write(out.join(report::graph::SVG_FILE), report::graph::svg(&rep.timeline))?;
        std::fs::write(out.join(report::FILE_LIST_CSV), report::file_list_csv(&rep))?;
        progress.done(&format!("{}", out.display()));
    } else {
        progress.done("no output directory");
    }
    let _ = short("");
    Ok(rep)
}

fn e_path(e: Option<&SnapshotEntry>) -> String {
    e.map(|e| e.path.clone()).unwrap_or_default()
}
