//! Markdown report for an auditor.

use super::ForkScopeReport;
use crate::analysis::rules::Severity;
use crate::diff::similarity::render_unified;
use crate::diff::{ChangeStatus, FileChange};
use crate::git::reference::Certainty;
use crate::utils::short;
use std::fmt::Write as _;

/// Name of the generated Markdown file.
pub const REPORT_FILE: &str = "forkscope-report.md";

const MAX_ROWS: usize = 500;

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ").replace('`', "'")
}

fn code(s: &str) -> String {
    format!("`{}`", s.replace('`', "'").replace('|', "\\|"))
}

fn commit_links(commits: &[String]) -> String {
    if commits.is_empty() {
        return "—".into();
    }
    let mut v: Vec<String> = commits.iter().take(5).map(|c| format!("`{}`", short(c))).collect();
    if commits.len() > 5 {
        v.push(format!("+{}", commits.len() - 5));
    }
    v.join(", ")
}

fn diff_link(c: &FileChange) -> String {
    match &c.diff_file {
        Some(f) => format!("[diff]({})", f.replace(' ', "%20")),
        None => "—".into(),
    }
}

fn fence(body: &str, lang: &str) -> String {
    format!("````{lang}\n{body}\n````\n")
}

/// Generates the Markdown report.
pub fn render(r: &ForkScopeReport) -> String {
    let mut s = String::new();
    let w = &mut s;
    let _ = writeln!(w, "# ForkScope report\n");
    let _ = writeln!(
        w,
        "> Generated on {} by {} {} (schema {}). The findings in this report are **leads to investigate**, not confirmed vulnerabilities.\n",
        r.generated_at, r.tool.name, r.tool.version, r.schema_version
    );

    // 1. Executive summary
    let _ = writeln!(w, "## 1. Executive summary\n");
    let certainty = match r.reference.certainty {
        Certainty::Exact => "identified with certainty (Git ancestry)".to_string(),
        Certainty::Estimated => format!(
            "**estimated** (confidence {:.0} %, {}) — to be validated",
            r.reference.confidence, r.reference.confidence_level
        ),
    };
    let refs = if r.reference.location.pointing_refs.is_empty() {
        r.reference
            .location
            .describe
            .clone()
            .unwrap_or_else(|| "no exact branch/tag".into())
    } else {
        r.reference.location.pointing_refs.join(", ")
    };
    let _ = writeln!(w, "- **Fork**: {} ({})", code(&r.client.path), r.client.mode.label());
    let _ = writeln!(w, "- **Source**: {}", code(&r.upstream.url));
    let _ = writeln!(
        w,
        "- **Source reference**: `{}` ({}) — {}",
        r.reference.commit.short,
        esc(&refs),
        certainty
    );
    if let Some(h) = &r.history {
        let _ = writeln!(w, "- **Fork-specific commits**: {}", h.client_commits_total);
        {
            let tl = &r.timeline;
            let start = tl
                .first_fork_commit
                .as_ref()
                .map(|c| c.date.clone())
                .or_else(|| tl.last_disk_change.as_ref().map(|d| d.date.clone()));
            let end = [
                tl.last_fork_commit.as_ref().map(|c| c.date.clone()),
                tl.last_disk_change.as_ref().map(|d| d.date.clone()),
            ]
            .into_iter()
            .flatten()
            .max_by_key(|d| {
                chrono::DateTime::parse_from_rfc3339(d)
                    .map(|x| x.timestamp())
                    .unwrap_or(0)
            });
            if let Some(d) = &tl.divergence {
                let _ = writeln!(
                    w,
                    "- **Divergence**: {}{} (source commit `{}`)",
                    super::graph::when(&d.date),
                    if tl.divergence_estimated { " — estimated" } else { "" },
                    d.short
                );
            }
            if let (Some(a), Some(b)) = (start, end) {
                let _ = writeln!(
                    w,
                    "- **Fork modification period**: from {} to {}",
                    super::graph::when(&a),
                    super::graph::when(&b)
                );
            }
        }
    }
    let st = &r.diff.stats;
    let _ = writeln!(
        w,
        "- **Files**: {} added, {} deleted, {} modified, {} renamed, {} moved, {} identical (+{} / −{} lines)",
        st.added, st.deleted, st.modified, st.renamed, st.moved, st.identical, st.lines_added, st.lines_removed
    );
    let _ = writeln!(
        w,
        "- **Files attributed to the fork**: {} out of {} differing files (see \"Changed files\", section 6)",
        st.client_changes,
        r.diff.files.len()
    );
    let counts: Vec<String> = Severity::ALL
        .iter()
        .map(|sev| format!("{}: {}", sev.label(), r.security.counts.get(sev).copied().unwrap_or(0)))
        .collect();
    let _ = writeln!(w, "- **Security findings**: {}", counts.join(" · "));
    let _ = writeln!(
        w,
        "- **Dependencies**: {} added, {} removed, {} versions changed, {} sources changed, {} external",
        r.dependencies.added,
        r.dependencies.removed,
        r.dependencies.version_changed,
        r.dependencies.source_changed,
        r.dependencies.external
    );
    let _ = writeln!(w, "- **Potential secrets**: {}\n", r.secrets.len());

    // Key dates and divergence graph
    let tl = &r.timeline;
    let _ = writeln!(w, "### Key dates\n");
    let _ = writeln!(w, "| Event | Date | Details |\n|---|---|---|");
    let commit_row = |w: &mut String, label: &str, c: &Option<crate::git::timeline::DatedCommit>, note: &str| {
        if let Some(c) = c {
            let author = if c.author_date != c.date && !c.author_date.is_empty() {
                format!(" — written on {}", super::graph::when(&c.author_date))
            } else {
                String::new()
            };
            let _ = writeln!(
                w,
                "| {label} | **{}** | `{}` {}{}{} |",
                super::graph::when(&c.date),
                c.short,
                esc(&crate::utils::truncate(&c.subject, 70)),
                author,
                note
            );
        }
    };
    commit_row(
        w,
        if tl.divergence_estimated {
            "Fork divergence (estimated)"
        } else {
            "Fork divergence"
        },
        &tl.divergence,
        if tl.divergence_estimated {
            " — date of the estimated source commit, the fork may have diverged later"
        } else {
            ""
        },
    );
    if tl
        .reference
        .as_ref()
        .map(|x| Some(&x.hash) != tl.divergence.as_ref().map(|d| &d.hash))
        .unwrap_or(false)
    {
        commit_row(w, "Latest integration from the source", &tl.reference, "");
    }
    commit_row(w, "First fork commit", &tl.first_fork_commit, "");
    commit_row(w, "Last fork commit", &tl.last_fork_commit, "");
    if let Some(d) = &tl.last_disk_change {
        let _ = writeln!(
            w,
            "| Last file change (disk) | **{}** | {} — file system date of {} fork file(s), indicative (copying or extracting changes it) |",
            super::graph::when(&d.date),
            code(&d.path),
            d.files
        );
    }
    commit_row(
        w,
        &format!(
            "Latest source commit ({})",
            r.upstream.preferred_branch.as_deref().unwrap_or("?")
        ),
        &tl.source_tip,
        "",
    );
    if let Some(days) = tl.days_of_divergence {
        let _ = writeln!(
            w,
            "| Divergence duration | **{days} day(s)** | between the divergence and the fork's latest known change |"
        );
    }
    if !tl.graph.nodes.is_empty() {
        let _ = writeln!(w, "\n### Divergence graph\n");
        let _ = writeln!(
            w,
            "![Divergence graph between the source and the fork]({})\n",
            super::graph::SVG_FILE
        );
        let _ = writeln!(
            w,
            "<details><summary>Text version of the graph (newest at the top; S = source, F = fork)</summary>\n"
        );
        let _ = writeln!(w, "```text\n{}```\n\n</details>\n", super::graph::ascii(tl));
    }
    if !r.warnings.is_empty() {
        let _ = writeln!(w, "**Avertissements :**\n");
        for x in &r.warnings {
            let _ = writeln!(w, "- ⚠️ {}", x);
        }
        let _ = writeln!(w);
    }

    // 2. Repositories
    let _ = writeln!(w, "## 2. Repository information\n");
    let _ = writeln!(w, "| Item | Value |\n|---|---|");
    let _ = writeln!(w, "| Fork path | {} |", code(&r.client.path));
    let _ = writeln!(w, "| Type | {} |", r.client.mode.label());
    let _ = writeln!(
        w,
        "| Fork HEAD | {} |",
        r.client.head.as_deref().map(code).unwrap_or_else(|| "—".into())
    );
    let _ = writeln!(
        w,
        "| HEAD reference | {} |",
        r.client
            .head_ref
            .as_deref()
            .map(code)
            .unwrap_or_else(|| "detached / —".into())
    );
    let _ = writeln!(
        w,
        "| Shallow repository | {} |",
        if r.client.shallow { "yes" } else { "no" }
    );
    let _ = writeln!(w, "| Fork files analysed | {} |", r.client.files);
    let _ = writeln!(w, "| Source URL | {} |", code(&r.upstream.url));
    let _ = writeln!(
        w,
        "| Source default branch | {} |",
        r.upstream.default_branch.as_deref().unwrap_or("—")
    );
    let _ = writeln!(
        w,
        "| Preferred branch | {} |",
        r.upstream.preferred_branch.as_deref().unwrap_or("—")
    );
    let _ = writeln!(
        w,
        "| Source branches / tags | {} / {} |",
        r.upstream.branches, r.upstream.tags
    );
    if let Some(d) = r.upstream.depth {
        let _ = writeln!(w, "| Fetch depth | {d} |");
    }
    if let Some(h) = &r.history {
        if !h.remotes.is_empty() {
            let rem: Vec<String> = h
                .remotes
                .iter()
                .map(|x| format!("{} → {}", x.name, code(&x.url)))
                .collect();
            let _ = writeln!(w, "| Remotes declared by the fork | {} |", rem.join("<br>"));
        }
        let _ = writeln!(w, "| Fork local branches | {} |", h.branches.len());
        let _ = writeln!(
            w,
            "| Fork tags | {} ({} specific) |",
            h.tags.len(),
            h.tags.iter().filter(|t| !t.matches_upstream).count()
        );
        let _ = writeln!(w, "| Stash entries | {} |", h.stash_entries);
    }
    let _ = writeln!(w);

    // 3. Reference
    let _ = writeln!(w, "## 3. Identified source reference\n");
    let c = &r.reference.commit;
    let _ = writeln!(w, "| Item | Value |\n|---|---|");
    let _ = writeln!(w, "| Commit | {} |", code(&c.hash));
    let _ = writeln!(
        w,
        "| Method | {} |",
        match r.reference.method {
            crate::git::reference::ReferenceMethod::GitAncestry => "Git ancestry (merge-base)",
            crate::git::reference::ReferenceMethod::SnapshotEstimation => "content-based estimation",
        }
    );
    let _ = writeln!(w, "| Commit date | {} |", c.committer_date);
    let _ = writeln!(w, "| Author | {} |", esc(&c.author));
    let _ = writeln!(w, "| Message | {} |", esc(&c.subject));
    let _ = writeln!(
        w,
        "| Branches/tags pointing at this commit | {} |",
        if r.reference.location.pointing_refs.is_empty() {
            "—".into()
        } else {
            esc(&r.reference.location.pointing_refs.join(", "))
        }
    );
    let _ = writeln!(
        w,
        "| Source branches containing it | {} |",
        if r.reference.location.containing_branches.is_empty() {
            "—".into()
        } else {
            esc(&r.reference.location.containing_branches.join(", "))
        }
    );
    let _ = writeln!(
        w,
        "| Closest tag (describe) | {} |",
        r.reference
            .location
            .describe
            .as_deref()
            .map(code)
            .unwrap_or_else(|| "—".into())
    );
    let _ = writeln!(
        w,
        "| First tag containing this commit | {} |",
        r.reference
            .location
            .first_tag_containing
            .as_deref()
            .map(code)
            .unwrap_or_else(|| "—".into())
    );
    if let Some(f) = &r.reference.fork_point {
        let _ = writeln!(
            w,
            "| Initial starting point of the fork | {} ({}) — {} |",
            code(&f.short),
            f.committer_date,
            esc(&f.subject)
        );
    }
    let _ = writeln!(w);
    if let Some(init) = &r.reference.estimated_initial_base {
        let _ = writeln!(
            w,
            "**Estimated starting point of the rewritten history** (tree of the fork's first commit): `{}` ({}) — confidence {:.0} % ({}). Estimate, not certain.\n",
            init.commit.short,
            init.location.pointing_refs.join(", "),
            init.confidence,
            init.confidence_level
        );
    }

    // 4. Confidence
    let _ = writeln!(w, "## 4. Confidence level\n");
    let _ = writeln!(
        w,
        "**{:.0} % — {}**\n",
        r.reference.confidence, r.reference.confidence_level
    );
    if r.reference.certainty == Certainty::Estimated {
        let _ = writeln!(
            w,
            "> ⚠️ This commit is an **estimate**: it must not be presented as the reference the fork certainly used.\n"
        );
    }
    let _ = writeln!(w, "Reasons:\n");
    for x in &r.reference.reasons {
        let _ = writeln!(w, "- {}", x);
    }
    for x in &r.reference.warnings {
        let _ = writeln!(w, "- ⚠️ {}", x);
    }
    if !r.reference.candidates.is_empty() {
        let _ = writeln!(w, "\nEvaluated candidates:\n");
        let _ = writeln!(w, "| Commit | Refs | Score | Identical | Modified | Added | Deleted | Content similarity |\n|---|---|---|---|---|---|---|---|");
        for cand in &r.reference.candidates {
            let _ = writeln!(
                w,
                "| `{}` | {} | {:.4} | {} | {} | {} | {} | {} |",
                short(&cand.commit),
                esc(&cand.refs.join(", ")),
                cand.score,
                cand.identical,
                cand.modified,
                cand.added,
                cand.deleted,
                cand.content_similarity
                    .map(|s| format!("{:.1} %", s * 100.0))
                    .unwrap_or_else(|| "—".into())
            );
        }
    }
    if !r.reference.equivalent_commits.is_empty() {
        let eq: Vec<String> = r
            .reference
            .equivalent_commits
            .iter()
            .take(20)
            .map(|c| format!("`{}`", short(c)))
            .collect();
        let _ = writeln!(
            w,
            "\nCommits indistinguishable from the selected one: {}",
            eq.join(", ")
        );
    }
    let _ = writeln!(w);

    // 5. History
    let _ = writeln!(w, "## 5. Fork-specific commit history\n");
    match &r.history {
        None => {
            let _ = writeln!(w, "_No usable Git history in the fork._\n");
        }
        Some(h) => {
            let _ = writeln!(
                w,
                "- Specific commits: **{}** ({} merges){}",
                h.client_commits_total,
                h.merge_commits,
                if h.truncated { " — truncated list" } else { "" }
            );
            if h.mode == crate::git::history::HistoryMode::Ancestry {
                let _ = writeln!(
                    w,
                    "- Source commits present in the fork history: {}",
                    h.upstream_commits_in_client
                );
                let _ = writeln!(
                    w,
                    "- Source commits integrated since the fork's starting point: {}",
                    h.upstream_integrated_since_fork
                );
                if !h.upstream_merges.is_empty() {
                    let _ = writeln!(
                        w,
                        "- Fork merges integrating the source: {}",
                        commit_links(&h.upstream_merges)
                    );
                }
            } else {
                let _ = writeln!(
                    w,
                    "- ⚠️ Rewritten history: no commit is shared with the source; every fork commit is listed."
                );
            }
            for b in &h.behind {
                let _ = writeln!(
                    w,
                    "- Behind `{}`: {} source commit(s) not integrated",
                    b.branch, b.commits_behind
                );
            }
            for x in &h.rebase_indicators {
                let _ = writeln!(w, "- Rewrite hint: {}", x);
            }
            for x in &h.warnings {
                let _ = writeln!(w, "- ⚠️ {}", x);
            }
            let _ = writeln!(w);
            if !h.client_commits.is_empty() {
                let _ = writeln!(w, "| Commit | Date | Author | Message | Files | +/− | Parents | Finding |\n|---|---|---|---|---|---|---|---|");
                for c in h.client_commits.iter().take(MAX_ROWS) {
                    let alert = c
                        .max_severity
                        .map(|s| {
                            let cats: Vec<&str> = c
                                .suspicious
                                .iter()
                                .map(|x| x.category.label())
                                .collect::<std::collections::BTreeSet<_>>()
                                .into_iter()
                                .collect();
                            format!("**{}** ({})", s.label(), cats.join(", "))
                        })
                        .unwrap_or_else(|| "—".into());
                    let _ = writeln!(
                        w,
                        "| `{}`{} | {} | {} | {} | {} | +{} / −{} | {} | {} |",
                        c.short,
                        if c.is_merge { " (merge)" } else { "" },
                        c.author_date,
                        esc(&c.author),
                        esc(&crate::utils::truncate(&c.subject, 90)),
                        c.files_changed,
                        c.insertions,
                        c.deletions,
                        c.parents
                            .iter()
                            .map(|p| format!("`{}`", short(p)))
                            .collect::<Vec<_>>()
                            .join(" "),
                        alert
                    );
                }
                if h.client_commits.len() > MAX_ROWS {
                    let _ = writeln!(
                        w,
                        "\n_… {} more commits in the JSON report._",
                        h.client_commits.len() - MAX_ROWS
                    );
                }
                let suspicious: Vec<_> = h.client_commits.iter().filter(|c| !c.suspicious.is_empty()).collect();
                if !suspicious.is_empty() {
                    let _ = writeln!(w, "\n### Suspicious commits\n");
                    for c in suspicious.iter().take(100) {
                        let _ = writeln!(w, "- **`{}`** {} — {}", c.short, esc(&c.subject), esc(&c.author));
                        for x in c.suspicious.iter().take(8) {
                            let _ = writeln!(
                                w,
                                "  - [{}] {}: {}",
                                x.severity.label(),
                                x.category.label(),
                                esc(&x.detail)
                            );
                        }
                    }
                }
            }
            if !h.patch_matches.is_empty() {
                let _ = writeln!(w, "\n### Source commits kept, modified or reverted (patch-id)\n");
                let _ = writeln!(
                    w,
                    "| Type | Fork commit | Source commit | Source message | Evidence |\n|---|---|---|---|---|"
                );
                for m in h.patch_matches.iter().take(MAX_ROWS) {
                    let _ = writeln!(
                        w,
                        "| {} | `{}` | `{}` | {} | {} |",
                        m.kind.label(),
                        short(&m.client_commit),
                        short(&m.upstream_commit),
                        esc(&m.upstream_subject),
                        esc(&m.evidence)
                    );
                }
            }
            let divergent: Vec<_> = h.branches.iter().filter(|b| b.divergent).collect();
            if !divergent.is_empty() {
                let _ = writeln!(w, "\n### Divergent branches\n");
                let _ = writeln!(
                    w,
                    "| Branch | Commit | Commits not in source | Commits not in HEAD |\n|---|---|---|---|"
                );
                for b in divergent {
                    let _ = writeln!(
                        w,
                        "| `{}` | `{}` | {} | {} |",
                        b.name,
                        short(&b.commit),
                        b.commits_not_upstream,
                        b.commits_not_in_head
                    );
                }
            }
            let specific_tags: Vec<_> = h.tags.iter().filter(|t| !t.matches_upstream).collect();
            if !specific_tags.is_empty() {
                let tags: Vec<String> = specific_tags
                    .iter()
                    .take(30)
                    .map(|t| format!("`{}` → `{}`", t.name, short(&t.commit)))
                    .collect();
                let _ = writeln!(w, "\nFork-specific tags: {}", tags.join(", "));
            }
            let wt = &h.working_tree;
            if wt.available {
                let _ = writeln!(w, "\n### Uncommitted changes\n");
                if let Some(n) = &wt.note {
                    let _ = writeln!(w, "_{}_\n", n);
                }
                if wt.is_clean() && wt.ignored.is_empty() {
                    let _ = writeln!(w, "Clean working tree.");
                }
                for e in wt.staged.iter().take(MAX_ROWS) {
                    let _ = writeln!(w, "- staged ({}): {}", e.change, code(&e.path));
                }
                for e in wt.unstaged.iter().take(MAX_ROWS) {
                    let _ = writeln!(w, "- unstaged ({}): {}", e.change, code(&e.path));
                }
                for p in wt.untracked.iter().take(MAX_ROWS) {
                    let _ = writeln!(w, "- untracked: {}", code(p));
                }
                for p in wt.ignored.iter().take(MAX_ROWS) {
                    let _ = writeln!(w, "- ignored by .gitignore (present on disk): {}", code(p));
                }
            }
            if !h.upstream_security_hints.is_empty() {
                let _ = writeln!(w, "\n### Potentially missing source fixes\n");
                let _ = writeln!(w, "_Hint based on commit messages (not reliable)._\n");
                for c in &h.upstream_security_hints {
                    let _ = writeln!(w, "- `{}` ({}) {}", short(&c.hash), c.date, esc(&c.subject));
                }
            }
            let _ = writeln!(w);
        }
    }

    // 6. Statistics
    let _ = writeln!(w, "## 6. Global diff statistics\n");
    let _ = writeln!(
        w,
        "Comparison: reference `{}` ↔ current fork content (including uncommitted changes).\n",
        r.reference.commit.short
    );
    let _ = writeln!(w, "| Metric | Value |\n|---|---|");
    for (k, v) in [
        ("Files (reference)", st.files_reference),
        ("Files (fork)", st.files_client),
        ("Identical", st.identical),
        ("Added", st.added),
        ("Deleted", st.deleted),
        ("Modified", st.modified),
        ("Renamed", st.renamed),
        ("Moved", st.moved),
        ("Binaries changed", st.binary_changed),
        ("Line endings only", st.eol_only),
        ("Lines added", st.lines_added),
        ("Lines removed", st.lines_removed),
    ] {
        let _ = writeln!(w, "| {k} | {v} |");
    }
    let _ = writeln!(w);

    // Origin and list of changed files
    let _ = writeln!(w, "### Origin of changes\n");
    let _ = writeln!(
        w,
        "A file that differs from the reference was not necessarily written by the fork: its content may be identical to another source version (backport, cherry-pick, rollback). The main criterion is content identity (Git blob) with the source history, then the fork commits.\n"
    );
    if r.history.is_none() {
        let _ = writeln!(
            w,
            "_Without Git history, files with no equivalent in the source are presumed modified by the fork._\n"
        );
    }
    let _ = writeln!(w, "| Origin | Files |\n|---|---|");
    for o in crate::diff::ChangeOrigin::ALL {
        let n = st.by_origin.get(&o).copied().unwrap_or(0);
        if n > 0 {
            let _ = writeln!(w, "| {} | {} |", o.label(), n);
        }
    }
    let _ = writeln!(w, "\n### Changed files\n");
    let _ = writeln!(w, "Full list also available in [`changed-files.txt`](changed-files.txt) and [`changed-files.csv`](changed-files.csv).\n");
    let mut listed: Vec<&FileChange> = r.diff.files.iter().collect();
    listed.sort_by(|a, b| {
        b.origin
            .is_client()
            .cmp(&a.origin.is_client())
            .then(a.path.cmp(&b.path))
    });
    if listed.is_empty() {
        let _ = writeln!(w, "_No changed file._\n");
    } else {
        let _ = writeln!(
            w,
            "| Status | File | Origin | +/− | Fork commits | Diff |\n|---|---|---|---|---|---|"
        );
        for c in listed.iter().take(MAX_ROWS * 2) {
            let name = match &c.old_path {
                Some(o) => format!("{} ← {}", code(&c.path), code(o)),
                None => code(&c.path),
            };
            let origin = match &c.upstream_commit {
                Some(u) => format!("{} (`{}`)", c.origin.label(), short(u)),
                None => c.origin.label().to_string(),
            };
            let _ = writeln!(
                w,
                "| {} {} | {} | {} | +{} / −{} | {} | {} |",
                super::status_letter(c.status),
                c.status.label(),
                name,
                origin,
                c.lines_added,
                c.lines_removed,
                commit_links(&c.commits),
                diff_link(c)
            );
        }
        if listed.len() > MAX_ROWS * 2 {
            let _ = writeln!(
                w,
                "\n_… {} more files in changed-files.txt._",
                listed.len() - MAX_ROWS * 2
            );
        }
        let _ = writeln!(w);
    }

    let section = |w: &mut String, title: &str, filter: &dyn Fn(&FileChange) -> bool, show_sim: bool| {
        let files: Vec<&FileChange> = r.diff.files.iter().filter(|c| filter(c)).collect();
        let _ = writeln!(w, "{title}\n");
        if files.is_empty() {
            let _ = writeln!(w, "_None._\n");
            return;
        }
        if show_sim {
            let _ = writeln!(w, "| File | Status | Origin | +/− | Similarity | SHA-256 before → after | Commits | Diff |\n|---|---|---|---|---|---|---|---|");
        } else {
            let _ = writeln!(
                w,
                "| File | Origin | Size | Lines | SHA-256 | Commits | Diff |\n|---|---|---|---|---|---|---|"
            );
        }
        for c in files.iter().take(MAX_ROWS) {
            let mut name = code(&c.path);
            if let Some(o) = &c.old_path {
                name = format!("{} ← {}", name, code(o));
            }
            let mut flags = Vec::new();
            if c.is_binary {
                flags.push("binary");
            }
            if c.eol_only {
                flags.push("line endings");
            }
            if c.too_large {
                flags.push("large");
            }
            if c.mode_changed {
                flags.push("mode");
            }
            if c.untracked {
                flags.push("untracked");
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" _({})_", flags.join(", "))
            };
            if show_sim {
                let _ = writeln!(
                    w,
                    "| {}{} | {} | {} | +{} / −{} | {} | `{}` → `{}` | {} | {} |",
                    name,
                    flags,
                    c.status.label(),
                    c.origin.label(),
                    c.lines_added,
                    c.lines_removed,
                    c.similarity
                        .map(|s| format!("{:.1} %", s * 100.0))
                        .unwrap_or_else(|| "—".into()),
                    c.old_sha256.as_deref().map(|h| &h[..12]).unwrap_or("—"),
                    c.new_sha256.as_deref().map(|h| &h[..12]).unwrap_or("—"),
                    commit_links(&c.commits),
                    diff_link(c)
                );
            } else {
                let size = c.new_size.or(c.old_size).unwrap_or(0);
                let lines = c.lines_added.max(c.lines_removed);
                let hash = c
                    .new_sha256
                    .as_deref()
                    .or(c.old_sha256.as_deref())
                    .map(|h| &h[..12])
                    .unwrap_or("—");
                let _ = writeln!(
                    w,
                    "| {}{} | {} | {} o | {} | `{}` | {} | {} |",
                    name,
                    flags,
                    c.origin.label(),
                    size,
                    lines,
                    hash,
                    commit_links(&c.commits),
                    diff_link(c)
                );
            }
        }
        if files.len() > MAX_ROWS {
            let _ = writeln!(w, "\n_… {} more files in the JSON report._", files.len() - MAX_ROWS);
        }
        let _ = writeln!(w);
    };
    section(w, "## 7. Added files", &|c| c.status == ChangeStatus::Added, false);
    section(w, "## 8. Deleted files", &|c| c.status == ChangeStatus::Deleted, false);
    section(
        w,
        "## 9. Modified files (including renamed and moved)",
        &|c| {
            matches!(
                c.status,
                ChangeStatus::Modified | ChangeStatus::Renamed | ChangeStatus::Moved
            )
        },
        true,
    );
    if r.options.full_diff {
        let _ = writeln!(w, "### Full diffs\n");
        for c in r.diff.files.iter().filter(|c| !c.hunks.is_empty()) {
            let old = if c.status == ChangeStatus::Added {
                None
            } else {
                Some(c.old_path.as_deref().unwrap_or(&c.path))
            };
            let new = if c.status == ChangeStatus::Deleted {
                None
            } else {
                Some(c.path.as_str())
            };
            let _ = writeln!(w, "#### {}\n", code(&c.path));
            let _ = writeln!(w, "{}", fence(render_unified(old, new, &c.hunks).trim_end(), "diff"));
        }
    }

    // 10. Sensitive changes
    let _ = writeln!(w, "## 10. Sensitive changes\n");
    if r.security.findings.is_empty() {
        let _ = writeln!(w, "_No finding._\n");
    } else {
        let _ = writeln!(w, "| ID | Severity | Confidence | Category | File | Line | Change | Title |\n|---|---|---|---|---|---|---|---|");
        for f in r.security.findings.iter().take(MAX_ROWS) {
            let _ = writeln!(
                w,
                "| [{}](#{}) | {} | {} | {} | {} | {} | {} | {} |",
                f.id,
                f.id.to_lowercase(),
                f.severity.label(),
                f.confidence.label(),
                f.category.label(),
                code(&f.file),
                f.line
                    .map(|l| l.to_string())
                    .or(f.old_line.map(|l| format!("ref. {l}")))
                    .unwrap_or_else(|| "—".into()),
                f.change,
                esc(&f.title)
            );
        }
        let _ = writeln!(w);
        for f in r
            .security
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Low)
            .take(200)
        {
            let _ = writeln!(w, "### {}\n", f.id);
            let _ = writeln!(
                w,
                "**{}** — {} / confidence {} — rule `{}` ({})\n",
                esc(&f.title),
                f.severity.label(),
                f.confidence.label(),
                f.rule_id,
                f.source
            );
            let loc = match (f.old_line, f.line) {
                (Some(o), Some(n)) if o != n => format!(" (line {o} → {n})"),
                (_, Some(n)) => format!(" (line {n})"),
                (Some(o), None) => format!(" (line {o} of the reference)"),
                _ => String::new(),
            };
            let _ = writeln!(w, "- File: {}{}", code(&f.file), loc);
            let _ = writeln!(w, "- Change: {}", f.change);
            if !f.commits.is_empty() {
                let _ = writeln!(w, "- Commits: {}", commit_links(&f.commits));
            } else if r.history.is_some() {
                let _ = writeln!(w, "- Commits: none (uncommitted change or untracked file)");
            }
            if let Some(d) = r
                .diff
                .files
                .iter()
                .find(|c| c.path == f.file)
                .and_then(|c| c.diff_file.as_ref())
            {
                let _ = writeln!(w, "- Diff: [{}]({})", d, d.replace(' ', "%20"));
            }
            let _ = writeln!(w, "- Justification: {}\n", f.justification);
            if let Some(o) = &f.old_code {
                let _ = writeln!(w, "Old code:\n\n{}", fence(o, ""));
            }
            if let Some(n) = &f.new_code {
                let _ = writeln!(w, "New code:\n\n{}", fence(n, ""));
            }
        }
        let info = r
            .security
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
        if info > 0 {
            let _ = writeln!(w, "_{} Info-level finding(s) listed only in the table above._\n", info);
        }
    }

    // 11. Dependencies
    let _ = writeln!(w, "## 11. Dependency analysis\n");
    if r.dependencies.manifests.is_empty() {
        let _ = writeln!(w, "_No dependency file changed._\n");
    }
    for m in &r.dependencies.manifests {
        let _ = writeln!(
            w,
            "### {} ({}, {}, file {})\n",
            code(&m.path),
            m.ecosystem,
            if m.lockfile { "lockfile" } else { "manifest" },
            m.status.label()
        );
        if let Some(e) = &m.parse_error {
            let _ = writeln!(w, "⚠️ {}\n", esc(e));
        }
        if m.changes.is_empty() {
            let _ = writeln!(w, "_No dependency change detected._\n");
            continue;
        }
        let _ = writeln!(
            w,
            "| Dependency | Scope | Change | Before | After | External |\n|---|---|---|---|---|---|"
        );
        for c in m.changes.iter().take(MAX_ROWS) {
            let fmt = |v: &Option<String>, s: &Option<String>| -> String {
                match (v, s) {
                    (None, None) => "—".into(),
                    (Some(v), None) => code(v),
                    (None, Some(s)) => code(s),
                    (Some(v), Some(s)) => format!("{} ({})", code(v), code(s)),
                }
            };
            let _ = writeln!(
                w,
                "| {} | {} | {} | {} | {} | {} |",
                code(&c.name),
                c.scope,
                c.kind.label(),
                fmt(&c.old_version, &c.old_source),
                fmt(&c.new_version, &c.new_source),
                if c.external { "⚠️ yes" } else { "no" }
            );
        }
        if m.changes.len() > MAX_ROWS {
            let _ = writeln!(
                w,
                "\n_… {} more changes in the JSON report._",
                m.changes.len() - MAX_ROWS
            );
        }
        let _ = writeln!(w);
    }

    // 12. Secrets
    let _ = writeln!(w, "## 12. Potential secrets\n");
    if r.secrets.is_empty() {
        let _ = writeln!(w, "_No secret detected in the fork's additions._\n");
    } else {
        let _ = writeln!(
            w,
            "_Values are masked. Test and example files are not considered safe._\n"
        );
        let _ = writeln!(w, "| ID | Severity | Confidence | Type | File | Line | Masked value | Test/example | Commits |\n|---|---|---|---|---|---|---|---|---|");
        for s in r.secrets.iter().take(MAX_ROWS) {
            let _ = writeln!(
                w,
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                s.id,
                s.severity.label(),
                s.confidence.label(),
                esc(&s.description),
                code(&s.file),
                s.line.map(|l| l.to_string()).unwrap_or_else(|| "—".into()),
                code(&s.masked_value),
                if s.in_test_or_example { "yes" } else { "no" },
                commit_links(&s.commits)
            );
        }
        let _ = writeln!(w);
    }

    // 13. Recommendations
    let _ = writeln!(w, "## 13. Investigation recommendations\n");
    for (i, x) in r.recommendations.iter().enumerate() {
        let _ = writeln!(w, "{}. {}", i + 1, x);
    }
    let _ = writeln!(w, "\n---\n_Report generated by ForkScope. No data was sent to any external service; the fork's code was not executed._");
    s
}
