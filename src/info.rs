//! `info` command: quick information about a local or remote repository.

use crate::config::Config;
use crate::diff::files::{snapshot_directory, PathFilter};
use crate::git::reference::display_ref;
use crate::git::repository::{exec, fetch_client, git_command, inspect_client, TempRepo};
use crate::git::upstream::{explain_fetch_error, normalize_source, redact_url, remote_default_branch};
use anyhow::{bail, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct RepoInfo {
    pub target: String,
    pub kind: String,
    pub is_git: bool,
    pub head: Option<String>,
    pub head_ref: Option<String>,
    pub shallow: bool,
    pub default_branch: Option<String>,
    pub branches: Vec<String>,
    pub tags: Vec<String>,
    pub remotes: Vec<(String, String)>,
    pub commits: Option<usize>,
    pub files: Option<usize>,
    pub size_bytes: Option<u64>,
    pub stash: bool,
}

/// Collects the information of a repository (local path or URL).
pub fn collect(target: &str) -> Result<RepoInfo> {
    let path = Path::new(target);
    if path.is_dir() {
        let root = path.canonicalize()?;
        let layout = inspect_client(&root)?;
        let (snap, _) = snapshot_directory(&root, &PathFilter::from_config(&Config::default())?)?;
        let mut info = RepoInfo {
            target: root.display().to_string(),
            kind: "local".into(),
            is_git: layout.is_git(),
            head: None,
            head_ref: layout.head_ref.clone(),
            shallow: layout.shallow,
            default_branch: None,
            branches: vec![],
            tags: vec![],
            remotes: layout.remotes.clone(),
            commits: None,
            files: Some(snap.files().count()),
            size_bytes: Some(snap.files().filter_map(|e| e.size).sum()),
            stash: false,
        };
        if layout.is_git() {
            let repo = TempRepo::new()?;
            let f = fetch_client(&repo, &layout)?;
            info.head = f.head.clone();
            if let Some(h) = &f.head {
                info.commits = Some(repo.count(&[h])?);
            }
            info.branches = repo
                .refs(&["refs/client/heads"])?
                .into_iter()
                .map(|r| r.name.trim_start_matches("refs/client/heads/").to_string())
                .collect();
            info.tags = repo
                .refs(&["refs/client/tags"])?
                .into_iter()
                .map(|r| r.name.trim_start_matches("refs/client/tags/").to_string())
                .collect();
            info.stash = repo.resolve_commit("refs/client/stash")?.is_some();
        }
        return Ok(info);
    }
    let src = normalize_source(target);
    let mut cmd = git_command();
    cmd.args(["ls-remote", "--heads", "--tags", &src]);
    let out = exec(cmd, None)?;
    if !out.status.success() {
        bail!("{}", explain_fetch_error(&String::from_utf8_lossy(&out.stderr)));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut branches = Vec::new();
    let mut tags = Vec::new();
    for l in text.lines() {
        let Some((_, r)) = l.split_once('\t') else { continue };
        if let Some(b) = r.strip_prefix("refs/heads/") {
            branches.push(b.to_string());
        } else if let Some(t) = r.strip_prefix("refs/tags/") {
            if !t.ends_with("^{}") {
                tags.push(t.to_string());
            }
        }
    }
    Ok(RepoInfo {
        target: redact_url(target),
        kind: "remote".into(),
        is_git: true,
        head: None,
        head_ref: None,
        shallow: false,
        default_branch: remote_default_branch(&src),
        branches,
        tags,
        remotes: vec![],
        commits: None,
        files: None,
        size_bytes: None,
        stash: false,
    })
}

/// Console output.
pub fn print(info: &RepoInfo) {
    use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec!["Item", "Value"]);
    let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "—".into());
    t.add_row(vec!["Target".into(), info.target.clone()]);
    t.add_row(vec![
        "Type".into(),
        format!("{}{}", info.kind, if info.is_git { " (Git)" } else { " (no Git)" }),
    ]);
    if info.kind == "local" {
        t.add_row(vec!["HEAD".into(), opt(&info.head)]);
        t.add_row(vec!["HEAD reference".into(), opt(&info.head_ref)]);
        t.add_row(vec![
            "Shallow".to_string(),
            if info.shallow { "yes" } else { "no" }.to_string(),
        ]);
        t.add_row(vec![
            "Commits (HEAD)".into(),
            info.commits.map(|c| c.to_string()).unwrap_or_else(|| "—".into()),
        ]);
        t.add_row(vec![
            "Files (excluding exclusions)".into(),
            info.files.map(|c| c.to_string()).unwrap_or_default(),
        ]);
        t.add_row(vec![
            "Size".into(),
            info.size_bytes
                .map(|s| format!("{:.1} Mio", s as f64 / 1_048_576.0))
                .unwrap_or_default(),
        ]);
        t.add_row(vec![
            "Stash".to_string(),
            if info.stash { "yes" } else { "no" }.to_string(),
        ]);
        let remotes: Vec<String> = info.remotes.iter().map(|(n, u)| format!("{n} → {u}")).collect();
        t.add_row(vec![
            "Remotes".into(),
            if remotes.is_empty() {
                "—".into()
            } else {
                remotes.join("\n")
            },
        ]);
    } else {
        t.add_row(vec!["Default branch".into(), opt(&info.default_branch)]);
    }
    let list = |v: &Vec<String>| {
        if v.is_empty() {
            "—".to_string()
        } else if v.len() > 15 {
            format!("{} (+{} more)", v[..15].join(", "), v.len() - 15)
        } else {
            v.join(", ")
        }
    };
    t.add_row(vec![
        format!("Branches ({})", info.branches.len()),
        list(&info.branches),
    ]);
    t.add_row(vec![format!("Tags ({})", info.tags.len()), list(&info.tags)]);
    println!("{t}");
    let _ = display_ref("");
}
