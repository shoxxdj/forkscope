//! Exhaustive comparison of two snapshots (source reference / fork).

use super::files::{ContentProvider, EntryKind, Snapshot, SnapshotEntry};
use super::similarity::{build_hunks, similarity, whole_file_hunk};
use super::{ChangeStatus, FileChange};
use crate::config::DiffConfig;
use crate::utils::{basename, dirname, extension, hashing::sha256_hex, is_binary, to_normalized_text};
use anyhow::Result;
use rayon::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Global diff statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DiffStats {
    pub files_reference: usize,
    pub files_client: usize,
    pub identical: usize,
    pub added: usize,
    pub deleted: usize,
    pub modified: usize,
    pub renamed: usize,
    pub moved: usize,
    pub binary_changed: usize,
    pub eol_only: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
    /// Number of differing files per origin.
    #[serde(default)]
    pub by_origin: std::collections::BTreeMap<super::ChangeOrigin, usize>,
    /// Differing files attributable to the fork (fork, uncommitted, undetermined).
    #[serde(default, rename = "fork_changes")]
    pub client_changes: usize,
}

/// Comparison result.
#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    /// Differing files (added, deleted, modified, renamed, moved).
    pub changes: Vec<FileChange>,
    /// Identical paths.
    pub identical: Vec<String>,
    pub stats: DiffStats,
}

/// Compares the reference (`reference`) and the fork (`client`).
pub fn compare(
    reference: &Snapshot,
    ref_src: &dyn ContentProvider,
    client: &Snapshot,
    client_src: &dyn ContentProvider,
    cfg: &DiffConfig,
) -> Result<DiffResult> {
    let mut identical = Vec::new();
    let mut modified: Vec<(&SnapshotEntry, &SnapshotEntry)> = Vec::new();
    let mut deleted: Vec<&SnapshotEntry> = Vec::new();
    let mut added: Vec<&SnapshotEntry> = Vec::new();

    for (path, r) in &reference.entries {
        match client.entries.get(path) {
            Some(c) => {
                if r.kind == EntryKind::Submodule || c.kind == EntryKind::Submodule {
                    identical.push(path.clone());
                } else if r.oid == c.oid {
                    if r.kind == c.kind {
                        identical.push(path.clone());
                    } else {
                        modified.push((r, c));
                    }
                } else {
                    modified.push((r, c));
                }
            }
            None if r.kind != EntryKind::Submodule => deleted.push(r),
            None => {}
        }
    }
    for (path, c) in &client.entries {
        if !reference.entries.contains_key(path) && c.kind != EntryKind::Submodule {
            added.push(c);
        }
    }

    // 1) Exact renames (same content, different path).
    let mut pairs: Vec<(&SnapshotEntry, &SnapshotEntry, f64)> = Vec::new();
    {
        let mut by_oid: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, d) in deleted.iter().enumerate() {
            if d.size.unwrap_or(1) > 0 {
                by_oid.entry(d.oid.as_str()).or_default().push(i);
            }
        }
        let mut used_del = HashSet::new();
        let mut used_add = HashSet::new();
        for (ai, a) in added.iter().enumerate() {
            let Some(cands) = by_oid.get(a.oid.as_str()) else {
                continue;
            };
            let free: Vec<usize> = cands.iter().copied().filter(|i| !used_del.contains(i)).collect();
            let pick = free
                .iter()
                .copied()
                .find(|&i| basename(&deleted[i].path) == basename(&a.path))
                .or_else(|| free.first().copied());
            if let Some(di) = pick {
                used_del.insert(di);
                used_add.insert(ai);
                pairs.push((deleted[di], a, 1.0));
            }
        }
        deleted = deleted
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !used_del.contains(i))
            .map(|(_, d)| d)
            .collect();
        added = added
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !used_add.contains(i))
            .map(|(_, a)| a)
            .collect();
    }

    // 2) Load the required contents.
    let mut need_ref: Vec<&SnapshotEntry> = modified.iter().map(|(r, _)| *r).collect();
    need_ref.extend(deleted.iter().copied());
    let mut need_client: Vec<&SnapshotEntry> = modified.iter().map(|(_, c)| *c).collect();
    need_client.extend(added.iter().copied());
    need_client.extend(pairs.iter().map(|(_, a, _)| *a));
    let ref_content = ref_src.load(&need_ref)?;
    let client_content = client_src.load(&need_client)?;

    // 3) Approximate renames (content similarity).
    let similar_pairs = detect_similar_renames(&deleted, &added, &ref_content, &client_content, cfg);
    if !similar_pairs.is_empty() {
        let used_del: HashSet<&str> = similar_pairs.iter().map(|(d, _, _)| d.path.as_str()).collect();
        let used_add: HashSet<&str> = similar_pairs.iter().map(|(_, a, _)| a.path.as_str()).collect();
        deleted.retain(|d| !used_del.contains(d.path.as_str()));
        added.retain(|a| !used_add.contains(a.path.as_str()));
        pairs.extend(similar_pairs);
    }

    // 4) Build the FileChanges (in parallel).
    let empty: Vec<u8> = Vec::new();
    let ctx = cfg.context_lines;
    let max = cfg.max_text_size;
    let mut changes: Vec<FileChange> = Vec::new();

    changes.par_extend(modified.par_iter().map(|(r, c)| {
        let old = ref_content.get(&r.path).unwrap_or(&empty);
        let new = client_content.get(&c.path).unwrap_or(&empty);
        let mut fc = FileChange::new(c.path.clone(), ChangeStatus::Modified);
        fc.mode_changed = r.kind != c.kind;
        fill_content_diff(&mut fc, Some(old), Some(new), ctx, max);
        fc
    }));
    changes.par_extend(pairs.par_iter().map(|(d, a, _)| {
        let status = if basename(&d.path) == basename(&a.path) && dirname(&d.path) != dirname(&a.path) {
            ChangeStatus::Moved
        } else {
            ChangeStatus::Renamed
        };
        let mut fc = FileChange::new(a.path.clone(), status);
        fc.old_path = Some(d.path.clone());
        fc.mode_changed = d.kind != a.kind;
        let new = client_content.get(&a.path).unwrap_or(&empty);
        if d.oid == a.oid {
            fill_identical(&mut fc, new);
        } else {
            let old = ref_content.get(&d.path).unwrap_or(&empty);
            fill_content_diff(&mut fc, Some(old), Some(new), ctx, max);
        }
        fc
    }));
    changes.par_extend(added.par_iter().map(|a| {
        let mut fc = FileChange::new(a.path.clone(), ChangeStatus::Added);
        let new = client_content.get(&a.path).unwrap_or(&empty);
        fill_content_diff(&mut fc, None, Some(new), ctx, max);
        fc
    }));
    changes.par_extend(deleted.par_iter().map(|d| {
        let mut fc = FileChange::new(d.path.clone(), ChangeStatus::Deleted);
        let old = ref_content.get(&d.path).unwrap_or(&empty);
        fill_content_diff(&mut fc, Some(old), None, ctx, max);
        fc
    }));
    changes.sort_by(|a, b| a.path.cmp(&b.path));

    let mut stats = DiffStats {
        files_reference: reference.files().count(),
        files_client: client.files().count(),
        identical: identical.len(),
        ..Default::default()
    };
    for c in &changes {
        match c.status {
            ChangeStatus::Added => stats.added += 1,
            ChangeStatus::Deleted => stats.deleted += 1,
            ChangeStatus::Modified => stats.modified += 1,
            ChangeStatus::Renamed => stats.renamed += 1,
            ChangeStatus::Moved => stats.moved += 1,
            ChangeStatus::Identical => {}
        }
        if c.is_binary {
            stats.binary_changed += 1;
        }
        if c.eol_only {
            stats.eol_only += 1;
        }
        stats.lines_added += c.lines_added;
        stats.lines_removed += c.lines_removed;
    }
    Ok(DiffResult {
        changes,
        identical,
        stats,
    })
}

fn fill_identical(fc: &mut FileChange, data: &[u8]) {
    let h = sha256_hex(data);
    fc.is_binary = is_binary(data);
    fc.old_size = Some(data.len() as u64);
    fc.new_size = Some(data.len() as u64);
    fc.old_sha256 = Some(h.clone());
    fc.new_sha256 = Some(h);
    fc.similarity = Some(1.0);
}

/// Fills hashes, statistics and hunks of a content change.
fn fill_content_diff(fc: &mut FileChange, old: Option<&Vec<u8>>, new: Option<&Vec<u8>>, ctx: usize, max: u64) {
    fc.old_size = old.map(|d| d.len() as u64);
    fc.new_size = new.map(|d| d.len() as u64);
    fc.old_sha256 = old.map(|d| sha256_hex(d));
    fc.new_sha256 = new.map(|d| sha256_hex(d));
    fc.is_binary = old.map(|d| is_binary(d)).unwrap_or(false) || new.map(|d| is_binary(d)).unwrap_or(false);
    if fc.is_binary {
        if old.is_some() && new.is_some() {
            fc.similarity = Some(0.0);
        }
        return;
    }
    let too_large =
        old.map(|d| d.len() as u64 > max).unwrap_or(false) || new.map(|d| d.len() as u64 > max).unwrap_or(false);
    if too_large {
        fc.too_large = true;
        return;
    }
    match (old, new) {
        (Some(o), Some(n)) => {
            let (ot, nt) = (to_normalized_text(o), to_normalized_text(n));
            if ot == nt {
                fc.eol_only = true;
                fc.similarity = Some(1.0);
                return;
            }
            let (hunks, a, r) = build_hunks(&ot, &nt, ctx);
            fc.hunks = hunks;
            fc.lines_added = a;
            fc.lines_removed = r;
            fc.similarity = Some(similarity(&ot, &nt));
        }
        (None, Some(n)) => {
            let (hunks, a) = whole_file_hunk(&to_normalized_text(n), true);
            fc.hunks = hunks;
            fc.lines_added = a;
        }
        (Some(o), None) => {
            let (hunks, r) = whole_file_hunk(&to_normalized_text(o), false);
            fc.hunks = hunks;
            fc.lines_removed = r;
        }
        (None, None) => {}
    }
}

/// Detects approximate renames between deleted and added files.
fn detect_similar_renames<'a>(
    deleted: &[&'a SnapshotEntry],
    added: &[&'a SnapshotEntry],
    ref_content: &HashMap<String, Vec<u8>>,
    client_content: &HashMap<String, Vec<u8>>,
    cfg: &DiffConfig,
) -> Vec<(&'a SnapshotEntry, &'a SnapshotEntry, f64)> {
    let text = |m: &HashMap<String, Vec<u8>>, p: &str| -> Option<String> {
        let d = m.get(p)?;
        if d.is_empty() || is_binary(d) || d.len() as u64 > cfg.max_text_size {
            None
        } else {
            Some(to_normalized_text(d))
        }
    };
    let dels: Vec<(&SnapshotEntry, String)> = deleted
        .iter()
        .filter_map(|d| text(ref_content, &d.path).map(|t| (*d, t)))
        .collect();
    let adds: Vec<(&SnapshotEntry, String)> = added
        .iter()
        .filter_map(|a| text(client_content, &a.path).map(|t| (*a, t)))
        .collect();
    if dels.is_empty() || adds.is_empty() {
        return vec![];
    }
    let restrict_basename = dels.len().saturating_mul(adds.len()) > cfg.max_rename_pairs;
    let mut cands: Vec<(usize, usize)> = Vec::new();
    for (di, (d, dt)) in dels.iter().enumerate() {
        for (ai, (a, at)) in adds.iter().enumerate() {
            let same_name = basename(&d.path) == basename(&a.path);
            if restrict_basename && !same_name {
                continue;
            }
            if !same_name && extension(&d.path) != extension(&a.path) {
                continue;
            }
            let (l1, l2) = (dt.len().max(1) as f64, at.len().max(1) as f64);
            if l1 / l2 > 3.0 || l2 / l1 > 3.0 {
                continue;
            }
            cands.push((di, ai));
            if cands.len() >= cfg.max_rename_pairs {
                break;
            }
        }
    }
    let mut scored: Vec<(usize, usize, f64)> = cands
        .par_iter()
        .map(|&(di, ai)| (di, ai, similarity(&dels[di].1, &adds[ai].1)))
        .filter(|&(_, _, s)| s >= cfg.rename_threshold)
        .collect();
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let (mut ud, mut ua) = (HashSet::new(), HashSet::new());
    let mut out = Vec::new();
    for (di, ai, s) in scored {
        if ud.contains(&di) || ua.contains(&ai) {
            continue;
        }
        ud.insert(di);
        ua.insert(ai);
        out.push((dels[di].0, adds[ai].0, s));
    }
    out
}
