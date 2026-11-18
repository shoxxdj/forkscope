//! File snapshots: fork directory or Git tree.

use crate::config::Config;
use crate::git::repository::TempRepo;
use crate::utils::hashing::git_blob_oid;
use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Kind of entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Executable,
    Symlink,
    Submodule,
}

/// File of a snapshot, identified by its Git blob ID.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    pub path: String,
    pub kind: EntryKind,
    /// Git blob ID (SHA-1); empty for a fork submodule.
    pub oid: String,
    pub size: Option<u64>,
}

/// Files indexed by relative path (`/` separator).
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub entries: BTreeMap<String, SnapshotEntry>,
}

impl Snapshot {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Comparable files (excluding submodules).
    pub fn files(&self) -> impl Iterator<Item = &SnapshotEntry> {
        self.entries.values().filter(|e| e.kind != EntryKind::Submodule)
    }
}

/// Path filter (directory exclusions, globs, extensions).
#[derive(Debug, Clone)]
pub struct PathFilter {
    dirs: HashSet<String>,
    globs: GlobSet,
    include_ext: HashSet<String>,
    exclude_ext: HashSet<String>,
}

impl PathFilter {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let mut b = GlobSetBuilder::new();
        for g in &cfg.exclude.globs {
            b.add(Glob::new(g).with_context(|| format!("invalid exclusion glob: {g}"))?);
        }
        Ok(Self {
            dirs: cfg.excluded_dirs().into_iter().collect(),
            globs: b.build()?,
            include_ext: cfg
                .diff
                .include_extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
            exclude_ext: cfg
                .diff
                .exclude_extensions
                .iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
        })
    }

    /// Should the directory (relative path) be ignored?
    pub fn is_dir_excluded(&self, rel_dir: &str) -> bool {
        let name = crate::utils::basename(rel_dir);
        name == ".git" || self.dirs.contains(name) || self.globs.is_match(rel_dir)
    }

    /// Should the file (relative path) be compared?
    pub fn is_file_included(&self, rel: &str) -> bool {
        let mut comps: Vec<&str> = rel.split('/').collect();
        comps.pop();
        if comps.iter().any(|c| *c == ".git" || self.dirs.contains(*c)) {
            return false;
        }
        if self.globs.is_match(rel) {
            return false;
        }
        let ext = crate::utils::extension(rel).unwrap_or_default();
        if !self.include_ext.is_empty() && !self.include_ext.contains(&ext) {
            return false;
        }
        !self.exclude_ext.contains(&ext)
    }
}

/// Builds the snapshot of a directory (actual content on disk, including
/// uncommitted changes). Symbolic links are never followed.
pub fn snapshot_directory(root: &Path, filter: &PathFilter) -> Result<(Snapshot, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut files: Vec<(String, PathBuf, bool)> = Vec::new();
    let mut submodules = Vec::new();
    let mut it = WalkDir::new(root).follow_links(false).sort_by_file_name().into_iter();
    while let Some(entry) = it.next() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warnings.push(format!("cannot read: {e}"));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let rel = match entry.path().strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        let ft = entry.file_type();
        if ft.is_dir() {
            if filter.is_dir_excluded(&rel) {
                it.skip_current_dir();
                continue;
            }
            if entry.path().join(".git").exists() {
                submodules.push(rel);
                it.skip_current_dir();
            }
            continue;
        }
        if entry.file_name() == ".git" || !filter.is_file_included(&rel) {
            continue;
        }
        files.push((rel, entry.path().to_path_buf(), ft.is_symlink()));
    }

    let results: Vec<Result<SnapshotEntry, String>> = files
        .par_iter()
        .map(|(rel, abs, is_link)| {
            let (data, kind) = if *is_link {
                let target = std::fs::read_link(abs).map_err(|e| format!("{rel}: {e}"))?;
                (target.to_string_lossy().into_owned().into_bytes(), EntryKind::Symlink)
            } else {
                let data = std::fs::read(abs).map_err(|e| format!("{rel}: {e}"))?;
                (data, file_kind(abs))
            };
            Ok(SnapshotEntry {
                path: rel.clone(),
                kind,
                oid: git_blob_oid(&data),
                size: Some(data.len() as u64),
            })
        })
        .collect();

    let mut snap = Snapshot::default();
    for r in results {
        match r {
            Ok(e) => {
                snap.entries.insert(e.path.clone(), e);
            }
            Err(w) => warnings.push(format!("unreadable file skipped: {w}")),
        }
    }
    for s in submodules {
        snap.entries.insert(
            s.clone(),
            SnapshotEntry {
                path: s,
                kind: EntryKind::Submodule,
                oid: String::new(),
                size: None,
            },
        );
    }
    Ok((snap, warnings))
}

#[cfg(unix)]
fn file_kind(p: &Path) -> EntryKind {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) if m.permissions().mode() & 0o111 != 0 => EntryKind::Executable,
        _ => EntryKind::File,
    }
}

#[cfg(not(unix))]
fn file_kind(_p: &Path) -> EntryKind {
    EntryKind::File
}

/// Builds the snapshot of a Git commit or tree.
pub fn snapshot_from_tree(repo: &TempRepo, treeish: &str, filter: &PathFilter) -> Result<Snapshot> {
    let mut snap = Snapshot::default();
    for e in repo.ls_tree(treeish)? {
        if !filter.is_file_included(&e.path) {
            continue;
        }
        let kind = match e.mode.as_str() {
            "100755" => EntryKind::Executable,
            "120000" => EntryKind::Symlink,
            "160000" => EntryKind::Submodule,
            _ => EntryKind::File,
        };
        snap.entries.insert(
            e.path.clone(),
            SnapshotEntry {
                path: e.path,
                kind,
                oid: e.oid,
                size: e.size,
            },
        );
    }
    Ok(snap)
}

/// Content source for the files of a snapshot.
pub trait ContentProvider: Sync {
    /// Loads the content of the requested entries (key: path).
    fn load(&self, entries: &[&SnapshotEntry]) -> Result<HashMap<String, Vec<u8>>>;
}

/// Content read from a directory on disk.
pub struct DirectoryContent {
    pub root: PathBuf,
}

impl ContentProvider for DirectoryContent {
    fn load(&self, entries: &[&SnapshotEntry]) -> Result<HashMap<String, Vec<u8>>> {
        Ok(entries
            .par_iter()
            .filter(|e| e.kind != EntryKind::Submodule)
            .filter_map(|e| {
                let p = self.root.join(&e.path);
                let data = if e.kind == EntryKind::Symlink {
                    std::fs::read_link(&p)
                        .ok()
                        .map(|t| t.to_string_lossy().into_owned().into_bytes())
                } else {
                    std::fs::read(&p).ok()
                };
                data.map(|d| (e.path.clone(), d))
            })
            .collect())
    }
}

/// Content read from the temporary repository's object database.
pub struct GitContent<'a> {
    pub repo: &'a TempRepo,
}

impl ContentProvider for GitContent<'_> {
    fn load(&self, entries: &[&SnapshotEntry]) -> Result<HashMap<String, Vec<u8>>> {
        let oids: Vec<String> = entries
            .iter()
            .filter(|e| e.kind != EntryKind::Submodule && !e.oid.is_empty())
            .map(|e| e.oid.clone())
            .collect();
        let blobs = self.repo.read_blobs(&oids)?;
        Ok(entries
            .iter()
            .filter_map(|e| blobs.get(&e.oid).map(|b| (e.path.clone(), b.clone())))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_excludes_node_modules() {
        let f = PathFilter::from_config(&Config::default()).unwrap();
        assert!(!f.is_file_included("web/node_modules/x/index.js"));
        assert!(f.is_file_included("src/main.rs"));
        assert!(f.is_dir_excluded("target"));
    }

    #[test]
    fn extension_filter() {
        let mut c = Config::default();
        c.diff.include_extensions = vec!["rs".into()];
        let f = PathFilter::from_config(&c).unwrap();
        assert!(f.is_file_included("a.rs"));
        assert!(!f.is_file_included("a.py"));
    }
}
