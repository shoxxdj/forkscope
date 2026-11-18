//! Git execution and temporary working repository.
//!
//! Safety principle: **no Git command is ever run in the fork
//! repository**. Its objects are imported read-only (`git fetch` from its
//! path) into a temporary bare repository, where every analysis takes
//! place. The fork's local configuration (hooks, fsmonitor, filters…) is
//! therefore never interpreted, and its repository is never modified.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

/// Builds a `git` command with a hardened, non-interactive environment.
pub fn git_command() -> Command {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GCM_INTERACTIVE", "never")
        .env("LC_ALL", "C")
        .env("LANGUAGE", "C")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    if std::env::var_os("GIT_SSH_COMMAND").is_none() && std::env::var_os("GIT_SSH").is_none() {
        cmd.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes");
    }
    cmd.args([
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.quotePath=false",
        "-c",
        "safe.directory=*",
        "-c",
        "protocol.ext.allow=never",
        "-c",
        "color.ui=false",
        "-c",
        "log.showSignature=false",
        "-c",
        "diff.noprefix=false",
    ]);
    cmd
}

/// Runs a command, optionally feeding data on stdin.
pub fn exec(mut cmd: Command, stdin: Option<&[u8]>) -> Result<Output> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd
        .spawn()
        .context("cannot run `git`: check that it is installed and in the PATH")?;
    let writer = stdin.map(|data| {
        let mut pipe = child.stdin.take().expect("stdin piped");
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        })
    });
    let out = child.wait_with_output()?;
    if let Some(w) = writer {
        let _ = w.join();
    }
    Ok(out)
}

/// Readable Git error.
pub fn git_error(args: &[&str], out: &Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    anyhow!(
        "git {} failed ({}): {}",
        args.iter().take(3).cloned().collect::<Vec<_>>().join(" "),
        out.status,
        stderr.trim()
    )
}

/// Entry of a Git tree (`git ls-tree -r -l`).
#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub size: Option<u64>,
    pub path: String,
}

/// Reference resolved to a commit.
#[derive(Debug, Clone)]
pub struct RefInfo {
    pub name: String,
    pub commit: String,
}

/// Commit metadata.
#[derive(Debug, Clone, Default)]
pub struct CommitMeta {
    pub hash: String,
    pub author_name: String,
    pub author_email: String,
    pub author_date: String,
    pub committer_date: String,
    pub subject: String,
}

/// Temporary bare Git repository used as a workspace (deleted at the end).
pub struct TempRepo {
    dir: TempDir,
    git_dir: PathBuf,
    hooks_dir: PathBuf,
}

impl TempRepo {
    /// Creates an empty bare repository, without templates or hooks.
    pub fn new() -> Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("forkscope-")
            .tempdir()
            .context("creating the temporary directory")?;
        let git_dir = dir.path().join("work.git");
        let hooks_dir = dir.path().join("no-hooks");
        let mut cmd = git_command();
        cmd.arg("init").arg("--bare").arg("-q").arg("--template=").arg(&git_dir);
        let out = exec(cmd, None)?;
        if !out.status.success() {
            return Err(git_error(&["init", "--bare"], &out));
        }
        Ok(Self {
            dir,
            git_dir,
            hooks_dir,
        })
    }

    pub fn path(&self) -> &Path {
        &self.git_dir
    }

    pub fn temp_root(&self) -> &Path {
        self.dir.path()
    }

    /// Git command targeting this repository.
    pub fn command(&self) -> Command {
        let mut cmd = git_command();
        cmd.arg("-c")
            .arg(format!("core.hooksPath={}", self.hooks_dir.display()));
        cmd.arg("--git-dir").arg(&self.git_dir);
        cmd
    }

    /// Runs and returns stdout (error on non-zero exit code).
    pub fn run_bytes<S: AsRef<OsStr>>(&self, args: &[S], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        self.run_env(args, stdin, &[])
    }

    /// Variant with additional environment variables.
    pub fn run_env<S: AsRef<OsStr>>(
        &self,
        args: &[S],
        stdin: Option<&[u8]>,
        env: &[(&str, &OsStr)],
    ) -> Result<Vec<u8>> {
        let mut cmd = self.command();
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = exec(cmd, stdin)?;
        if !out.status.success() {
            let a: Vec<String> = args.iter().map(|s| s.as_ref().to_string_lossy().into_owned()).collect();
            let a: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            return Err(git_error(&a, &out));
        }
        Ok(out.stdout)
    }

    pub fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.run_bytes(args, None)?).into_owned())
    }

    /// Runs; returns `None` if git exits with a non-zero code.
    pub fn try_run<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<Option<String>> {
        let mut cmd = self.command();
        cmd.args(args);
        let out = exec(cmd, None)?;
        if out.status.success() {
            Ok(Some(String::from_utf8_lossy(&out.stdout).into_owned()))
        } else {
            Ok(None)
        }
    }

    /// Resolves a revision to a commit hash.
    pub fn resolve_commit(&self, rev: &str) -> Result<Option<String>> {
        Ok(self
            .try_run(&["rev-parse", "--verify", "-q", &format!("{rev}^{{commit}}")])?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()))
    }

    /// Recursive listing of a tree (commit or tree).
    pub fn ls_tree(&self, treeish: &str) -> Result<Vec<TreeEntry>> {
        let out = self.run_bytes(&["ls-tree", "-r", "-z", "-l", "--full-tree", treeish], None)?;
        let mut entries = Vec::new();
        for rec in out.split(|&b| b == 0) {
            if rec.is_empty() {
                continue;
            }
            let rec = String::from_utf8_lossy(rec);
            let Some((meta, path)) = rec.split_once('\t') else {
                continue;
            };
            let mut it = meta.split_whitespace();
            let (Some(mode), Some(kind), Some(oid), Some(size)) = (it.next(), it.next(), it.next(), it.next()) else {
                continue;
            };
            entries.push(TreeEntry {
                mode: mode.to_string(),
                kind: kind.to_string(),
                oid: oid.to_string(),
                size: size.parse().ok(),
                path: path.to_string(),
            });
        }
        Ok(entries)
    }

    /// Reads a set of blobs in a single `git cat-file --batch` call.
    pub fn read_blobs(&self, oids: &[String]) -> Result<HashMap<String, Vec<u8>>> {
        let mut result = HashMap::new();
        if oids.is_empty() {
            return Ok(result);
        }
        let mut unique: Vec<&String> = oids.iter().collect();
        unique.sort();
        unique.dedup();
        for chunk in unique.chunks(2000) {
            let input: String = chunk.iter().map(|o| format!("{o}\n")).collect();
            let out = self.run_bytes(&["cat-file", "--batch"], Some(input.as_bytes()))?;
            let mut pos = 0usize;
            while pos < out.len() {
                let nl = out[pos..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or_else(|| anyhow!("truncated cat-file output"))?;
                let header = String::from_utf8_lossy(&out[pos..pos + nl]).into_owned();
                pos += nl + 1;
                let parts: Vec<&str> = header.split(' ').collect();
                if parts.len() == 2 && parts[1] == "missing" {
                    continue;
                }
                if parts.len() < 3 {
                    bail!("unexpected cat-file header: {header}");
                }
                let size: usize = parts[2].parse().context("cat-file size")?;
                if pos + size > out.len() {
                    bail!("truncated cat-file output");
                }
                result.insert(parts[0].to_string(), out[pos..pos + size].to_vec());
                pos += size + 1;
            }
        }
        Ok(result)
    }

    /// References (branches/tags) resolved to commits.
    pub fn refs(&self, patterns: &[&str]) -> Result<Vec<RefInfo>> {
        let mut args = vec![
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(*objectname)%09%(objecttype)%09%(*objecttype)",
        ];
        args.extend_from_slice(patterns);
        let out = self.run(&args)?;
        let mut refs = Vec::new();
        for line in out.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 5 {
                continue;
            }
            let commit = if f[3] == "commit" {
                f[1]
            } else if f[3] == "tag" && f[4] == "commit" {
                f[2]
            } else {
                continue;
            };
            refs.push(RefInfo {
                name: f[0].to_string(),
                commit: commit.to_string(),
            });
        }
        Ok(refs)
    }

    /// Commit metadata.
    pub fn commit_meta(&self, commit: &str) -> Result<CommitMeta> {
        let out = self.run(&["show", "-s", "--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%s", commit])?;
        let f: Vec<&str> = out.trim_end_matches('\n').split('\x1f').collect();
        if f.len() < 6 {
            bail!("unreadable metadata for commit {commit}");
        }
        Ok(CommitMeta {
            hash: f[0].to_string(),
            author_name: f[1].to_string(),
            author_email: f[2].to_string(),
            author_date: f[3].to_string(),
            committer_date: f[4].to_string(),
            subject: f[5].to_string(),
        })
    }

    /// Number of commits in a revision range.
    pub fn count(&self, revs: &[&str]) -> Result<usize> {
        let mut args = vec!["rev-list", "--count"];
        args.extend_from_slice(revs);
        Ok(self.run(&args)?.trim().parse().unwrap_or(0))
    }

    /// Is `a` an ancestor of `b`?
    pub fn is_ancestor(&self, a: &str, b: &str) -> Result<bool> {
        Ok(self.try_run(&["merge-base", "--is-ancestor", a, b])?.is_some())
    }
}

/// Layout of the fork project (read without running Git in it).
#[derive(Debug, Clone, Default)]
pub struct ClientLayout {
    pub root: PathBuf,
    /// Worktree-specific Git directory (`.git` or target of a `.git` file).
    pub git_dir: Option<PathBuf>,
    /// Common directory (different for linked worktrees).
    pub common_dir: Option<PathBuf>,
    pub shallow: bool,
    /// Symbolic content of HEAD (`refs/heads/main`) or `None` if HEAD is detached.
    pub head_ref: Option<String>,
    pub remotes: Vec<(String, String)>,
}

impl ClientLayout {
    pub fn is_git(&self) -> bool {
        self.git_dir.is_some()
    }
}

/// Inspects the fork directory by reading files only (no Git command).
pub fn inspect_client(root: &Path) -> Result<ClientLayout> {
    let mut layout = ClientLayout {
        root: root.to_path_buf(),
        ..Default::default()
    };
    let dotgit = root.join(".git");
    let git_dir = if dotgit.is_dir() {
        Some(dotgit)
    } else if dotgit.is_file() {
        let text = std::fs::read_to_string(&dotgit).unwrap_or_default();
        text.lines()
            .find_map(|l| l.strip_prefix("gitdir:"))
            .map(|p| {
                let p = PathBuf::from(p.trim());
                if p.is_absolute() {
                    p
                } else {
                    root.join(p)
                }
            })
            .filter(|p| p.is_dir())
    } else {
        None
    };
    let Some(git_dir) = git_dir else { return Ok(layout) };
    if !git_dir.join("HEAD").is_file() {
        return Ok(layout);
    }
    let common = std::fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|c| {
            let p = PathBuf::from(c.trim());
            if p.is_absolute() {
                p
            } else {
                git_dir.join(p)
            }
        })
        .unwrap_or_else(|| git_dir.clone());
    layout.shallow = common.join("shallow").is_file();
    let head = std::fs::read_to_string(git_dir.join("HEAD")).unwrap_or_default();
    layout.head_ref = head.trim().strip_prefix("ref:").map(|s| s.trim().to_string());
    layout.remotes = parse_remotes(&std::fs::read_to_string(common.join("config")).unwrap_or_default());
    layout.git_dir = Some(git_dir);
    layout.common_dir = Some(common);
    Ok(layout)
}

/// Reads (data only) the remote URLs declared in a Git config file.
fn parse_remotes(config: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            current = t
                .strip_prefix("[remote \"")
                .and_then(|r| r.strip_suffix("\"]"))
                .map(|s| s.to_string());
        } else if let (Some(name), Some(v)) = (&current, t.strip_prefix("url")) {
            if let Some(url) = v.trim_start().strip_prefix('=') {
                out.push((name.clone(), crate::git::upstream::redact_url(url.trim())));
            }
        }
    }
    out
}

/// Result of importing the fork's objects.
#[derive(Debug, Clone, Default)]
pub struct ClientFetch {
    pub head: Option<String>,
    pub warnings: Vec<String>,
}

/// Internal reference holding the fork's HEAD.
pub const CLIENT_HEAD_REF: &str = "refs/forkscope/client-head";

/// Imports the fork's objects and references into the temporary repository
/// (`refs/client/*` and [`CLIENT_HEAD_REF`]). Read-only for the fork.
pub fn fetch_client(repo: &TempRepo, layout: &ClientLayout) -> Result<ClientFetch> {
    let mut res = ClientFetch::default();
    let src = layout.root.as_os_str();
    let mut cmd = repo.command();
    cmd.args(["fetch", "-q", "--no-tags", "--no-write-fetch-head"])
        .arg(src)
        .arg("+refs/*:refs/client/*");
    let out = exec(cmd, None)?;
    if !out.status.success() {
        res.warnings.push(format!(
            "incomplete import of the fork's references: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let mut cmd = repo.command();
    cmd.args(["fetch", "-q", "--no-tags", "--no-write-fetch-head"])
        .arg(src)
        .arg(format!("+HEAD:{CLIENT_HEAD_REF}"));
    let out = exec(cmd, None)?;
    if out.status.success() {
        res.head = repo.resolve_commit(CLIENT_HEAD_REF)?;
    } else {
        res.warnings.push(format!(
            "unreadable fork HEAD (empty or corrupt repository?): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if layout.shallow {
        res.warnings
            .push("the fork repository is shallow: its history is incomplete".to_string());
    }
    Ok(res)
}
