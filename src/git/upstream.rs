//! Fetching the original (source) repository via Git, without any forge API.

use super::repository::{exec, git_command, TempRepo};
use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Information about the fetched source repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UpstreamInfo {
    /// URL (credentials masked).
    pub url: String,
    pub default_branch: Option<String>,
    pub branches: usize,
    pub tags: usize,
    pub depth: Option<u32>,
    pub preferred_branch: Option<String>,
}

/// Masks credentials that may be present in a URL.
pub fn redact_url(url: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]+@").unwrap());
    re.replace(url, "${1}***@").into_owned()
}

/// Normalises a URL/path before passing it to Git (local paths made absolute).
pub fn normalize_source(url: &str) -> String {
    let p = std::path::Path::new(url);
    if !url.contains("://") && p.exists() {
        if let Ok(c) = p.canonicalize() {
            return c.to_string_lossy().into_owned();
        }
    }
    url.to_string()
}

/// Turns common Git errors (authentication, network) into a clear message.
pub fn explain_fetch_error(stderr: &str) -> String {
    let s = stderr.to_ascii_lowercase();
    let hint = if s.contains("authentication failed")
        || s.contains("could not read username")
        || s.contains("terminal prompts disabled")
        || s.contains("permission denied (publickey")
        || s.contains("http basic: access denied")
    {
        "authentication failed: configure a credential helper, a token in the URL, or an SSH agent (no interactive prompt is possible)"
    } else if s.contains("repository not found")
        || s.contains("not found")
        || s.contains("does not appear to be a git repository")
    {
        "repository not found or access denied (a private repository may look non-existent)"
    } else if s.contains("could not resolve host")
        || s.contains("connection timed out")
        || s.contains("unable to access")
    {
        "network error: host unreachable"
    } else if s.contains("host key verification failed") {
        "unknown SSH host key: add it to known_hosts"
    } else {
        "Git fetch failed"
    };
    format!("{hint}\n  git details: {}", stderr.trim())
}

/// Default branch of the remote repository (`git ls-remote --symref <url> HEAD`).
pub fn remote_default_branch(url: &str) -> Option<String> {
    let mut cmd = git_command();
    cmd.args(["ls-remote", "--symref", url, "HEAD"]);
    let out = exec(cmd, None).ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("ref: refs/heads/"))
        .and_then(|l| l.split('\t').next())
        .map(|s| s.to_string())
}

/// Fetches the source branches and tags into the temporary repository:
/// branches → `refs/upstream/heads/*`, tags → `refs/tags/*`.
pub fn fetch_upstream(
    repo: &TempRepo,
    url: &str,
    depth: Option<u32>,
    preferred_branch: Option<&str>,
) -> Result<UpstreamInfo> {
    let source = normalize_source(url);
    let mut cmd = repo.command();
    cmd.args(["fetch", "-q", "--no-tags", "--no-write-fetch-head"]);
    if let Some(d) = depth {
        cmd.arg(format!("--depth={d}"));
    }
    cmd.arg(&source)
        .arg("+refs/heads/*:refs/upstream/heads/*")
        .arg("+refs/tags/*:refs/tags/*");
    let out = exec(cmd, None)?;
    if !out.status.success() {
        bail!(
            "cannot fetch the source repository {}: {}",
            redact_url(url),
            explain_fetch_error(&String::from_utf8_lossy(&out.stderr))
        );
    }
    let branches = repo.refs(&["refs/upstream/heads"])?;
    let tags = repo.refs(&["refs/tags"])?;
    if branches.is_empty() && tags.is_empty() {
        bail!("the source repository {} contains no branch or tag", redact_url(url));
    }
    let default_branch = remote_default_branch(&source);
    let preferred = preferred_branch
        .map(|s| s.to_string())
        .or_else(|| default_branch.clone())
        .or_else(|| {
            ["main", "master", "develop"]
                .iter()
                .find(|b| branches.iter().any(|r| r.name == format!("refs/upstream/heads/{b}")))
                .map(|s| s.to_string())
        });
    Ok(UpstreamInfo {
        url: redact_url(url),
        default_branch,
        branches: branches.len(),
        tags: tags.len(),
        depth,
        preferred_branch: preferred,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_credentials() {
        assert_eq!(
            redact_url("https://user:tok@github.com/o/r.git"),
            "https://***@github.com/o/r.git"
        );
        assert_eq!(redact_url("git@github.com:o/r.git"), "git@github.com:o/r.git");
    }

    #[test]
    fn explains_auth() {
        assert!(explain_fetch_error("fatal: Authentication failed for").contains("authentication"));
    }
}
