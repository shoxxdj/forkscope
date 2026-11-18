//! Helpers building (deterministic) test Git repositories.
#![allow(dead_code)]

use forkscope::pipeline::{run, AnalyzeOptions};
use forkscope::report::console::Silent;
use forkscope::report::ForkScopeReport;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI64, Ordering};

static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);

/// Runs git in `dir` with a deterministic identity and date.
pub fn git_as(dir: &Path, author: &str, args: &[&str]) -> String {
    let ts = CLOCK.fetch_add(3600, Ordering::SeqCst);
    let date = format!("@{ts} +0000");
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", author)
        .env("GIT_AUTHOR_EMAIL", format!("{}@example.org", author.to_lowercase()))
        .env("GIT_COMMITTER_NAME", author)
        .env("GIT_COMMITTER_EMAIL", format!("{}@example.org", author.to_lowercase()))
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .env_remove("GIT_DIR")
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    git_as(dir, "Upstream", args)
}

pub fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

pub fn remove(dir: &Path, rel: &str) {
    std::fs::remove_file(dir.join(rel)).unwrap();
}

pub fn commit(dir: &Path, author: &str, msg: &str) -> String {
    git_as(dir, author, &["add", "-A"]);
    git_as(dir, author, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

/// Base content of a Python + JS project.
pub const AUTH_PY: &str = "import bcrypt\n\n\ndef login(user, password):\n    if not check_password(user, password):\n        raise PermissionDenied()\n    return create_session(user)\n\n\ndef logout(session):\n    session.destroy()\n";
pub const VIEWS_PY: &str = "def delete_item(request, item):\n    if not request.user.is_admin:\n        return forbidden()\n    item.delete()\n    return ok()\n\n\ndef show(request, item):\n    return render(item)\n";
pub const NET_PY: &str =
    "import requests\n\n\ndef fetch(url):\n    r = requests.get(url, timeout=10)\n    return r.json()\n";

pub fn util_py(n: usize) -> String {
    (0..n)
        .map(|i| format!("def helper_{i}(x):\n    return x + {i}\n\n"))
        .collect()
}

/// Reference source repository:
/// c1 (tag v1.0) → c2 (tag v1.1) → c3 (no tag) → c4 "security fix" (tag v1.2, main)
pub struct Upstream {
    pub dir: PathBuf,
    pub c1: String,
    pub c2: String,
    pub c3: String,
    pub c4: String,
}

pub fn make_upstream(root: &Path) -> Upstream {
    let dir = root.join("upstream");
    std::fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    write(&dir, "README.md", "# Project\n\nProject description.\n");
    write(&dir, "CHANGELOG.md", "## 1.0.0\n- first release\n");
    write(&dir, "src/auth.py", AUTH_PY);
    write(&dir, "src/views.py", VIEWS_PY);
    write(&dir, "src/net.py", NET_PY);
    write(&dir, "src/util.py", &util_py(20));
    write(&dir, "requirements.txt", "requests==2.31.0\nflask==2.3.0\n");
    write(
        &dir,
        "package.json",
        "{\n  \"name\": \"demo\",\n  \"dependencies\": {\n    \"express\": \"^4.18.0\"\n  }\n}\n",
    );
    write(&dir, "docs/guide.md", "Guide\n");
    let c1 = commit(&dir, "Upstream", "initial version");
    git(&dir, &["tag", "v1.0"]);

    write(
        &dir,
        "src/util.py",
        &(util_py(20) + "def extra(x):\n    return x * 2\n"),
    );
    write(&dir, "CHANGELOG.md", "## 1.1.0\n- extra\n\n## 1.0.0\n- first release\n");
    let c2 = commit(&dir, "Upstream", "add extra()");
    git(&dir, &["tag", "-a", "v1.1", "-m", "version 1.1"]);

    write(&dir, "src/feature.py", "def feature():\n    return 42\n");
    write(
        &dir,
        "CHANGELOG.md",
        "## unreleased\n- feature\n\n## 1.1.0\n- extra\n\n## 1.0.0\n- first release\n",
    );
    let c3 = commit(&dir, "Upstream", "new feature");

    write(&dir, "src/net.py", "import requests\n\n\ndef fetch(url):\n    if not url.startswith('https://'):\n        raise ValueError('https required')\n    r = requests.get(url, timeout=10)\n    return r.json()\n");
    write(
        &dir,
        "CHANGELOG.md",
        "## 1.2.0\n- security: URL validation\n- feature\n\n## 1.1.0\n- extra\n\n## 1.0.0\n- first release\n",
    );
    let c4 = commit(&dir, "Upstream", "security: validate URL scheme (CVE-2024-0001)");
    git(&dir, &["tag", "v1.2"]);
    Upstream { dir, c1, c2, c3, c4 }
}

/// Clones the source into `root/name`, checked out at `rev`.
pub fn clone_at(up: &Upstream, root: &Path, name: &str, rev: &str) -> PathBuf {
    let dir = root.join(name);
    git(root, &["clone", "-q", up.dir.to_str().unwrap(), dir.to_str().unwrap()]);
    git(&dir, &["checkout", "-q", "-B", "main", rev]);
    dir
}

/// Copies the tree of a revision into a directory without Git metadata.
pub fn export_tree(repo: &Path, rev: &str, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    let files = git(repo, &["ls-tree", "-r", "--name-only", rev]);
    for f in files.lines() {
        let content = Command::new("git")
            .current_dir(repo)
            .args(["show", &format!("{rev}:{f}")])
            .output()
            .unwrap()
            .stdout;
        let p = dest.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
}

/// Runs the analysis; returns the report.
pub fn analyze(client: &Path, up: &Upstream, out: &Path) -> ForkScopeReport {
    analyze_with(client, up, out, |_| {})
}

pub fn analyze_with(client: &Path, up: &Upstream, out: &Path, f: impl FnOnce(&mut AnalyzeOptions)) -> ForkScopeReport {
    let mut opts = AnalyzeOptions::new(client, up.dir.to_str().unwrap());
    opts.output = Some(out.to_path_buf());
    f(&mut opts);
    run(&opts, &Silent).expect("analyse")
}

pub fn status_of<'a>(r: &'a ForkScopeReport, path: &str) -> Option<&'a forkscope::diff::FileChange> {
    r.diff.files.iter().find(|c| c.path == path)
}

/// Fingerprint of a directory state (paths, sizes, modification dates).
pub fn fingerprint(dir: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut v: Vec<_> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let m = e.metadata().unwrap();
            (e.path().display().to_string(), m.len(), m.modified().unwrap())
        })
        .collect();
    v.sort();
    v
}
