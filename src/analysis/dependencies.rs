//! Dependency file analysis (manifests and lockfiles) for the main
//! ecosystems. No package is downloaded or installed: files are only
//! read and parsed.

use super::rules::{Category, Confidence, Finding, Severity};
use crate::diff::{ChangeStatus, FileChange};
use crate::utils::basename;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Ecosystem / format of a dependency file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DepFormat {
    CargoToml,
    CargoLock,
    PackageJson,
    PackageLock,
    YarnLock,
    PnpmLock,
    Requirements,
    Pyproject,
    PoetryLock,
    ComposerJson,
    ComposerLock,
    PomXml,
    Gradle,
    GoMod,
    GoSum,
    Gemfile,
    GemfileLock,
}

impl DepFormat {
    pub fn ecosystem(self) -> &'static str {
        use DepFormat::*;
        match self {
            CargoToml | CargoLock => "Rust",
            PackageJson | PackageLock | YarnLock | PnpmLock => "JavaScript",
            Requirements | Pyproject | PoetryLock => "Python",
            ComposerJson | ComposerLock => "PHP",
            PomXml | Gradle => "Java",
            GoMod | GoSum => "Go",
            Gemfile | GemfileLock => "Ruby",
        }
    }
    pub fn is_lockfile(self) -> bool {
        use DepFormat::*;
        matches!(
            self,
            CargoLock | PackageLock | YarnLock | PnpmLock | PoetryLock | ComposerLock | GoSum | GemfileLock
        )
    }
}

/// Recognises a dependency file from its name.
pub fn ecosystem_for(path: &str) -> Option<DepFormat> {
    use DepFormat::*;
    let name = basename(path);
    Some(match name {
        "Cargo.toml" => CargoToml,
        "Cargo.lock" => CargoLock,
        "package.json" => PackageJson,
        "package-lock.json" | "npm-shrinkwrap.json" => PackageLock,
        "yarn.lock" => YarnLock,
        "pnpm-lock.yaml" => PnpmLock,
        "pyproject.toml" => Pyproject,
        "poetry.lock" => PoetryLock,
        "composer.json" => ComposerJson,
        "composer.lock" => ComposerLock,
        "pom.xml" => PomXml,
        "build.gradle" | "build.gradle.kts" => Gradle,
        "go.mod" => GoMod,
        "go.sum" => GoSum,
        "Gemfile" | "gems.rb" => Gemfile,
        "Gemfile.lock" | "gems.locked" => GemfileLock,
        n if n.starts_with("requirements") && n.ends_with(".txt") => Requirements,
        _ => return None,
    })
}

/// Dependency extracted from a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Dependency {
    pub name: String,
    /// dependencies, dev, build, peer, optional, lock, replace…
    pub scope: String,
    pub version: Option<String>,
    /// Source: registry, git+URL, url, path…
    pub source: Option<String>,
}

impl Dependency {
    fn new(name: impl Into<String>, scope: impl Into<String>, version: Option<String>, source: Option<String>) -> Self {
        Self {
            name: name.into(),
            scope: scope.into(),
            version,
            source,
        }
    }
    /// Dependency coming from a source outside the public registry.
    pub fn is_external(&self) -> bool {
        is_external_source(self.source.as_deref()) || is_external_source(self.version.as_deref())
    }
}

fn is_external_source(s: Option<&str>) -> bool {
    let Some(s) = s else { return false };
    let l = s.to_ascii_lowercase();
    l.starts_with("git")
        || l.contains("git+")
        || l.starts_with("http://")
        || (l.starts_with("https://") && !is_official_registry(&l))
        || l.starts_with("file:")
        || l.starts_with("path:")
        || l.starts_with("link:")
        || l.starts_with("../")
        || l.starts_with("./")
        || l.starts_with('/')
        || l.contains("github.com/") && !l.contains("registry")
}

fn is_official_registry(l: &str) -> bool {
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "files.pythonhosted.org",
        "github.com/rust-lang/crates.io-index",
        "index.crates.io",
        "repo.packagist.org",
        "api.github.com/repos", // dist composer
        "codeload.github.com",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "rubygems.org",
        "proxy.golang.org",
    ]
    .iter()
    .any(|r| l.contains(r))
}

/// Kind of dependency change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DepChangeKind {
    Added,
    Removed,
    VersionChanged,
    SourceChanged,
}

impl DepChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::VersionChanged => "version changed",
            Self::SourceChanged => "source changed",
        }
    }
}

/// Change of a dependency.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DepChange {
    pub name: String,
    pub scope: String,
    pub kind: DepChangeKind,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub old_source: Option<String>,
    pub new_source: Option<String>,
    /// Git, URL or local path dependency (outside the official registry).
    pub external: bool,
}

/// Analysis of a modified dependency file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ManifestReport {
    pub path: String,
    pub ecosystem: String,
    pub format: DepFormat,
    pub lockfile: bool,
    pub status: ChangeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    pub changes: Vec<DepChange>,
}

/// Dependency summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DependencyReport {
    pub manifests: Vec<ManifestReport>,
    pub added: usize,
    pub removed: usize,
    pub version_changed: usize,
    pub source_changed: usize,
    pub external: usize,
}

/// Parses a dependency file.
pub fn parse(format: DepFormat, text: &str) -> Result<Vec<Dependency>, String> {
    use DepFormat::*;
    let deps = match format {
        CargoToml => parse_cargo_toml(text)?,
        CargoLock => parse_toml_packages(text, "package", "source")?,
        PackageJson => parse_package_json(text)?,
        PackageLock => parse_package_lock(text)?,
        YarnLock => parse_yarn_lock(text),
        PnpmLock => parse_pnpm_lock(text)?,
        Requirements => parse_requirements(text),
        Pyproject => parse_pyproject(text)?,
        PoetryLock => parse_toml_packages(text, "package", "source")?,
        ComposerJson => parse_composer_json(text)?,
        ComposerLock => parse_composer_lock(text)?,
        PomXml => parse_pom(text),
        Gradle => parse_gradle(text),
        GoMod => parse_go_mod(text),
        GoSum => parse_go_sum(text),
        Gemfile => parse_gemfile(text),
        GemfileLock => parse_gemfile_lock(text),
    };
    Ok(deps)
}

// ---------------------------------------------------------------- Rust
fn toml_dep(name: &str, v: &toml::Value, scope: &str) -> Dependency {
    match v {
        toml::Value::String(s) => Dependency::new(name, scope, Some(s.clone()), None),
        toml::Value::Table(t) => {
            let get = |k: &str| t.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
            let source = if let Some(g) = get("git") {
                let rev = get("rev")
                    .or(get("tag"))
                    .or(get("branch"))
                    .map(|r| format!("#{r}"))
                    .unwrap_or_default();
                Some(format!("git+{g}{rev}"))
            } else if let Some(p) = get("path") {
                Some(format!("path:{p}"))
            } else {
                get("registry").map(|r| format!("registry:{r}"))
            };
            let name = get("package").unwrap_or_else(|| name.to_string());
            Dependency::new(name, scope, get("version"), source)
        }
        _ => Dependency::new(name, scope, None, None),
    }
}

fn parse_cargo_toml(text: &str) -> Result<Vec<Dependency>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let mut section = |tbl: Option<&toml::Value>, scope: &str| {
        if let Some(t) = tbl.and_then(|t| t.as_table()) {
            for (k, val) in t {
                out.push(toml_dep(k, val, scope));
            }
        }
    };
    section(v.get("dependencies"), "dependencies");
    section(v.get("dev-dependencies"), "dev");
    section(v.get("build-dependencies"), "build");
    section(v.get("workspace").and_then(|w| w.get("dependencies")), "workspace");
    if let Some(targets) = v.get("target").and_then(|t| t.as_table()) {
        for (tname, t) in targets {
            for (key, scope) in [
                ("dependencies", "target"),
                ("dev-dependencies", "target-dev"),
                ("build-dependencies", "target-build"),
            ] {
                if let Some(tb) = t.get(key).and_then(|x| x.as_table()) {
                    for (k, val) in tb {
                        out.push(toml_dep(k, val, &format!("{scope}:{tname}")));
                    }
                }
            }
        }
    }
    if let Some(p) = v.get("patch").and_then(|t| t.as_table()) {
        for (reg, t) in p {
            if let Some(tb) = t.as_table() {
                for (k, val) in tb {
                    out.push(toml_dep(k, val, &format!("patch:{reg}")));
                }
            }
        }
    }
    Ok(out)
}

/// `[[package]]` with name / version / source (Cargo.lock, poetry.lock).
fn parse_toml_packages(text: &str, key: &str, source_key: &str) -> Result<Vec<Dependency>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(arr) = v.get(key).and_then(|a| a.as_array()) {
        for p in arr {
            let name = p.get("name").and_then(|x| x.as_str()).unwrap_or_default();
            let version = p.get("version").and_then(|x| x.as_str()).map(|s| s.to_string());
            let source = match p.get(source_key) {
                Some(toml::Value::String(s)) => Some(s.clone()),
                Some(toml::Value::Table(t)) => {
                    let ty = t.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    let url = t.get("url").and_then(|x| x.as_str()).unwrap_or("");
                    Some(if ty == "git" {
                        format!("git+{url}")
                    } else {
                        format!("{ty}:{url}")
                    })
                }
                _ => None,
            };
            out.push(Dependency::new(name, "lock", version, source));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- JavaScript
fn npm_spec_source(spec: &str) -> Option<String> {
    let l = spec.to_ascii_lowercase();
    if l.starts_with("git")
        || l.starts_with("http")
        || l.starts_with("file:")
        || l.starts_with("link:")
        || l.starts_with("github:")
        || l.starts_with("npm:")
        || l.starts_with("workspace:")
        || (spec.contains('/') && !spec.starts_with('@') && !spec.contains(' '))
    {
        Some(spec.to_string())
    } else {
        None
    }
}

fn parse_package_json(text: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (key, scope) in [
        ("dependencies", "dependencies"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
        ("bundledDependencies", "bundled"),
        ("overrides", "overrides"),
        ("resolutions", "resolutions"),
    ] {
        if let Some(obj) = v.get(key).and_then(|o| o.as_object()) {
            for (name, spec) in obj {
                let spec_s = spec.as_str().map(|s| s.to_string()).unwrap_or_else(|| spec.to_string());
                out.push(Dependency::new(
                    name.clone(),
                    scope,
                    Some(spec_s.clone()),
                    npm_spec_source(&spec_s),
                ));
            }
        }
    }
    if let Some(scripts) = v.get("scripts").and_then(|o| o.as_object()) {
        for hook in ["preinstall", "install", "postinstall", "prepare", "prepublish"] {
            if let Some(cmd) = scripts.get(hook).and_then(|c| c.as_str()) {
                out.push(Dependency::new(
                    format!("script:{hook}"),
                    "lifecycle-script",
                    Some(cmd.to_string()),
                    None,
                ));
            }
        }
    }
    Ok(out)
}

fn parse_package_lock(text: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(|o| o.as_object()) {
        for (k, p) in pkgs {
            if k.is_empty() {
                continue;
            }
            let name = k.rsplit("node_modules/").next().unwrap_or(k).to_string();
            let version = p.get("version").and_then(|x| x.as_str()).map(|s| s.to_string());
            let resolved = p.get("resolved").and_then(|x| x.as_str()).map(|s| s.to_string());
            let scope = if p.get("dev").and_then(|d| d.as_bool()).unwrap_or(false) {
                "lock-dev"
            } else {
                "lock"
            };
            out.push(Dependency::new(
                name,
                scope,
                version,
                resolved.map(registry_host_or_url),
            ));
        }
    } else if let Some(deps) = v.get("dependencies").and_then(|o| o.as_object()) {
        fn walk(deps: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<Dependency>) {
            for (name, p) in deps {
                let version = p.get("version").and_then(|x| x.as_str()).map(|s| s.to_string());
                let resolved = p.get("resolved").and_then(|x| x.as_str()).map(|s| s.to_string());
                out.push(Dependency::new(
                    name.clone(),
                    "lock",
                    version,
                    resolved.map(registry_host_or_url),
                ));
                if let Some(sub) = p.get("dependencies").and_then(|o| o.as_object()) {
                    walk(sub, out);
                }
            }
        }
        walk(deps, &mut out);
    }
    Ok(out)
}

/// For a lockfile, keep only the host of an official registry URL
/// (the path changes with the version), and the full URL otherwise.
fn registry_host_or_url(url: String) -> String {
    let l = url.to_ascii_lowercase();
    if is_official_registry(&l) {
        url.split('/').take(3).collect::<Vec<_>>().join("/")
    } else {
        url
    }
}

fn parse_yarn_lock(text: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let mut resolved: Option<String> = None;
    let flush = |names: &mut Vec<String>,
                 version: &mut Option<String>,
                 resolved: &mut Option<String>,
                 out: &mut Vec<Dependency>| {
        let mut uniq: Vec<String> = std::mem::take(names);
        uniq.sort();
        uniq.dedup();
        for n in uniq {
            out.push(Dependency::new(
                n,
                "lock",
                version.clone(),
                resolved.clone().map(registry_host_or_url),
            ));
        }
        *version = None;
        *resolved = None;
    };
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            flush(&mut names, &mut version, &mut resolved, &mut out);
            let header = line.trim_end().trim_end_matches(':');
            for spec in header.split(", ") {
                let spec = spec.trim().trim_matches('"');
                if spec == "__metadata" {
                    continue;
                }
                // name@range or @scope/name@range ; berry: name@npm:range
                let name = match spec[1..].find('@') {
                    Some(i) => &spec[..i + 1],
                    None => spec,
                };
                names.push(name.to_string());
            }
        } else {
            let t = line.trim();
            if let Some(v) = t
                .strip_prefix("version")
                .map(|s| s.trim_start_matches(':').trim().trim_matches('"'))
            {
                version = Some(v.to_string());
            } else if let Some(r) = t.strip_prefix("resolved").or_else(|| t.strip_prefix("resolution:")) {
                resolved = Some(r.trim_start_matches(':').trim().trim_matches('"').to_string());
            }
        }
    }
    flush(&mut names, &mut version, &mut resolved, &mut out);
    out
}

fn parse_pnpm_lock(text: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(pkgs) = v.get("packages").and_then(|p| p.as_mapping()) {
        for (k, p) in pkgs {
            let key = k.as_str().unwrap_or_default().trim_start_matches('/');
            let key = key.split('(').next().unwrap_or(key);
            let (name, version) = match key.rfind('@') {
                Some(i) if i > 0 => (key[..i].to_string(), Some(key[i + 1..].to_string())),
                _ => (key.to_string(), None),
            };
            let tarball = p
                .get("resolution")
                .and_then(|r| r.get("tarball").or_else(|| r.get("repo")))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
            out.push(Dependency::new(name, "lock", version, tarball));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- Python
fn pep508(spec: &str, scope: &str) -> Option<Dependency> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(@\s*(\S+))?\s*([^;@]*)").unwrap()
    });
    let c = re.captures(spec)?;
    let name = c.get(1)?.as_str().to_ascii_lowercase().replace('_', "-");
    let url = c.get(4).map(|m| m.as_str().to_string());
    let ver = c
        .get(5)
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty());
    Some(Dependency::new(name, scope, ver, url))
}

fn parse_requirements(text: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("--index-url")
            || line.starts_with("--extra-index-url")
            || line.starts_with("-i ")
            || line.starts_with("--trusted-host")
            || line.starts_with("--find-links")
            || line.starts_with("-f ")
        {
            let mut it = line.splitn(2, [' ', '=']);
            let opt = it.next().unwrap_or("");
            out.push(Dependency::new(
                format!("option:{opt}"),
                "pip-option",
                None,
                it.next().map(|s| s.trim().to_string()),
            ));
            continue;
        }
        if line.starts_with("-r") || line.starts_with("-c") || line.starts_with("--") {
            continue;
        }
        if line.starts_with("-e") || line.contains("://") && !line.contains(" @ ") {
            let url = line.trim_start_matches("-e").trim();
            let name = url
                .split("#egg=")
                .nth(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| url.to_string());
            out.push(Dependency::new(name, "dependencies", None, Some(url.to_string())));
            continue;
        }
        if let Some(d) = pep508(line, "dependencies") {
            out.push(d);
        }
    }
    out
}

fn parse_pyproject(text: &str) -> Result<Vec<Dependency>, String> {
    let v: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    if let Some(arr) = v
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        out.extend(
            arr.iter()
                .filter_map(|s| s.as_str())
                .filter_map(|s| pep508(s, "dependencies")),
        );
    }
    if let Some(opt) = v
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for (g, arr) in opt {
            if let Some(arr) = arr.as_array() {
                out.extend(
                    arr.iter()
                        .filter_map(|s| s.as_str())
                        .filter_map(|s| pep508(s, &format!("optional:{g}"))),
                );
            }
        }
    }
    if let Some(arr) = v
        .get("build-system")
        .and_then(|p| p.get("requires"))
        .and_then(|d| d.as_array())
    {
        out.extend(arr.iter().filter_map(|s| s.as_str()).filter_map(|s| pep508(s, "build")));
    }
    let poetry = v.get("tool").and_then(|t| t.get("poetry"));
    let mut poetry_section = |tbl: Option<&toml::Value>, scope: &str| {
        if let Some(t) = tbl.and_then(|t| t.as_table()) {
            for (k, val) in t {
                if k == "python" {
                    continue;
                }
                out.push(toml_dep(&k.to_ascii_lowercase(), val, scope));
            }
        }
    };
    poetry_section(poetry.and_then(|p| p.get("dependencies")), "dependencies");
    poetry_section(poetry.and_then(|p| p.get("dev-dependencies")), "dev");
    if let Some(groups) = poetry.and_then(|p| p.get("group")).and_then(|g| g.as_table()) {
        for (g, t) in groups {
            poetry_section(t.get("dependencies"), &format!("group:{g}"));
        }
    }
    if let Some(srcs) = poetry.and_then(|p| p.get("source")).and_then(|s| s.as_array()) {
        for s in srcs {
            let name = s.get("name").and_then(|x| x.as_str()).unwrap_or("source");
            let url = s.get("url").and_then(|x| x.as_str()).map(|x| x.to_string());
            out.push(Dependency::new(format!("source:{name}"), "package-source", None, url));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- PHP
fn parse_composer_json(text: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (key, scope) in [("require", "dependencies"), ("require-dev", "dev")] {
        if let Some(obj) = v.get(key).and_then(|o| o.as_object()) {
            for (name, spec) in obj {
                out.push(Dependency::new(
                    name.clone(),
                    scope,
                    spec.as_str().map(|s| s.to_string()),
                    None,
                ));
            }
        }
    }
    if let Some(repos) = v.get("repositories") {
        let list: Vec<&serde_json::Value> = match repos {
            serde_json::Value::Array(a) => a.iter().collect(),
            serde_json::Value::Object(o) => o.values().collect(),
            _ => vec![],
        };
        for (i, r) in list.iter().enumerate() {
            let url = r.get("url").and_then(|u| u.as_str()).map(|s| s.to_string());
            let ty = r.get("type").and_then(|u| u.as_str()).unwrap_or("repo");
            out.push(Dependency::new(
                format!("repository:{ty}#{i}"),
                "package-source",
                None,
                url,
            ));
        }
    }
    if let Some(scripts) = v.get("scripts").and_then(|o| o.as_object()) {
        for (hook, cmd) in scripts {
            if hook.starts_with("post-") || hook.starts_with("pre-") {
                out.push(Dependency::new(
                    format!("script:{hook}"),
                    "lifecycle-script",
                    Some(cmd.to_string()),
                    None,
                ));
            }
        }
    }
    Ok(out)
}

fn parse_composer_lock(text: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (key, scope) in [("packages", "lock"), ("packages-dev", "lock-dev")] {
        if let Some(arr) = v.get(key).and_then(|a| a.as_array()) {
            for p in arr {
                let name = p.get("name").and_then(|x| x.as_str()).unwrap_or_default();
                let version = p.get("version").and_then(|x| x.as_str()).map(|s| s.to_string());
                let source = p
                    .get("source")
                    .and_then(|s| s.get("url"))
                    .or_else(|| p.get("dist").and_then(|s| s.get("url")))
                    .and_then(|u| u.as_str())
                    .map(|s| registry_host_or_url(s.to_string()));
                out.push(Dependency::new(name, scope, version, source));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- Java
fn parse_pom(text: &str) -> Vec<Dependency> {
    static DEP: OnceLock<Regex> = OnceLock::new();
    static TAG: OnceLock<Regex> = OnceLock::new();
    static REPO: OnceLock<Regex> = OnceLock::new();
    let dep = DEP.get_or_init(|| Regex::new(r"(?s)<(dependency|plugin)>(.*?)</(dependency|plugin)>").unwrap());
    let tag = TAG.get_or_init(|| Regex::new(r"(?s)<(groupId|artifactId|version|scope)>\s*(.*?)\s*</").unwrap());
    let repo =
        REPO.get_or_init(|| Regex::new(r"(?s)<(repository|pluginRepository)>.*?<url>\s*(.*?)\s*</url>").unwrap());
    let mut out = Vec::new();
    for c in dep.captures_iter(text) {
        let kind = &c[1];
        let body = &c[2];
        let mut fields: BTreeMap<String, String> = BTreeMap::new();
        for t in tag.captures_iter(body) {
            fields.entry(t[1].to_string()).or_insert_with(|| t[2].to_string());
        }
        let name = format!(
            "{}:{}",
            fields.get("groupId").cloned().unwrap_or_default(),
            fields.get("artifactId").cloned().unwrap_or_default()
        );
        let scope = if kind == "plugin" {
            "plugin".to_string()
        } else {
            fields.get("scope").cloned().unwrap_or_else(|| "compile".into())
        };
        out.push(Dependency::new(name, scope, fields.get("version").cloned(), None));
    }
    for (i, c) in repo.captures_iter(text).enumerate() {
        out.push(Dependency::new(
            format!("repository#{i}"),
            "package-source",
            None,
            Some(c[2].to_string()),
        ));
    }
    out
}

fn parse_gradle(text: &str) -> Vec<Dependency> {
    static DEP: OnceLock<Regex> = OnceLock::new();
    static REPO: OnceLock<Regex> = OnceLock::new();
    let dep = DEP.get_or_init(|| {
        Regex::new(r#"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt|classpath|compile|testCompile)\s*\(?\s*['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?['"]"#).unwrap()
    });
    let repo = REPO.get_or_init(|| Regex::new(r#"(?m)\burl\s*[=(]?\s*(uri\()?\s*['"]([^'"]+)['"]"#).unwrap());
    let mut out: Vec<Dependency> = dep
        .captures_iter(text)
        .map(|c| {
            Dependency::new(
                format!("{}:{}", &c[2], &c[3]),
                c[1].to_string(),
                c.get(4).map(|m| m.as_str().to_string()),
                None,
            )
        })
        .collect();
    for (i, c) in repo.captures_iter(text).enumerate() {
        out.push(Dependency::new(
            format!("repository#{i}"),
            "package-source",
            None,
            Some(c[2].to_string()),
        ));
    }
    out
}

// ---------------------------------------------------------------- Go
fn parse_go_mod(text: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut block: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == ")" {
            block = None;
            continue;
        }
        let (directive, rest) = if let Some(b) = &block {
            (b.clone(), line.to_string())
        } else {
            let mut it = line.splitn(2, char::is_whitespace);
            let d = it.next().unwrap_or("").to_string();
            let r = it.next().unwrap_or("").trim().to_string();
            if r == "(" {
                block = Some(d);
                continue;
            }
            (d, r)
        };
        match directive.as_str() {
            "require" => {
                let f: Vec<&str> = rest.split_whitespace().collect();
                if f.len() >= 2 {
                    out.push(Dependency::new(f[0], "require", Some(f[1].to_string()), None));
                }
            }
            "replace" => {
                if let Some((from, to)) = rest.split_once("=>") {
                    let from = from.split_whitespace().next().unwrap_or("");
                    let to_f: Vec<&str> = to.split_whitespace().collect();
                    let target = to_f.join(" ");
                    out.push(Dependency::new(
                        from,
                        "replace",
                        to_f.get(1).map(|s| s.to_string()),
                        Some(format!("replace:{target}")),
                    ));
                }
            }
            _ => {}
        }
    }
    out
}

fn parse_go_sum(text: &str) -> Vec<Dependency> {
    let mut out: Vec<Dependency> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 || f[1].ends_with("/go.mod") {
                return None;
            }
            Some(Dependency::new(
                f[0],
                "lock",
                Some(f[1].to_string()),
                Some(f[2].to_string()),
            ))
        })
        .collect();
    out.dedup();
    out
}

// ---------------------------------------------------------------- Ruby
fn parse_gemfile(text: &str) -> Vec<Dependency> {
    static GEM: OnceLock<Regex> = OnceLock::new();
    static SRC: OnceLock<Regex> = OnceLock::new();
    static VER: OnceLock<Regex> = OnceLock::new();
    static ORIGIN: OnceLock<Regex> = OnceLock::new();
    let gem = GEM.get_or_init(|| Regex::new(r#"^\s*gem\s+['"]([^'"]+)['"](.*)$"#).unwrap());
    let src = SRC.get_or_init(|| Regex::new(r#"^\s*source\s+['"]([^'"]+)['"]"#).unwrap());
    let ver_re = VER.get_or_init(|| Regex::new(r#"['"]([~><=!\s\d.]+[\d.]+)['"]"#).unwrap());
    let origin_re = ORIGIN.get_or_init(|| Regex::new(r#"(git|github|path|source)\s*:\s*['"]([^'"]+)['"]"#).unwrap());
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(c) = gem.captures(line) {
            let rest = &c[2];
            let ver = ver_re.captures(rest).map(|m| m[1].to_string());
            let source = origin_re.captures(rest).map(|m| format!("{}:{}", &m[1], &m[2]));
            out.push(Dependency::new(c[1].to_string(), "dependencies", ver, source));
        } else if let Some(c) = src.captures(line) {
            out.push(Dependency::new(
                "source",
                "package-source",
                None,
                Some(c[1].to_string()),
            ));
        }
    }
    out
}

fn parse_gemfile_lock(text: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut remote: Option<String> = None;
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_specs = false;
            remote = None;
            continue;
        }
        let t = line.trim();
        if let Some(r) = t.strip_prefix("remote:") {
            remote = Some(r.trim().to_string());
        } else if t == "specs:" {
            in_specs = true;
        } else if in_specs && line.starts_with("    ") && !line.starts_with("      ") {
            if let Some((name, ver)) = t.split_once(' ') {
                out.push(Dependency::new(
                    name,
                    "lock",
                    Some(ver.trim_matches(|c| c == '(' || c == ')').to_string()),
                    remote.clone(),
                ));
            }
        }
    }
    out
}

// ---------------------------------------------------------------- Comparison

/// Compares dependencies before/after.
pub fn diff_deps(old: &[Dependency], new: &[Dependency]) -> Vec<DepChange> {
    let key = |d: &Dependency| (d.name.clone(), d.scope.clone());
    let mut o: BTreeMap<(String, String), &Dependency> = BTreeMap::new();
    for d in old {
        o.insert(key(d), d);
    }
    let mut n: BTreeMap<(String, String), &Dependency> = BTreeMap::new();
    for d in new {
        n.insert(key(d), d);
    }
    let mut out = Vec::new();
    for (k, nd) in &n {
        match o.get(k) {
            None => out.push(DepChange {
                name: k.0.clone(),
                scope: k.1.clone(),
                kind: DepChangeKind::Added,
                old_version: None,
                new_version: nd.version.clone(),
                old_source: None,
                new_source: nd.source.clone(),
                external: nd.is_external(),
            }),
            Some(od) => {
                let kind = if od.source != nd.source {
                    Some(DepChangeKind::SourceChanged)
                } else if od.version != nd.version {
                    Some(DepChangeKind::VersionChanged)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    out.push(DepChange {
                        name: k.0.clone(),
                        scope: k.1.clone(),
                        kind,
                        old_version: od.version.clone(),
                        new_version: nd.version.clone(),
                        old_source: od.source.clone(),
                        new_source: nd.source.clone(),
                        external: nd.is_external(),
                    });
                }
            }
        }
    }
    for (k, od) in &o {
        if !n.contains_key(k) {
            out.push(DepChange {
                name: k.0.clone(),
                scope: k.1.clone(),
                kind: DepChangeKind::Removed,
                old_version: od.version.clone(),
                new_version: None,
                old_source: od.source.clone(),
                new_source: None,
                external: od.is_external(),
            });
        }
    }
    out
}

/// Analyses a modified dependency file from its before/after contents.
pub fn analyze_manifest(change: &FileChange, old: Option<&[u8]>, new: Option<&[u8]>) -> Option<ManifestReport> {
    let format = ecosystem_for(&change.path).or_else(|| change.old_path.as_deref().and_then(ecosystem_for))?;
    let mut parse_error = None;
    let mut parse_side = |data: Option<&[u8]>, label: &str| -> Vec<Dependency> {
        match data {
            None => vec![],
            Some(d) => match parse(format, &String::from_utf8_lossy(d)) {
                Ok(v) => v,
                Err(e) => {
                    parse_error = Some(format!("cannot parse {label}: {e}"));
                    vec![]
                }
            },
        }
    };
    let old_deps = parse_side(old, "of the reference version");
    let new_deps = parse_side(new, "of the fork version");
    Some(ManifestReport {
        path: change.path.clone(),
        ecosystem: format.ecosystem().to_string(),
        format,
        lockfile: format.is_lockfile(),
        status: change.status,
        parse_error,
        changes: diff_deps(&old_deps, &new_deps),
    })
}

/// Aggregates manifest reports.
pub fn summarize(manifests: Vec<ManifestReport>) -> DependencyReport {
    let mut r = DependencyReport {
        manifests,
        ..Default::default()
    };
    for m in &r.manifests {
        for c in &m.changes {
            match c.kind {
                DepChangeKind::Added => r.added += 1,
                DepChangeKind::Removed => r.removed += 1,
                DepChangeKind::VersionChanged => r.version_changed += 1,
                DepChangeKind::SourceChanged => r.source_changed += 1,
            }
            if c.external && c.kind != DepChangeKind::Removed {
                r.external += 1;
            }
        }
    }
    r
}

/// Turns risky dependency changes into security findings.
pub fn dependency_findings(report: &DependencyReport) -> Vec<Finding> {
    let mut out = Vec::new();
    let mk = |m: &ManifestReport, c: &DepChange, sev: Severity, conf: Confidence, title: &str, why: String| Finding {
        id: String::new(),
        rule_id: "DEP".into(),
        title: title.into(),
        category: Category::Dependencies,
        severity: sev,
        confidence: conf,
        file: m.path.clone(),
        line: None,
        old_line: None,
        change: c.kind.label().into(),
        old_code: c.old_version.clone().map(|v| {
            format!(
                "{} {}{}",
                c.name,
                v,
                c.old_source.as_deref().map(|s| format!(" ({s})")).unwrap_or_default()
            )
        }),
        new_code: c.new_version.clone().or(c.new_source.clone()).map(|v| {
            format!(
                "{} {}{}",
                c.name,
                v,
                c.new_source.as_deref().map(|s| format!(" ({s})")).unwrap_or_default()
            )
        }),
        justification: why,
        source: "dependencies".into(),
        commits: vec![],
    };
    for m in &report.manifests {
        // For lockfiles, only sources are raised as findings (details are in the dependencies section).
        for c in &m.changes {
            if c.scope == "lifecycle-script" && c.kind != DepChangeKind::Removed {
                out.push(mk(
                    m,
                    c,
                    Severity::High,
                    Confidence::High,
                    "Lifecycle script added/modified",
                    format!(
                        "The `{}` script runs automatically when dependencies are installed.",
                        c.name
                    ),
                ));
                continue;
            }
            if c.scope == "package-source" || c.scope == "pip-option" {
                if c.kind != DepChangeKind::Removed {
                    out.push(mk(m, c, Severity::High, Confidence::Medium, "Package source added/modified",
                        "A dependency download source was added or modified: risk of dependency confusion or malicious registry.".into()));
                }
                continue;
            }
            match c.kind {
                DepChangeKind::SourceChanged => out.push(mk(m, c, Severity::High, Confidence::Medium, "Dependency source changed",
                    format!("The source of `{}` changed ({} → {}).", c.name, c.old_source.as_deref().unwrap_or("registry"), c.new_source.as_deref().unwrap_or("registry")))),
                DepChangeKind::Added if c.external => out.push(mk(m, c, Severity::Medium, Confidence::High, "External dependency (Git/URL/path) added",
                    format!("`{}` comes from a source outside the official registry: content cannot be verified by version.", c.name))),
                DepChangeKind::Added if !m.lockfile => out.push(mk(m, c, Severity::Low, Confidence::High, "Dependency added",
                    format!("New dependency `{}`: check its legitimacy (typosquatting, maintenance, vulnerabilities).", c.name))),
                DepChangeKind::VersionChanged if !m.lockfile => out.push(mk(m, c, Severity::Info, Confidence::High, "Dependency version changed",
                    format!("`{}` : {} → {}.", c.name, c.old_version.as_deref().unwrap_or("?"), c.new_version.as_deref().unwrap_or("?")))),
                DepChangeKind::Removed if !m.lockfile => out.push(mk(m, c, Severity::Info, Confidence::High, "Dependency removed",
                    format!("`{}` was removed: check whether it provided a security function.", c.name))),
                _ => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_git_dependency() {
        let d = parse(
            DepFormat::CargoToml,
            "[dependencies]\nserde = \"1\"\nevil = { git = \"https://x.org/evil\", rev = \"abc\" }\n",
        )
        .unwrap();
        let evil = d.iter().find(|d| d.name == "evil").unwrap();
        assert!(evil.is_external());
        assert!(!d.iter().find(|d| d.name == "serde").unwrap().is_external());
    }

    #[test]
    fn package_json_diff() {
        let a = parse(DepFormat::PackageJson, r#"{"dependencies":{"lodash":"^4.17.0"}}"#).unwrap();
        let b = parse(
            DepFormat::PackageJson,
            r#"{"dependencies":{"lodash":"^4.17.21","x":"github:a/b"},"scripts":{"postinstall":"node x.js"}}"#,
        )
        .unwrap();
        let c = diff_deps(&a, &b);
        assert!(c
            .iter()
            .any(|c| c.name == "lodash" && c.kind == DepChangeKind::VersionChanged));
        assert!(c.iter().any(|c| c.name == "x" && c.external));
        assert!(c.iter().any(|c| c.scope == "lifecycle-script"));
    }

    #[test]
    fn requirements_and_index() {
        let d = parse_requirements("requests==2.31.0\n--extra-index-url https://evil.example/simple\nflask>=2\n-e git+https://g.com/x.git#egg=x\n");
        assert!(d
            .iter()
            .any(|d| d.name == "requests" && d.version.as_deref() == Some("==2.31.0")));
        assert!(d.iter().any(|d| d.scope == "pip-option"));
        assert!(d.iter().any(|d| d.name == "x" && d.is_external()));
    }

    #[test]
    fn go_mod_replace() {
        let d = parse_go_mod(
            "module m\nrequire (\n github.com/a/b v1.2.3\n)\nreplace github.com/a/b => github.com/evil/b v1.2.4\n",
        );
        assert!(d.iter().any(|d| d.scope == "replace"));
    }

    #[test]
    fn yarn_lock_v1() {
        let d = parse_yarn_lock("lodash@^4.17.0, lodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc\"\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn gemfile_lock() {
        let d = parse_gemfile_lock(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n      x (>= 1)\n\nPLATFORMS\n  ruby\n",
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "rack");
    }

    #[test]
    fn pom_parse() {
        let d = parse_pom("<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>");
        assert_eq!(d[0].name, "g:a");
    }
}
