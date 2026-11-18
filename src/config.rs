//! ForkScope configuration (optional TOML file).
//!
//! Every section is optional; missing values take their
//! default value. See `config.example.toml`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Directories excluded by default (generated or large).
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &["node_modules", "target", "build", "dist", "vendor", ".venv", ".next"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub exclude: ExcludeConfig,
    pub diff: DiffConfig,
    pub reference: ReferenceConfig,
    pub history: HistoryConfig,
    pub security: SecurityConfig,
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExcludeConfig {
    /// Use the default exclusion list.
    pub use_defaults: bool,
    /// Additional excluded directory names (at any depth).
    pub dirs: Vec<String>,
    /// Additional glob patterns (e.g. `docs/**`, `**/*.min.js`).
    pub globs: Vec<String>,
    /// Directories no longer excluded (removed from the default list).
    pub keep_dirs: Vec<String>,
}

impl Default for ExcludeConfig {
    fn default() -> Self {
        Self {
            use_defaults: true,
            dirs: vec![],
            globs: vec![],
            keep_dirs: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiffConfig {
    /// If not empty, only these extensions are compared (without the dot; "" = no extension).
    pub include_extensions: Vec<String>,
    /// Ignored extensions.
    pub exclude_extensions: Vec<String>,
    /// Similarity threshold (0-1) to detect a rename without Git information.
    pub rename_threshold: f64,
    /// Maximum size (bytes) of a text file for line diffs.
    pub max_text_size: u64,
    /// Maximum number of pairs evaluated for rename detection.
    pub max_rename_pairs: usize,
    /// Context lines in diffs.
    pub context_lines: usize,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            include_extensions: vec![],
            exclude_extensions: vec![],
            rename_threshold: 0.6,
            max_text_size: 2 * 1024 * 1024,
            max_rename_pairs: 50_000,
            context_lines: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReferenceConfig {
    /// Maximum number of source commits walked during estimation.
    pub max_commits: usize,
    /// Below this number of commits, all of them are evaluated.
    pub exhaustive_threshold: usize,
    /// Number of samples in the coarse phase.
    pub coarse_samples: usize,
    /// Number of candidates evaluated finely (content similarity).
    pub top_candidates: usize,
    /// Weight of dependency / version files in the score.
    pub manifest_weight: f64,
}

impl Default for ReferenceConfig {
    fn default() -> Self {
        Self {
            max_commits: 5000,
            exhaustive_threshold: 400,
            coarse_samples: 200,
            top_candidates: 5,
            manifest_weight: 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    /// Maximum number of fork commits detailed.
    pub max_client_commits: usize,
    /// Maximum number of source commits for which a patch-id is computed.
    pub max_upstream_patch_ids: usize,
    /// Analyse the diff of each fork commit (suspicious commit detection).
    pub analyze_commit_diffs: bool,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            max_client_commits: 2000,
            max_upstream_patch_ids: 3000,
            analyze_commit_diffs: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Built-in rule IDs to disable.
    pub disable_rules: Vec<String>,
    /// Custom rules.
    pub rules: Vec<CustomRule>,
}

/// Custom rule declared in the configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    pub id: String,
    pub title: String,
    /// authentication | authorization | cryptography | input_validation | configuration | dependencies | secrets | other
    pub category: String,
    /// info | low | medium | high | critical
    pub severity: String,
    /// removed | added | file_changed | file_added | file_deleted
    pub on: String,
    /// Regular expression applied to lines (required for removed/added).
    #[serde(default)]
    pub pattern: Option<String>,
    /// Regular expression filtering the affected paths.
    #[serde(default)]
    pub path: Option<String>,
    /// Exclusion regular expression (lines).
    #[serde(default)]
    pub exclude: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    /// low | medium | high
    #[serde(default)]
    pub confidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    /// Minimum entropy for generic detections (assignments).
    pub min_entropy: f64,
    /// Regular expressions of values to ignore.
    pub allowlist: Vec<String>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            min_entropy: 3.0,
            allowlist: vec![],
        }
    }
}

impl Config {
    /// Loads the configuration from a TOML file (or the default configuration).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else { return Ok(Self::default()) };
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading configuration file {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("invalid configuration file: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if !(0.0..=1.0).contains(&self.diff.rename_threshold) {
            anyhow::bail!("diff.rename_threshold must be between 0 and 1");
        }
        if self.reference.max_commits == 0 {
            anyhow::bail!("reference.max_commits must be > 0");
        }
        Ok(())
    }

    /// Effective list of excluded directories.
    pub fn excluded_dirs(&self) -> Vec<String> {
        let mut dirs: Vec<String> = if self.exclude.use_defaults {
            DEFAULT_EXCLUDED_DIRS.iter().map(|s| s.to_string()).collect()
        } else {
            vec![]
        };
        dirs.extend(self.exclude.dirs.iter().cloned());
        dirs.retain(|d| !self.exclude.keep_dirs.contains(d));
        dirs.sort();
        dirs.dedup();
        dirs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example_config() {
        let text = include_str!("../config.example.toml");
        let cfg: Config = toml::from_str(text).expect("config.example.toml must be valid");
        cfg.validate().unwrap();
    }

    #[test]
    fn keep_dirs_removes_default() {
        let mut cfg = Config::default();
        cfg.exclude.keep_dirs = vec!["build".into()];
        assert!(!cfg.excluded_dirs().contains(&"build".to_string()));
        assert!(cfg.excluded_dirs().contains(&"node_modules".to_string()));
    }
}
