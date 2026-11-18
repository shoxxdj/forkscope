//! Detection of secrets introduced by the fork.
//!
//! Scans **added** lines first (added or modified files).
//! Detected values are never written in clear text in the reports.

use super::rules::{Confidence, Severity};
use crate::config::SecretsConfig;
use crate::diff::{ChangeStatus, FileChange};
use crate::utils::{basename, is_test_or_example_path, mask_secret, shannon_entropy, truncate};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Potential secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretFinding {
    pub id: String,
    pub detector: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Masked value.
    pub masked_value: String,
    /// Context line (value masked).
    pub context: String,
    pub in_test_or_example: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
}

struct Detector {
    id: &'static str,
    description: &'static str,
    severity: Severity,
    regex: Regex,
    /// Capture group containing the value (0 = whole match).
    group: usize,
    /// Generic detection subject to the entropy threshold.
    generic: bool,
}

fn detectors() -> &'static [Detector] {
    static D: OnceLock<Vec<Detector>> = OnceLock::new();
    D.get_or_init(|| {
        let d = |id, description, severity, re: &str, group, generic| Detector {
            id,
            description,
            severity,
            regex: Regex::new(re).unwrap_or_else(|e| panic!("invalid detector {id}: {e}")),
            group,
            generic,
        };
        vec![
            d("private-key", "Private key (PEM/OpenSSH/PGP)", Severity::Critical, r"-----BEGIN ((RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----", 0, false),
            d("aws-access-key", "AWS access key ID", Severity::High, r"\b((AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16})\b", 1, false),
            d("aws-secret-key", "AWS secret key", Severity::Critical, r#"(?i)aws.{0,20}(secret|private).{0,20}['"=:\s]+([A-Za-z0-9/+=]{40})\b"#, 2, false),
            d("github-token", "GitHub token", Severity::Critical, r"\b((ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b", 1, false),
            d("gitlab-token", "GitLab token", Severity::Critical, r"\b(glpat-[A-Za-z0-9_\-]{20,}|glptt-[A-Za-z0-9_\-]{20,}|GR1348941[A-Za-z0-9_\-]{20,})\b", 1, false),
            d("slack-token", "Slack token", Severity::High, r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b", 1, false),
            d("slack-webhook", "Webhook Slack", Severity::Medium, r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)", 1, false),
            d("stripe-key", "Stripe key", Severity::Critical, r"\b((sk|rk)_(live|test)_[A-Za-z0-9]{20,})\b", 1, false),
            d("google-api-key", "Google API key", Severity::High, r"\b(AIza[0-9A-Za-z_\-]{35})\b", 1, false),
            d("gcp-service-account", "GCP service account", Severity::Critical, r#""type"\s*:\s*"service_account""#, 0, false),
            d("azure-storage-key", "Azure storage key", Severity::Critical, r"AccountKey=([A-Za-z0-9+/=]{60,})", 1, false),
            d("npm-token", "npm token", Severity::High, r"\b(npm_[A-Za-z0-9]{36})\b|_authToken\s*=\s*([^\s$]{10,})", 0, false),
            d("pypi-token", "PyPI token", Severity::High, r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b", 1, false),
            d("openai-key", "OpenAI/Anthropic API key", Severity::High, r"\b(sk-(proj-|ant-)?[A-Za-z0-9_\-]{20,})\b", 1, false),
            d("sendgrid-key", "SendGrid key", Severity::High, r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", 1, false),
            d("twilio-key", "Twilio key", Severity::High, r"\b(SK[0-9a-fA-F]{32})\b", 1, false),
            d("jwt", "JWT token", Severity::Medium, r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b", 1, false),
            d("url-credentials", "Credentials in a URL", Severity::High, r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@'\x22]+:([^/\s@'\x22]{3,})@[^/\s'\x22]+", 1, false),
            d("password-assignment", "Hard-coded password", Severity::High, r#"(?i)\b(pass(word|wd)?|pwd|db_?pass(word)?|admin_?pass(word)?)\b['"]?\s*[:=]>?\s*['"]([^'"\s$%{}<>]{4,})['"]"#, 4, true),
            d("generic-secret", "Hard-coded secret / token", Severity::Medium, r#"(?i)\b([a-z0-9_.\-]*(secret|token|api_?key|apikey|access_?key|auth_?key|client_?secret|private_?key|credential)[a-z0-9_.\-]*)\b['"]?\s*[:=]>?\s*['"]([^'"\s$%{}<>]{8,})['"]"#, 3, true),
        ]
    })
}

fn placeholder_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)^(changeme|change_me|example|xxx+|your[_-].*|<.*>|\*+|\.\.\.|null|none|true|false|undefined|todo|dummy|sample|placeholder|redacted|secret|password|test|foo|bar|replace_?me|[x0]+)$").unwrap()
    })
}

/// Sensitive files by name.
fn sensitive_file(path: &str) -> Option<(&'static str, Severity)> {
    let name = basename(path).to_ascii_lowercase();
    if matches!(name.as_str(), "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519") {
        return Some(("SSH private key", Severity::Critical));
    }
    if name.ends_with(".pem")
        || name.ends_with(".key")
        || name.ends_with(".p12")
        || name.ends_with(".pfx")
        || name.ends_with(".jks")
        || name.ends_with(".keystore")
        || name.ends_with(".ppk")
    {
        return Some(("Key / certificate file", Severity::High));
    }
    if name == ".env"
        || (name.starts_with(".env.")
            && !name.ends_with(".example")
            && !name.ends_with(".sample")
            && !name.ends_with(".dist")
            && !name.ends_with(".template"))
    {
        return Some(("Environment file (.env)", Severity::Medium));
    }
    if matches!(
        name.as_str(),
        ".npmrc"
            | ".pypirc"
            | ".netrc"
            | ".git-credentials"
            | "credentials"
            | "credentials.json"
            | ".htpasswd"
            | ".dockercfg"
    ) || path.ends_with(".docker/config.json")
    {
        return Some(("Credentials file", Severity::High));
    }
    None
}

/// Masks every value recognised as a secret in a text.
pub fn mask_in_text(text: &str) -> String {
    let mut out = text.to_string();
    for d in detectors() {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for caps in d.regex.captures_iter(&out) {
            let m = if d.group == 0 {
                caps.get(0)
            } else {
                caps.get(d.group).or_else(|| caps.get(0))
            };
            if let Some(m) = m {
                spans.push((m.start(), m.end()));
            }
        }
        for (s, e) in spans.into_iter().rev() {
            let masked = if d.id == "private-key" {
                "-----BEGIN [PRIVATE KEY MASKED]-----".to_string()
            } else {
                mask_secret(&out[s..e])
            };
            out.replace_range(s..e, &masked);
        }
    }
    out
}

/// Searches for secrets in the added lines of the changes.
pub fn scan_changes(changes: &[FileChange], cfg: &SecretsConfig) -> Vec<SecretFinding> {
    let allow: Vec<Regex> = cfg.allowlist.iter().filter_map(|a| Regex::new(a).ok()).collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in changes {
        if c.status == ChangeStatus::Deleted {
            continue;
        }
        let test = is_test_or_example_path(&c.path);
        if matches!(
            c.status,
            ChangeStatus::Added | ChangeStatus::Renamed | ChangeStatus::Moved | ChangeStatus::Modified
        ) {
            if let Some((desc, sev)) = sensitive_file(&c.path) {
                if c.status == ChangeStatus::Added || c.lines_added > 0 || c.is_binary {
                    out.push(SecretFinding {
                        id: String::new(),
                        detector: "sensitive-file".into(),
                        description: format!(
                            "{desc} {} by the fork",
                            if c.status == ChangeStatus::Added {
                                "added"
                            } else {
                                "modified"
                            }
                        ),
                        severity: if test { sev.lower() } else { sev },
                        confidence: Confidence::Medium,
                        file: c.path.clone(),
                        line: None,
                        masked_value: "(file)".into(),
                        context: String::new(),
                        in_test_or_example: test,
                        commits: c.commits.clone(),
                    });
                }
            }
        }
        for (_, line_no, text) in c.added_lines() {
            for d in detectors() {
                for caps in d.regex.captures_iter(text) {
                    let m = if d.group == 0 {
                        caps.get(0)
                    } else {
                        caps.get(d.group).or_else(|| caps.iter().skip(1).flatten().next())
                    };
                    let Some(m) = m else { continue };
                    let value = m.as_str();
                    if allow.iter().any(|a| a.is_match(value)) {
                        continue;
                    }
                    let mut confidence = Confidence::High;
                    let mut severity = d.severity;
                    if d.generic {
                        if value.contains("${") || value.starts_with('$') || value.contains("{{") {
                            continue; // interpolation, not a value
                        }
                        let placeholder = placeholder_re().is_match(value);
                        let entropy = shannon_entropy(value);
                        if placeholder {
                            confidence = Confidence::Low;
                            severity = severity.lower();
                        } else if entropy < cfg.min_entropy && d.id != "password-assignment" {
                            continue;
                        } else {
                            confidence = Confidence::Medium;
                        }
                    }
                    if test {
                        confidence = confidence.lower();
                    }
                    if !seen.insert((c.path.clone(), line_no, m.start(), m.end())) {
                        continue;
                    }
                    out.push(SecretFinding {
                        id: String::new(),
                        detector: d.id.into(),
                        description: d.description.into(),
                        severity,
                        confidence,
                        file: c.path.clone(),
                        line: line_no,
                        masked_value: if d.id == "private-key" {
                            "[PRIVATE KEY MASKED]".into()
                        } else {
                            mask_secret(value)
                        },
                        context: truncate(&mask_in_text(text.trim()), 200),
                        in_test_or_example: test,
                        commits: c.commits.clone(),
                    });
                }
            }
        }
    }
    // Same line detected by a specific and a generic detector: keep the most severe.
    out.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(b.severity.cmp(&a.severity))
    });
    let mut kept: Vec<SecretFinding> = Vec::new();
    for f in out {
        if let Some(prev) = kept.last() {
            if prev.file == f.file
                && prev.line == f.line
                && f.line.is_some()
                && (f.detector == "generic-secret" || f.detector == "password-assignment")
            {
                continue;
            }
        }
        kept.push(f);
    }
    kept.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });
    for (i, f) in kept.iter_mut().enumerate() {
        f.id = format!("S-{:04}", i + 1);
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::similarity::whole_file_hunk;

    fn added(path: &str, text: &str) -> FileChange {
        let mut c = FileChange::new(path.into(), ChangeStatus::Added);
        let (h, n) = whole_file_hunk(text, true);
        c.hunks = h;
        c.lines_added = n;
        c
    }

    #[test]
    fn finds_and_masks_aws_key() {
        // Fake key assembled at runtime so that it never appears verbatim in the repository.
        let key = format!("{}{}", "AKIA", "IOSFODNN7ABCDEFG");
        let c = added("src/cfg.py", &format!("AWS_KEY = '{key}'\n"));
        let f = scan_changes(&[c], &SecretsConfig::default());
        assert_eq!(f[0].detector, "aws-access-key");
        assert!(!f[0].masked_value.contains("ABCDEFG"));
        assert!(!f[0].context.contains("ABCDEFG"));
    }

    #[test]
    fn test_files_not_ignored() {
        let c = added(
            "tests/conf.js",
            &format!(
                "const token = \"{}{}\";\n",
                "ghp_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
            ),
        );
        let f = scan_changes(&[c], &SecretsConfig::default());
        assert_eq!(f.len(), 1);
        assert!(f[0].in_test_or_example);
    }

    #[test]
    fn interpolation_ignored() {
        let c = added("a.yml", "password: \"${DB_PASSWORD}\"\n");
        assert!(scan_changes(&[c], &SecretsConfig::default()).is_empty());
    }

    #[test]
    fn private_key_masked() {
        let t = mask_in_text("-----BEGIN RSA PRIVATE KEY-----");
        assert!(t.contains("MASKED"));
    }
}
