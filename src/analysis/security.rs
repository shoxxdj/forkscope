//! Audit-oriented analysis: rules applied to the added and removed lines
//! of the diffs (not just to file names).

use super::rules::{AnalysisContext, Analyzer, Confidence, Finding, Rule, RuleSet, Severity, Trigger};
use super::secrets::mask_in_text;
use crate::diff::{ChangeStatus, FileChange, LineKind};
use crate::utils::{is_comment_line, is_test_or_example_path, normalize_code_line, truncate};
use anyhow::Result;
use std::collections::{HashMap, HashSet};

const MAX_PER_RULE_AND_FILE: usize = 10;
const MAX_CODE_LINES: usize = 6;

/// Rule-based analyzer (built-in + custom).
pub struct RuleAnalyzer {
    pub rules: RuleSet,
}

impl Analyzer for RuleAnalyzer {
    fn name(&self) -> &str {
        "builtin"
    }
    fn analyze(&self, ctx: &AnalysisContext) -> Result<Vec<Finding>> {
        Ok(analyze_changes(&self.rules, ctx.changes))
    }
}

/// Applies the rules to a set of file changes.
pub fn analyze_changes(rules: &RuleSet, changes: &[FileChange]) -> Vec<Finding> {
    let mut out = Vec::new();
    for change in changes {
        if change.status == ChangeStatus::Identical {
            continue;
        }
        for rule in &rules.rules {
            if !rule.applies_to_path(&change.path)
                && !change
                    .old_path
                    .as_deref()
                    .map(|p| rule.applies_to_path(p))
                    .unwrap_or(false)
            {
                continue;
            }
            // Built-in line rules ignore documentation (noise).
            if rule.builtin
                && matches!(rule.trigger, Trigger::Added | Trigger::Removed)
                && is_documentation(&change.path)
                && rule.id != "OTHER-001"
            {
                continue;
            }
            out.extend(apply_rule(rule, change));
        }
    }
    dedupe(out)
}

/// Documentation files (analysed at file level only).
pub fn is_documentation(path: &str) -> bool {
    let name = crate::utils::basename(path).to_ascii_lowercase();
    matches!(
        crate::utils::extension(path).as_deref(),
        Some("md" | "rst" | "adoc" | "txt" | "markdown" | "rdoc")
    ) && !name.starts_with("requirements")
        || name.starts_with("license")
        || name.starts_with("changelog")
        || name.starts_with("authors")
}

fn file_summary(change: &FileChange) -> String {
    format!(
        "file {} (+{} / -{} lines)",
        change.status.label(),
        change.lines_added,
        change.lines_removed
    )
}

fn base_finding(rule: &Rule, change: &FileChange) -> Finding {
    let mut f = Finding {
        id: String::new(),
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        category: rule.category,
        severity: rule.severity,
        confidence: rule.confidence,
        file: change.path.clone(),
        line: None,
        old_line: None,
        change: "file".into(),
        old_code: None,
        new_code: None,
        justification: rule.justification.clone(),
        source: if rule.builtin {
            "builtin".into()
        } else {
            "custom".into()
        },
        commits: change.commits.clone(),
    };
    if is_test_or_example_path(&change.path) {
        f.confidence = f.confidence.lower();
        f.justification
            .push_str(" (test/example file: not considered safe, reduced confidence)");
    }
    f
}

fn code_block(lines: &[&str]) -> Option<String> {
    if lines.is_empty() {
        return None;
    }
    let mut v: Vec<String> = lines
        .iter()
        .take(MAX_CODE_LINES)
        .map(|l| mask_in_text(&truncate(l, 300)))
        .collect();
    if lines.len() > MAX_CODE_LINES {
        v.push(format!("… ({} more lines)", lines.len() - MAX_CODE_LINES));
    }
    Some(v.join("\n"))
}

fn apply_rule(rule: &Rule, change: &FileChange) -> Vec<Finding> {
    match rule.trigger {
        Trigger::FileChanged | Trigger::FileAdded | Trigger::FileDeleted => {
            let ok = match rule.trigger {
                Trigger::FileAdded => change.status == ChangeStatus::Added,
                Trigger::FileDeleted => change.status == ChangeStatus::Deleted,
                _ => true,
            };
            if !ok {
                return vec![];
            }
            if let Some(pat) = &rule.pattern {
                // File rule with a pattern: at least one changed line must match.
                let any = change
                    .added_lines()
                    .chain(change.removed_lines())
                    .any(|(_, _, t)| pat.is_match(t));
                if !any {
                    return vec![];
                }
            }
            let mut f = base_finding(rule, change);
            f.change = "file".into();
            f.justification = format!("{} — {}", f.justification, file_summary(change));
            vec![f]
        }
        Trigger::Added => {
            let Some(pat) = &rule.pattern else { return vec![] };
            let removed_norm: HashSet<String> =
                change.removed_lines().map(|(_, _, t)| normalize_code_line(t)).collect();
            let mut out = Vec::new();
            for (hi, line_no, text) in change.added_lines() {
                if !pat.is_match(text) || rule.exclude.as_ref().map(|e| e.is_match(text)).unwrap_or(false) {
                    continue;
                }
                if removed_norm.contains(&normalize_code_line(text)) {
                    continue; // line merely moved
                }
                let mut f = base_finding(rule, change);
                f.change = "added".into();
                f.line = line_no;
                f.new_code = code_block(&[text]);
                let olds: Vec<&str> = change.hunks[hi]
                    .lines
                    .iter()
                    .filter(|l| l.kind == LineKind::Removed)
                    .map(|l| l.text.as_str())
                    .collect();
                f.old_code = code_block(&olds);
                if is_comment_line(text) {
                    f.severity = f.severity.lower();
                    f.confidence = Confidence::Low;
                    f.justification.push_str(" (comment line)");
                }
                out.push(f);
                if out.len() >= MAX_PER_RULE_AND_FILE || rule.once_per_file {
                    break;
                }
            }
            if rule.once_per_file {
                let n = change.added_lines().filter(|(_, _, t)| pat.is_match(t)).count();
                if let Some(f) = out.first_mut() {
                    f.justification.push_str(&format!(" ({n} occurrence(s) in the file)"));
                }
            }
            out
        }
        Trigger::Removed => {
            let Some(pat) = &rule.pattern else { return vec![] };
            let added_norm: HashSet<String> = change.added_lines().map(|(_, _, t)| normalize_code_line(t)).collect();
            let mut out = Vec::new();
            let mut reported_hunks: HashSet<usize> = HashSet::new();
            for (hi, line_no, text) in change.removed_lines() {
                let Some(m) = pat.find(text) else { continue };
                if rule.exclude.as_ref().map(|e| e.is_match(text)).unwrap_or(false) || is_comment_line(text) {
                    continue;
                }
                if added_norm.contains(&normalize_code_line(text)) {
                    continue; // moved line, not removed
                }
                if !reported_hunks.insert(hi) {
                    continue; // one finding per hunk and per rule
                }
                let hunk = &change.hunks[hi];
                // Lines that are only re-indented (e.g. body of a removed `if`) are
                // not replacement code.
                let removed_norm_hunk: HashSet<String> = hunk
                    .lines
                    .iter()
                    .filter(|l| l.kind == LineKind::Removed)
                    .map(|l| normalize_code_line(&l.text))
                    .collect();
                let replacement: Vec<&str> = hunk
                    .lines
                    .iter()
                    .filter(|l| l.kind == LineKind::Added && !removed_norm_hunk.contains(&normalize_code_line(&l.text)))
                    .map(|l| l.text.as_str())
                    .collect();
                let removed_in_hunk: Vec<&str> = hunk
                    .lines
                    .iter()
                    .filter(|l| l.kind == LineKind::Removed && pat.is_match(&l.text))
                    .map(|l| l.text.as_str())
                    .collect();
                let token = m.as_str().to_ascii_lowercase();
                let token_kept = replacement
                    .iter()
                    .any(|l| l.to_ascii_lowercase().contains(&token) || pat.is_match(l));
                let mut f = base_finding(rule, change);
                f.old_line = line_no;
                f.line = hunk
                    .lines
                    .iter()
                    .find(|l| l.kind == LineKind::Added)
                    .and_then(|l| l.new_no)
                    .or(line_no);
                f.old_code = code_block(&removed_in_hunk);
                f.new_code = code_block(&replacement);
                if replacement.is_empty() || change.status == ChangeStatus::Deleted {
                    f.change = "removed".into();
                    f.line = None;
                } else if token_kept {
                    f.change = "modified".into();
                    f.severity = f.severity.lower();
                    f.justification.push_str(" The condition was modified while keeping the control element: check that it has not become less restrictive.");
                } else {
                    f.change = "replaced".into();
                    f.justification
                        .push_str(" The check was replaced by code that no longer contains this element.");
                }
                out.push(f);
                if out.len() >= MAX_PER_RULE_AND_FILE {
                    break;
                }
            }
            out
        }
    }
}

fn dedupe(mut v: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    v.retain(|f| seen.insert((f.rule_id.clone(), f.file.clone(), f.line, f.old_line)));
    v
}

/// Sorts and numbers findings.
pub fn finalize(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("F-{:04}", i + 1);
    }
    findings
}

/// Count by severity.
pub fn count_by_severity(findings: &[Finding]) -> HashMap<Severity, usize> {
    let mut m = HashMap::new();
    for f in findings {
        *m.entry(f.severity).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::similarity::build_hunks;

    fn change(old: &str, new: &str, path: &str) -> FileChange {
        let (hunks, a, r) = build_hunks(old, new, 3);
        let mut c = FileChange::new(path.into(), ChangeStatus::Modified);
        c.hunks = hunks;
        c.lines_added = a;
        c.lines_removed = r;
        c
    }

    #[test]
    fn detects_removed_admin_check() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change(
            "def delete(user):\n    if user.is_admin:\n        db.delete()\n",
            "def delete(user):\n    db.delete()\n",
            "app/views.py",
        );
        let f = analyze_changes(&rules, &[c]);
        assert!(
            f.iter().any(|f| f.rule_id == "AUTHZ-001" && f.change == "removed"),
            "{f:#?}"
        );
    }

    #[test]
    fn detects_weakened_condition() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change(
            "if user.is_admin:\n    allow()\n",
            "if user.is_admin or user.is_guest:\n    allow()\n",
            "app/views.py",
        );
        let f = analyze_changes(&rules, &[c]);
        let x = f.iter().find(|f| f.rule_id == "AUTHZ-001").expect("finding");
        assert_eq!(x.change, "modified");
    }

    #[test]
    fn moved_line_not_reported() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change(
            "a\nif user.is_admin:\nb\nc\nd\ne\nf\ng\n",
            "a\nb\nc\nd\ne\nf\ng\nif user.is_admin:\n",
            "x.py",
        );
        let f = analyze_changes(&rules, &[c]);
        assert!(!f.iter().any(|f| f.rule_id == "AUTHZ-001"));
    }

    #[test]
    fn detects_neutralized_condition() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change(
            "if not app.secret_key:\n    return None\n",
            "if False and not app.secret_key:\n    return None\n",
            "s.py",
        );
        assert!(analyze_changes(&rules, &[c]).iter().any(|f| f.rule_id == "AUTH-011"));
    }

    #[test]
    fn documentation_lines_are_ignored() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change("Use verify=True\n", "Use verify=False\n", "docs/tls.md");
        assert!(analyze_changes(&rules, &[c]).iter().all(|f| f.change == "file"));
    }

    #[test]
    fn detects_tls_disabled() {
        let rules = RuleSet::load(&Default::default()).unwrap();
        let c = change(
            "r = requests.get(url)\n",
            "r = requests.get(url, verify=False)\n",
            "client.py",
        );
        let f = analyze_changes(&rules, &[c]);
        assert!(f.iter().any(|f| f.rule_id == "CRYPTO-001"));
    }
}
