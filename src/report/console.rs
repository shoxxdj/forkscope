//! Console interface: step progress and coloured summary.

use super::ForkScopeReport;
use crate::analysis::rules::Severity;
use crate::git::reference::Certainty;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, ContentArrangement, Table};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Mutex;
use std::time::Duration;

/// Feedback during the analysis.
pub trait Progress: Sync {
    /// Start of a step.
    fn step(&self, index: usize, total: usize, message: &str);
    /// Detail of the current step.
    fn detail(&self, message: &str);
    /// End of the current step.
    fn done(&self, message: &str);
    /// Non-blocking warning.
    fn warn(&self, message: &str);
}

/// No output (tests, library use).
pub struct Silent;

impl Progress for Silent {
    fn step(&self, _: usize, _: usize, _: &str) {}
    fn detail(&self, _: &str) {}
    fn done(&self, _: &str) {}
    fn warn(&self, _: &str) {}
}

/// Console progress with animated spinners (on stderr).
pub struct ConsoleProgress {
    bar: Mutex<Option<ProgressBar>>,
    label: Mutex<String>,
}

impl Default for ConsoleProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleProgress {
    pub fn new() -> Self {
        Self {
            bar: Mutex::new(None),
            label: Mutex::new(String::new()),
        }
    }
}

impl Progress for ConsoleProgress {
    fn step(&self, index: usize, total: usize, message: &str) {
        let label = format!("{} {}", style(format!("[{index}/{total}]")).bold().dim(), message);
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
        );
        pb.enable_steady_tick(Duration::from_millis(90));
        pb.set_message(label.clone());
        *self.label.lock().unwrap() = label;
        *self.bar.lock().unwrap() = Some(pb);
    }
    fn detail(&self, message: &str) {
        if let Some(pb) = self.bar.lock().unwrap().as_ref() {
            pb.set_message(format!(
                "{} {}",
                self.label.lock().unwrap(),
                style(format!("— {message}")).dim()
            ));
        }
    }
    fn done(&self, message: &str) {
        let label = self.label.lock().unwrap().clone();
        if let Some(pb) = self.bar.lock().unwrap().take() {
            pb.finish_and_clear();
        }
        eprintln!("{} {} {}", style("✓").green().bold(), label, style(message).dim());
    }
    fn warn(&self, message: &str) {
        let bar = self.bar.lock().unwrap();
        let line = format!("  {} {}", style("⚠").yellow().bold(), style(message).yellow());
        match bar.as_ref() {
            Some(pb) => pb.println(line),
            None => eprintln!("{line}"),
        }
    }
}

/// Header (name and version).
pub fn print_banner() {
    eprintln!(
        "{} {} — fork / source divergence analysis\n",
        style("ForkScope").cyan().bold(),
        style(format!("v{}", env!("CARGO_PKG_VERSION"))).dim()
    );
}

fn sev_color(s: Severity) -> Color {
    match s {
        Severity::Critical => Color::Magenta,
        Severity::High => Color::Red,
        Severity::Medium => Color::Yellow,
        Severity::Low => Color::Blue,
        Severity::Info => Color::Grey,
    }
}

/// Final summary on stdout.
pub fn print_summary(r: &ForkScopeReport, color: bool) {
    let mk = || {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(ContentArrangement::Dynamic);
        if !color {
            t.force_no_tty();
        }
        t
    };
    let mut t = mk();
    t.set_header(vec![Cell::new("Summary").add_attribute(Attribute::Bold), Cell::new("")]);
    t.add_row(vec![
        "Fork".to_string(),
        format!("{}\n{}", r.client.path, r.client.mode.label()),
    ]);
    t.add_row(vec!["Source".to_string(), r.upstream.url.clone()]);
    let refs = if r.reference.location.pointing_refs.is_empty() {
        r.reference.location.describe.clone().unwrap_or_default()
    } else {
        r.reference.location.pointing_refs.join(", ")
    };
    let certainty = match r.reference.certainty {
        Certainty::Exact => "certain (Git ancestry)".to_string(),
        Certainty::Estimated => format!(
            "ESTIMATED — confidence {:.0} % ({})",
            r.reference.confidence, r.reference.confidence_level
        ),
    };
    let ref_color = match r.reference.certainty {
        Certainty::Exact => Color::Green,
        Certainty::Estimated if r.reference.confidence >= 85.0 => Color::Green,
        Certainty::Estimated if r.reference.confidence >= 60.0 => Color::Yellow,
        _ => Color::Red,
    };
    t.add_row(vec![
        Cell::new("Identified reference"),
        Cell::new(format!(
            "{} {}\n{}\n{}",
            r.reference.commit.short,
            refs,
            super::graph::when(&r.reference.commit.committer_date),
            certainty
        ))
        .fg(ref_color),
    ]);
    if let Some(h) = &r.history {
        t.add_row(vec!["Specific commits".to_string(), h.client_commits_total.to_string()]);
    }
    let st = &r.diff.stats;
    t.add_row(vec![
        "Files".to_string(),
        format!(
            "{} added · {} deleted · {} modified · {} renamed/moved · {} identical",
            st.added,
            st.deleted,
            st.modified,
            st.renamed + st.moved,
            st.identical
        ),
    ]);
    t.add_row(vec![
        "Lines".to_string(),
        format!("+{} / −{}", st.lines_added, st.lines_removed),
    ]);
    t.add_row(vec![
        "Dependencies".to_string(),
        format!(
            "{} added · {} removed · {} versions · {} sources · {} external",
            r.dependencies.added,
            r.dependencies.removed,
            r.dependencies.version_changed,
            r.dependencies.source_changed,
            r.dependencies.external
        ),
    ]);
    t.add_row(vec!["Potential secrets".to_string(), r.secrets.len().to_string()]);
    let tl = &r.timeline;
    if let Some(d) = &tl.divergence {
        t.add_row(vec![
            Cell::new(if tl.divergence_estimated {
                "Divergence (estimated)"
            } else {
                "Divergence"
            }),
            Cell::new(format!("{} ({})", super::graph::when(&d.date), d.short)).fg(Color::Yellow),
        ]);
    }
    if let (Some(a), Some(b)) = (&tl.first_fork_commit, &tl.last_fork_commit) {
        t.add_row(vec![
            "Fork commits".to_string(),
            format!(
                "from {}\nto {}",
                super::graph::when(&a.date),
                super::graph::when(&b.date)
            ),
        ]);
    }
    if let Some(d) = &tl.last_disk_change {
        t.add_row(vec![
            "Last change on disk".to_string(),
            format!("{} ({})", super::graph::when(&d.date), d.path),
        ]);
    }
    if let Some(days) = tl.days_of_divergence {
        t.add_row(vec!["Divergence duration".to_string(), format!("{days} day(s)")]);
    }
    println!("{t}");
    if !tl.graph.nodes.is_empty() {
        println!("Divergence graph (newest at the top):\n{}", super::graph::ascii(tl));
    }

    let mut s = mk();
    s.set_header(Severity::ALL.iter().map(|sev| {
        Cell::new(sev.label())
            .fg(sev_color(*sev))
            .add_attribute(Attribute::Bold)
    }));
    s.add_row(
        Severity::ALL
            .iter()
            .map(|sev| Cell::new(r.security.counts.get(sev).copied().unwrap_or(0))),
    );
    println!("Security findings by severity:\n{s}");

    let top: Vec<_> = r
        .security
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .take(10)
        .collect();
    if !top.is_empty() {
        let mut t = mk();
        t.set_header(vec!["ID", "Severity", "File", "Title"]);
        for f in top {
            t.add_row(vec![
                Cell::new(&f.id),
                Cell::new(f.severity.label()).fg(sev_color(f.severity)),
                Cell::new(format!(
                    "{}{}",
                    f.file,
                    f.line
                        .map(|l| format!(":{l}"))
                        .or(f.old_line.map(|l| format!(" (ref. l.{l})")))
                        .unwrap_or_default()
                )),
                Cell::new(&f.title),
            ]);
        }
        println!("Top findings:\n{t}");
    }
    print_file_list(r);
    for w in &r.warnings {
        println!("{} {}", style("⚠").yellow(), w);
    }
}

/// List of changed files (those attributed to the fork first).
pub fn print_file_list(r: &ForkScopeReport) {
    const MAX: usize = 40;
    let mut files: Vec<_> = r.diff.files.iter().collect();
    files.sort_by(|a, b| {
        b.origin
            .is_client()
            .cmp(&a.origin.is_client())
            .then(a.path.cmp(&b.path))
    });
    println!(
        "Changed files ({}, {} attributed to the fork):",
        files.len(),
        r.diff.stats.client_changes
    );
    for c in files.iter().take(MAX) {
        let letter = super::status_letter(c.status).to_string();
        let letter = match c.status {
            crate::diff::ChangeStatus::Added => style(letter).green(),
            crate::diff::ChangeStatus::Deleted => style(letter).red(),
            _ => style(letter).yellow(),
        };
        let name = match &c.old_path {
            Some(o) => format!("{} ← {}", c.path, o),
            None => c.path.clone(),
        };
        let origin = if c.origin.is_client() {
            style(c.origin.label()).bold()
        } else {
            style(c.origin.label()).dim()
        };
        println!("  {} {}  {}", letter, name, origin);
    }
    if files.len() > MAX {
        println!("  … {} more (see {})", files.len() - MAX, super::FILE_LIST_TXT);
    }
}
