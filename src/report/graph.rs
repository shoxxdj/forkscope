//! Rendering of the source / fork divergence graph: SVG (report) and text
//! (console, Markdown).

use crate::analysis::rules::Severity;
use crate::git::timeline::{EdgeKind, GraphNode, Lane, NodeKind, Timeline};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Name of the generated SVG file.
pub const SVG_FILE: &str = "divergence-graph.svg";

const SOURCE: &str = "#0969da";
const FORK: &str = "#1a7f37";
const ALERT: &str = "#cf222e";
const DIVERGENCE: &str = "#bf8700";
const MUTED: &str = "#6e7781";
const TEXT: &str = "#24292f";

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Readable date (YYYY-MM-DD HH:MM:SS ±HH:MM) from an ISO date.
pub fn when(iso: &str) -> String {
    if iso.is_empty() {
        "—".into()
    } else {
        iso.replacen('T', " ", 1)
    }
}

/// Short date (YYYY-MM-DD) from an ISO date.
pub fn day(iso: &str) -> String {
    iso.get(..10).unwrap_or(iso).to_string()
}

fn trunc(s: &str, n: usize) -> String {
    crate::utils::truncate(s, n)
}

/// Standalone SVG graph (white background, tooltips on every node).
pub fn svg(tl: &Timeline) -> String {
    let g = &tl.graph;
    let step = 40.0;
    let x0 = 150.0;
    let (ys, yf) = (150.0, 230.0);
    let n = g.nodes.len().max(1);
    let width = (x0 + step * (n as f64 - 1.0) + 170.0).max(720.0);
    let height = 370.0;
    let idx: HashMap<&str, usize> = g.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    let pos = |i: usize, lane: Lane| (x0 + step * i as f64, if lane == Lane::Source { ys } else { yf });
    let mut s = String::new();
    let _ = writeln!(
        s,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0}" height="{height:.0}" viewBox="0 0 {width:.0} {height:.0}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="11">"#
    );
    let _ = writeln!(s, r#"<rect width="100%" height="100%" fill="white"/>"#);
    let branch = g.source_branch.as_deref().unwrap_or("source");
    let _ = writeln!(
        s,
        r#"<text x="16" y="24" font-size="15" font-weight="600" fill="{TEXT}">Divergence between the source ({}) and the fork</text>"#,
        esc(branch)
    );
    let mut sub = Vec::new();
    if let Some(d) = &tl.divergence {
        sub.push(format!(
            "divergence: {}{}",
            day(&d.date),
            if tl.divergence_estimated { " (estimated)" } else { "" }
        ));
    }
    if let (Some(a), Some(b)) = (&tl.first_fork_commit, &tl.last_fork_commit) {
        sub.push(format!("fork commits: {} → {}", day(&a.date), day(&b.date)));
    }
    if let Some(d) = &tl.last_disk_change {
        sub.push(format!("last change on disk: {}", day(&d.date)));
    }
    let _ = writeln!(
        s,
        r#"<text x="16" y="44" fill="{MUTED}">{}</text>"#,
        esc(&sub.join("   ·   "))
    );
    // Lane labels
    let _ = writeln!(
        s,
        r#"<text x="16" y="{:.0}" font-weight="600" fill="{SOURCE}">source</text><text x="16" y="{:.0}" fill="{MUTED}">{}</text>"#,
        ys + 4.0,
        ys + 18.0,
        esc(&trunc(branch, 18))
    );
    let _ = writeln!(
        s,
        r#"<text x="16" y="{:.0}" font-weight="600" fill="{FORK}">fork</text>"#,
        yf + 4.0
    );

    // Edges
    for e in &g.edges {
        let (Some(&a), Some(&b)) = (idx.get(e.from.as_str()), idx.get(e.to.as_str())) else {
            continue;
        };
        let (na, nb) = (&g.nodes[a], &g.nodes[b]);
        let (x1, y1) = pos(a, na.lane);
        let (x2, y2) = pos(b, nb.lane);
        let dashed =
            e.estimated || na.kind == NodeKind::Gap || nb.kind == NodeKind::Gap || nb.kind == NodeKind::Worktree;
        let dash = if dashed { r#" stroke-dasharray="4 3""# } else { "" };
        match e.kind {
            EdgeKind::Lane if na.lane == nb.lane => {
                let color = if na.lane == Lane::Source { SOURCE } else { FORK };
                let _ = writeln!(
                    s,
                    r#"<line x1="{x1:.1}" y1="{y1:.1}" x2="{x2:.1}" y2="{y2:.1}" stroke="{color}" stroke-width="3"{dash}/>"#
                );
            }
            _ => {
                if e.kind == EdgeKind::Merge {
                    // Source integration: direct curve to the merge commit.
                    let xa = x2 - step;
                    let xm = (xa + x2) / 2.0;
                    let _ = writeln!(
                        s,
                        r#"<path d="M {x1:.1} {y1:.1} L {xa:.1} {y1:.1} C {xm:.1} {y1:.1}, {xm:.1} {y2:.1}, {x2:.1} {y2:.1}" fill="none" stroke="{SOURCE}" stroke-width="2.5" stroke-opacity="0.85"{dash}/>"#
                    );
                } else {
                    // Fork departure: drop from the divergence point.
                    let xm = x1 + (x2 - x1).min(step) * 0.8;
                    let _ = writeln!(
                        s,
                        r#"<path d="M {x1:.1} {y1:.1} C {x1:.1} {y2:.1}, {x1:.1} {y2:.1}, {xm:.1} {y2:.1} L {x2:.1} {y2:.1}" fill="none" stroke="{FORK}" stroke-width="2.5"{dash}/>"#
                    );
                }
            }
        }
    }

    // Nodes
    for (i, node) in g.nodes.iter().enumerate() {
        let (x, y) = pos(i, node.lane);
        let color = if node.lane == Lane::Source { SOURCE } else { FORK };
        let tip = format!(
            "{} {}\n{}\n{}",
            if node.lane == Lane::Source {
                "[source]"
            } else {
                "[fork]"
            },
            node.short,
            node.date,
            node.subject
        );
        let _ = write!(s, "<g><title>{}</title>", esc(tip.trim()));
        match node.kind {
            NodeKind::Gap => {
                let _ = write!(
                    s,
                    r#"<rect x="{:.1}" y="{:.1}" width="34" height="16" rx="8" fill="white" stroke="{color}" stroke-dasharray="3 2"/><text x="{x:.1}" y="{:.1}" text-anchor="middle" font-size="10" fill="{color}">+{}</text>"#,
                    x - 17.0,
                    y - 8.0,
                    y + 4.0,
                    node.count
                );
            }
            NodeKind::Worktree => {
                let _ = write!(
                    s,
                    r#"<circle cx="{x:.1}" cy="{y:.1}" r="7" fill="white" stroke="{color}" stroke-width="2.5" stroke-dasharray="3 2"/>"#
                );
            }
            NodeKind::Snapshot => {
                let _ = write!(
                    s,
                    r#"<rect x="{:.1}" y="{:.1}" width="14" height="14" fill="white" stroke="{color}" stroke-width="2.5" stroke-dasharray="3 2"/>"#,
                    x - 7.0,
                    y - 7.0
                );
            }
            NodeKind::Merge => {
                let _ = write!(
                    s,
                    r#"<circle cx="{x:.1}" cy="{y:.1}" r="6.5" fill="white" stroke="{color}" stroke-width="3"/>"#
                );
            }
            NodeKind::Commit => {
                let _ = write!(
                    s,
                    r#"<circle cx="{x:.1}" cy="{y:.1}" r="6" fill="{color}" stroke="white" stroke-width="1.5"/>"#
                );
            }
        }
        if node.divergence {
            let _ = write!(
                s,
                r#"<circle cx="{x:.1}" cy="{y:.1}" r="11" fill="none" stroke="{DIVERGENCE}" stroke-width="2.5"/>"#
            );
        }
        if let Some(sev) = node.severity.filter(|s| *s >= Severity::Medium) {
            let c = if sev >= Severity::High { ALERT } else { DIVERGENCE };
            let _ = write!(
                s,
                r#"<circle cx="{x:.1}" cy="{y:.1}" r="10" fill="none" stroke="{c}" stroke-width="2"/><text x="{:.1}" y="{:.1}" font-weight="700" fill="{c}">!</text>"#,
                x + 8.0,
                y - 8.0
            );
        }
        let _ = writeln!(s, "</g>");
        // Labels
        let mut labels: Vec<String> = node.labels.clone();
        if node.divergence {
            labels.insert(
                0,
                if tl.divergence_estimated {
                    "divergence (estimated)".into()
                } else {
                    "divergence".into()
                },
            );
        }
        if node.reference && !node.divergence {
            labels.insert(0, "reference".into());
        }
        if !labels.is_empty() {
            let text = trunc(&labels.join(", "), 26);
            if node.lane == Lane::Source {
                let _ = writeln!(
                    s,
                    r#"<text transform="translate({:.1},{:.1}) rotate(-25)" fill="{}" font-weight="{}">{}</text>"#,
                    x + 2.0,
                    ys - 16.0,
                    if node.divergence { DIVERGENCE } else { TEXT },
                    if node.divergence || node.reference { 600 } else { 400 },
                    esc(&text)
                );
            } else {
                let _ = writeln!(
                    s,
                    r#"<text transform="translate({:.1},{:.1}) rotate(35)" fill="{FORK}" font-weight="600">{}</text>"#,
                    x + 4.0,
                    yf + 16.0,
                    esc(&text)
                );
            }
        }
        // Date axis
        if !node.date.is_empty() && node.kind != NodeKind::Gap {
            let _ = writeln!(
                s,
                r#"<text transform="translate({:.1},{:.1}) rotate(45)" font-size="9.5" fill="{MUTED}">{}</text>"#,
                x - 3.0,
                yf + 62.0,
                esc(&day(&node.date))
            );
        }
    }

    // Legend
    let ly = height - 18.0;
    let items: [(&str, String); 6] = [
        (
            "source commit",
            format!(r#"<circle cx="0" cy="-4" r="5" fill="{SOURCE}"/>"#),
        ),
        (
            "fork commit",
            format!(r#"<circle cx="0" cy="-4" r="5" fill="{FORK}"/>"#),
        ),
        (
            "merge",
            format!(r#"<circle cx="0" cy="-4" r="5" fill="white" stroke="{MUTED}" stroke-width="2.5"/>"#),
        ),
        (
            "divergence",
            format!(r#"<circle cx="0" cy="-4" r="7" fill="none" stroke="{DIVERGENCE}" stroke-width="2.5"/>"#),
        ),
        (
            "high/critical finding",
            format!(r#"<circle cx="0" cy="-4" r="7" fill="none" stroke="{ALERT}" stroke-width="2"/>"#),
        ),
        (
            "uncommitted / estimated",
            format!(
                r#"<circle cx="0" cy="-4" r="5" fill="white" stroke="{FORK}" stroke-width="2" stroke-dasharray="3 2"/>"#
            ),
        ),
    ];
    let mut lx = 16.0;
    for (label, icon) in items {
        let _ = writeln!(
            s,
            r#"<g transform="translate({:.1},{ly:.1})">{icon}<text x="12" y="0" fill="{MUTED}">{label}</text></g>"#,
            lx + 6.0
        );
        lx += 24.0 + label.chars().count() as f64 * 6.2;
    }
    s.push_str("</svg>\n");
    s
}

fn symbol(n: &GraphNode) -> char {
    match n.kind {
        NodeKind::Gap => '┆',
        NodeKind::Worktree => '○',
        NodeKind::Snapshot => '□',
        NodeKind::Merge => '◉',
        NodeKind::Commit if n.divergence => '◆',
        NodeKind::Commit => '●',
    }
}

/// Vertical text graph (newest at the top), readable in a console and in Markdown.
pub fn ascii(tl: &Timeline) -> String {
    let g = &tl.graph;
    if g.nodes.is_empty() {
        return String::new();
    }
    let idx: HashMap<&str, usize> = g.nodes.iter().enumerate().map(|(i, n)| (n.id.as_str(), i)).collect();
    // Sources of the source → fork edges (index of the source node).
    let mut cross_from: HashMap<usize, Vec<usize>> = HashMap::new();
    for e in &g.edges {
        if let (Some(&a), Some(&b)) = (idx.get(e.from.as_str()), idx.get(e.to.as_str())) {
            if g.nodes[a].lane == Lane::Source && g.nodes[b].lane == Lane::Fork {
                cross_from.entry(a).or_default().push(b);
            }
        }
    }
    let src: Vec<usize> = (0..g.nodes.len())
        .filter(|&i| g.nodes[i].lane == Lane::Source)
        .collect();
    let fork: Vec<usize> = (0..g.nodes.len()).filter(|&i| g.nodes[i].lane == Lane::Fork).collect();
    let (s_lo, s_hi) = (src.first().copied().unwrap_or(0), src.last().copied().unwrap_or(0));
    let f_hi = fork.last().copied().unwrap_or(0);
    let f_lo = cross_from.keys().min().copied().or(fork.first().copied()).unwrap_or(0);
    let src_active = |i: usize| !src.is_empty() && i >= s_lo && i <= s_hi;
    let fork_active = |i: usize| !fork.is_empty() && i > f_lo && i <= f_hi;

    let mut out = String::new();
    let _ = writeln!(out, "            S F");
    for i in (0..g.nodes.len()).rev() {
        let n = &g.nodes[i];
        let (c0, conn, c1) = match n.lane {
            Lane::Source => {
                if cross_from.contains_key(&i) {
                    (symbol(n), '─', if fork_active(i) || i > f_lo { '┤' } else { '╯' })
                } else {
                    (symbol(n), ' ', if fork_active(i) { '│' } else { ' ' })
                }
            }
            Lane::Fork => (if src_active(i) { '│' } else { ' ' }, ' ', symbol(n)),
        };
        let c1 = if n.lane == Lane::Source && cross_from.contains_key(&i) && i == f_lo {
            '╯'
        } else {
            c1
        };
        let date = if n.kind == NodeKind::Gap {
            String::new()
        } else {
            day(&n.date)
        };
        let mut desc = String::new();
        match n.kind {
            NodeKind::Gap => {
                let _ = write!(
                    desc,
                    "… {} commit(s) {}",
                    n.count,
                    if n.lane == Lane::Source {
                        "in the source"
                    } else {
                        "in the fork"
                    }
                );
            }
            _ => {
                let _ = write!(
                    desc,
                    "{:<10} [{}] ",
                    n.short,
                    if n.lane == Lane::Source { "source" } else { "fork" }
                );
                let mut labels = n.labels.clone();
                if n.divergence {
                    labels.insert(
                        0,
                        if tl.divergence_estimated {
                            "DIVERGENCE (estimated)".into()
                        } else {
                            "DIVERGENCE".into()
                        },
                    );
                }
                if n.reference && !n.divergence {
                    labels.insert(0, "reference".into());
                }
                if !labels.is_empty() {
                    let _ = write!(desc, "({}) ", labels.join(", "));
                }
                desc.push_str(&trunc(&n.subject, 64));
            }
        }
        if let Some(sev) = n.severity.filter(|s| *s >= Severity::Medium) {
            let _ = write!(desc, "  ⚠ {}", sev.label());
        }
        let _ = writeln!(out, "{date:<10}  {c0}{conn}{c1}  {desc}");
    }
    out
}
