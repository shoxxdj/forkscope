//! Fork timeline: key dates and source / fork divergence graph
//! (inspired by the forges' "network graph": the source line, the fork
//! line, the divergence point and the integrations from the source).

use super::history::HistoryAnalysis;
use super::reference::{display_ref, Certainty, ReferenceResult};
use super::repository::TempRepo;
use crate::analysis::rules::Severity;
use crate::utils::short;
use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Dated commit.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DatedCommit {
    pub hash: String,
    pub short: String,
    /// Commit date (ISO 8601).
    pub date: String,
    /// Author date (ISO 8601).
    pub author_date: String,
    pub subject: String,
}

/// Latest file modification observed on disk.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct DiskChange {
    pub date: String,
    pub path: String,
    /// Number of fork files (modified, not deleted) whose date was read.
    pub files: usize,
}

/// Graph lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    Source,
    Fork,
}

/// Kind of node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Commit,
    Merge,
    /// Grouped commits (not displayed individually).
    Gap,
    /// Uncommitted changes.
    Worktree,
    /// Fork content without history (estimate).
    Snapshot,
}

/// Graph node.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GraphNode {
    pub id: String,
    pub lane: Lane,
    pub kind: NodeKind,
    pub date: String,
    pub ts: i64,
    pub short: String,
    pub subject: String,
    /// Branches/tags, HEAD…
    pub labels: Vec<String>,
    /// Number of grouped commits (Gap node).
    pub count: usize,
    pub divergence: bool,
    pub reference: bool,
    /// Highest severity of the commit's findings (fork).
    pub severity: Option<Severity>,
}

/// Kind of edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Continuation of a lane.
    Lane,
    /// Fork departure from the source.
    BranchOff,
    /// Integration (merge) of the source into the fork.
    Merge,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    /// Estimated relation (no common history).
    pub estimated: bool,
}

/// Divergence graph (nodes sorted chronologically, consistent with the edges).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Graph {
    pub source_branch: Option<String>,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Fork timeline.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Timeline {
    /// Source commit from which the fork diverged.
    pub divergence: Option<DatedCommit>,
    /// The divergence is an estimate (no common history).
    pub divergence_estimated: bool,
    /// Most recent integrated source commit (diff reference).
    pub reference: Option<DatedCommit>,
    pub first_fork_commit: Option<DatedCommit>,
    pub last_fork_commit: Option<DatedCommit>,
    /// Latest modification of a fork file on disk (indicative).
    pub last_disk_change: Option<DiskChange>,
    /// Latest commit of the preferred source branch.
    pub source_tip: Option<DatedCommit>,
    /// Days between the divergence and the fork's latest known change.
    pub days_of_divergence: Option<i64>,
    pub graph: Graph,
}

const MAX_SOURCE_NODES: usize = 40;
const MAX_FORK_NODES: usize = 45;

fn ts_of(iso: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.timestamp())
        .unwrap_or(0)
}

/// A `git log` line: hash, parents, commit date, author date, subject.
struct LogLine {
    hash: String,
    parents: Vec<String>,
    date: String,
    author_date: String,
    subject: String,
}

fn log(repo: &TempRepo, args: &[&str]) -> Result<Vec<LogLine>> {
    let mut a = vec!["log", "--format=%H%x1f%P%x1f%cI%x1f%aI%x1f%s"];
    a.extend_from_slice(args);
    Ok(repo
        .run(&a)?
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.splitn(5, '\x1f').collect();
            (f.len() == 5).then(|| LogLine {
                hash: f[0].into(),
                parents: f[1].split_whitespace().map(|s| s.to_string()).collect(),
                date: f[2].into(),
                author_date: f[3].into(),
                subject: f[4].into(),
            })
        })
        .collect())
}

fn dated(repo: &TempRepo, hash: &str) -> Option<DatedCommit> {
    let l = log(repo, &["-1", hash]).ok()?.into_iter().next()?;
    Some(DatedCommit {
        short: short(&l.hash).into(),
        hash: l.hash,
        date: l.date,
        author_date: l.author_date,
        subject: l.subject,
    })
}

/// Build parameters.
pub struct TimelineParams<'a> {
    pub reference: &'a ReferenceResult,
    pub history: Option<&'a HistoryAnalysis>,
    pub preferred_branch: Option<&'a str>,
    pub last_disk_change: Option<DiskChange>,
    /// Number of uncommitted fork files (for the "uncommitted" node).
    pub uncommitted_files: usize,
    /// Number of differing files attributed to the fork (no-history mode).
    pub fork_changes: usize,
}

/// Builds the timeline and the graph.
pub fn build(repo: &TempRepo, p: &TimelineParams) -> Result<Timeline> {
    let r = p.reference;
    let exact = r.certainty == Certainty::Exact;
    let mut tl = Timeline {
        reference: dated(repo, &r.commit.hash),
        ..Default::default()
    };
    let divergence_hash = if exact {
        r.fork_point
            .as_ref()
            .map(|f| f.hash.clone())
            .unwrap_or_else(|| r.commit.hash.clone())
    } else {
        r.estimated_initial_base
            .as_ref()
            .map(|b| b.commit.hash.clone())
            .unwrap_or_else(|| r.commit.hash.clone())
    };
    tl.divergence = dated(repo, &divergence_hash);
    tl.divergence_estimated = !exact;
    tl.last_disk_change = p.last_disk_change.clone();
    let tip_ref = p.preferred_branch.map(|b| format!("refs/upstream/heads/{b}"));
    let tip = match &tip_ref {
        Some(t) => repo.resolve_commit(t)?,
        None => None,
    };
    tl.source_tip = tip.as_deref().and_then(|t| dated(repo, t));

    // ---------------- Fork lane
    let mut fork_nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut source_needed: Vec<(String, EdgeKind, String, bool)> = Vec::new(); // (source commit, kind, fork node, estimated)
    let mut fork_ids: HashSet<String> = HashSet::new();

    if let Some(h) = p.history {
        let mut commits: Vec<_> = h.client_commits.iter().collect();
        commits.reverse(); // oldest to newest
        if let (Some(first), Some(last)) = (commits.first(), commits.last()) {
            tl.first_fork_commit = Some(DatedCommit {
                hash: first.hash.clone(),
                short: first.short.clone(),
                date: first.committer_date.clone(),
                author_date: first.author_date.clone(),
                subject: first.subject.clone(),
            });
            tl.last_fork_commit = Some(DatedCommit {
                hash: last.hash.clone(),
                short: last.short.clone(),
                date: last.committer_date.clone(),
                author_date: last.author_date.clone(),
                subject: last.subject.clone(),
            });
        }
        let all: HashSet<&str> = h.client_commits.iter().map(|c| c.hash.as_str()).collect();
        // Grouping if there are too many commits: keep the start, the end and the merges.
        let n = commits.len();
        let keep = |i: usize, c: &crate::git::history::CommitInfo| {
            n <= MAX_FORK_NODES
                || i < 8
                || i >= n - (MAX_FORK_NODES - 10)
                || c.parents.iter().any(|p| !all.contains(p.as_str()))
        };
        let mut gap: Option<GraphNode> = None;
        let mut gap_of: HashMap<String, String> = HashMap::new();
        let mut gap_idx = 0;
        for (i, c) in commits.iter().enumerate() {
            if !keep(i, c) {
                let g = gap.get_or_insert_with(|| {
                    gap_idx += 1;
                    GraphNode {
                        id: format!("fork-gap-{gap_idx}"),
                        lane: Lane::Fork,
                        kind: NodeKind::Gap,
                        date: c.committer_date.clone(),
                        ts: ts_of(&c.committer_date),
                        short: String::new(),
                        subject: String::new(),
                        labels: vec![],
                        count: 0,
                        divergence: false,
                        reference: false,
                        severity: None,
                    }
                });
                g.count += 1;
                g.severity = g.severity.max(c.max_severity);
                gap_of.insert(c.hash.clone(), g.id.clone());
                continue;
            }
            if let Some(g) = gap.take() {
                fork_ids.insert(g.id.clone());
                fork_nodes.push(g);
            }
            let mut labels = vec![];
            if c.hash == h.client_head {
                labels.push("HEAD".to_string());
            }
            fork_nodes.push(GraphNode {
                id: c.hash.clone(),
                lane: Lane::Fork,
                kind: if c.is_merge { NodeKind::Merge } else { NodeKind::Commit },
                date: c.committer_date.clone(),
                ts: ts_of(&c.committer_date),
                short: c.short.clone(),
                subject: c.subject.clone(),
                labels,
                count: 1,
                divergence: false,
                reference: false,
                severity: c.max_severity,
            });
            fork_ids.insert(c.hash.clone());
            for (pi, parent) in c.parents.iter().enumerate() {
                if all.contains(parent.as_str()) {
                    let from = if fork_ids.contains(parent) {
                        parent.clone()
                    } else {
                        gap_of.get(parent).cloned().unwrap_or_default()
                    };
                    if !from.is_empty() {
                        edges.push(GraphEdge {
                            from,
                            to: c.hash.clone(),
                            kind: EdgeKind::Lane,
                            estimated: false,
                        });
                    }
                } else {
                    let kind = if pi == 0 { EdgeKind::BranchOff } else { EdgeKind::Merge };
                    source_needed.push((parent.clone(), kind, c.hash.clone(), false));
                }
            }
        }
        // Internal link between a group and the next commit.
        let ids: Vec<String> = fork_nodes.iter().map(|n| n.id.clone()).collect();
        for w in ids.windows(2) {
            if w[0].starts_with("fork-gap-") || w[1].starts_with("fork-gap-") {
                edges.push(GraphEdge {
                    from: w[0].clone(),
                    to: w[1].clone(),
                    kind: EdgeKind::Lane,
                    estimated: false,
                });
            }
        }
        // Rewritten history: estimated attachment to the starting point.
        if !exact {
            if let Some(first) = fork_nodes.first() {
                source_needed.push((divergence_hash.clone(), EdgeKind::BranchOff, first.id.clone(), true));
            }
        }
        // Source commits integrated without an own commit (HEAD = source commit).
        if h.client_commits.is_empty() && exact {
            source_needed.push((r.commit.hash.clone(), EdgeKind::BranchOff, String::new(), false));
        }
        if p.uncommitted_files > 0 {
            let date = p.last_disk_change.as_ref().map(|d| d.date.clone()).unwrap_or_default();
            let wt = GraphNode {
                id: "worktree".into(),
                lane: Lane::Fork,
                kind: NodeKind::Worktree,
                ts: ts_of(&date).max(fork_nodes.last().map(|n| n.ts + 1).unwrap_or(0)),
                date,
                short: String::new(),
                subject: format!("{} uncommitted modified file(s)", p.uncommitted_files),
                labels: vec!["uncommitted".into()],
                count: p.uncommitted_files,
                divergence: false,
                reference: false,
                severity: None,
            };
            match fork_nodes.last() {
                Some(last) => edges.push(GraphEdge {
                    from: last.id.clone(),
                    to: wt.id.clone(),
                    kind: EdgeKind::Lane,
                    estimated: false,
                }),
                None => source_needed.push((h.client_head.clone(), EdgeKind::BranchOff, wt.id.clone(), false)),
            }
            fork_nodes.push(wt);
        }
    } else {
        // Without history: one node representing the fork content.
        let date = p.last_disk_change.as_ref().map(|d| d.date.clone()).unwrap_or_default();
        let node = GraphNode {
            id: "snapshot".into(),
            lane: Lane::Fork,
            kind: NodeKind::Snapshot,
            ts: ts_of(&date),
            date,
            short: String::new(),
            subject: format!("fork sources without history ({} modified file(s))", p.fork_changes),
            labels: vec!["no history".into()],
            count: p.fork_changes,
            divergence: false,
            reference: false,
            severity: None,
        };
        source_needed.push((r.commit.hash.clone(), EdgeKind::BranchOff, node.id.clone(), true));
        fork_nodes.push(node);
    }

    // ---------------- Source lane
    let mut relevant: Vec<String> = vec![r.commit.hash.clone(), divergence_hash.clone()];
    relevant.extend(source_needed.iter().map(|(c, ..)| c.clone()));
    let relevant_set: HashSet<String> = relevant.iter().cloned().collect();
    let chain_tip = tip.clone().unwrap_or_else(|| r.commit.hash.clone());
    let mut chain = log(repo, &["--first-parent", "--max-count=5000", &chain_tip])?;
    chain.reverse();
    let pos: HashMap<String, usize> = chain.iter().enumerate().map(|(i, c)| (c.hash.clone(), i)).collect();
    // Position on the main line; for a commit off this line
    // (maintenance branch), position of its common ancestor with it.
    let mut anchor_pos: Vec<usize> = Vec::new();
    let mut anchors: HashSet<String> = HashSet::new();
    for c in &relevant {
        if let Some(&i) = pos.get(c) {
            anchor_pos.push(i);
        } else if !chain.is_empty() && repo.is_ancestor(c, &chain_tip)? {
            // First main-line commit containing c (binary search).
            let (mut lo, mut hi) = (0usize, chain.len() - 1);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if repo.is_ancestor(c, &chain[mid].hash)? {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            anchor_pos.push(lo);
            anchors.insert(chain[lo].hash.clone());
        } else if let Some(mb) = repo.try_run(&["merge-base", c, &chain_tip])? {
            let mb = mb.trim().to_string();
            if let Some(&i) = pos.get(&mb) {
                anchor_pos.push(i);
                anchors.insert(mb);
            }
        }
    }
    let start = anchor_pos
        .iter()
        .min()
        .copied()
        .unwrap_or(chain.len().saturating_sub(10))
        .saturating_sub(2);
    let window = &chain[start.min(chain.len())..];
    let mut tags: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rf in repo.refs(&["refs/tags", "refs/upstream/heads"])? {
        tags.entry(rf.commit)
            .or_default()
            .push(display_ref(&rf.name).replace("branch:", "").replace("tag:", ""));
    }
    let keep_src = |i: usize, c: &LogLine| {
        relevant_set.contains(&c.hash)
            || anchors.contains(&c.hash)
            || i == 0
            || i + 1 == window.len()
            || (window.len() <= MAX_SOURCE_NODES)
            || tags.contains_key(&c.hash) && window.len() <= MAX_SOURCE_NODES * 3
    };
    let mut source_nodes: Vec<GraphNode> = Vec::new();
    let mut src_gap: Option<GraphNode> = None;
    let mut gap_n = 0;
    let mk = |c: &LogLine, tags: &BTreeMap<String, Vec<String>>| GraphNode {
        id: c.hash.clone(),
        lane: Lane::Source,
        kind: if c.parents.len() > 1 {
            NodeKind::Merge
        } else {
            NodeKind::Commit
        },
        date: c.date.clone(),
        ts: ts_of(&c.date),
        short: short(&c.hash).into(),
        subject: c.subject.clone(),
        labels: tags.get(&c.hash).cloned().unwrap_or_default(),
        count: 1,
        divergence: c.hash == divergence_hash,
        reference: c.hash == r.commit.hash,
        severity: None,
    };
    for (i, c) in window.iter().enumerate() {
        if keep_src(i, c) {
            if let Some(g) = src_gap.take() {
                source_nodes.push(g);
            }
            source_nodes.push(mk(c, &tags));
        } else {
            let g = src_gap.get_or_insert_with(|| {
                gap_n += 1;
                GraphNode {
                    id: format!("source-gap-{gap_n}"),
                    lane: Lane::Source,
                    kind: NodeKind::Gap,
                    date: c.date.clone(),
                    ts: ts_of(&c.date),
                    short: String::new(),
                    subject: String::new(),
                    labels: vec![],
                    count: 0,
                    divergence: false,
                    reference: false,
                    severity: None,
                }
            });
            g.count += 1;
        }
    }
    if let Some(g) = src_gap.take() {
        source_nodes.push(g);
    }
    // Relevant source commits off the main line (other branch, isolated tag).
    let shown: HashSet<String> = source_nodes.iter().map(|n| n.id.clone()).collect();
    for c in &relevant_set {
        if !shown.contains(c) {
            if let Some(l) = log(repo, &["-1", c])?.into_iter().next() {
                let mut n = mk(&l, &tags);
                n.labels.push("off main line".into());
                source_nodes.push(n);
            }
        }
    }
    source_nodes.sort_by_key(|n| n.ts);
    for w in source_nodes.windows(2) {
        edges.push(GraphEdge {
            from: w[0].id.clone(),
            to: w[1].id.clone(),
            kind: EdgeKind::Lane,
            estimated: false,
        });
    }
    if let Some(n) = source_nodes.last_mut() {
        if let Some(b) = p.preferred_branch {
            if !n.labels.iter().any(|l| l == b) && tip.as_deref() == Some(n.id.as_str()) {
                n.labels.insert(0, b.to_string());
            }
        }
    }
    for (src, kind, to, estimated) in source_needed {
        if !to.is_empty() {
            edges.push(GraphEdge {
                from: src,
                to,
                kind,
                estimated,
            });
        } else if let Some(n) = source_nodes.iter_mut().find(|n| n.id == src) {
            n.labels.push("fork HEAD".into());
        }
    }

    let mut nodes = source_nodes;
    nodes.extend(fork_nodes);
    tl.graph = Graph {
        source_branch: p.preferred_branch.map(|s| s.to_string()),
        nodes: topo_sort(nodes, &edges),
        edges,
    };

    // Divergence duration.
    let last = [
        tl.last_fork_commit.as_ref().map(|c| ts_of(&c.date)),
        tl.last_disk_change.as_ref().map(|d| ts_of(&d.date)),
    ]
    .into_iter()
    .flatten()
    .max();
    if let (Some(d), Some(l)) = (tl.divergence.as_ref().map(|d| ts_of(&d.date)), last) {
        tl.days_of_divergence = Some(((l - d) / 86_400).max(0));
    }
    Ok(tl)
}

/// Chronological sort honouring the edges (parents before children).
fn topo_sort(nodes: Vec<GraphNode>, edges: &[GraphEdge]) -> Vec<GraphNode> {
    let ids: HashMap<String, usize> = nodes.iter().enumerate().map(|(i, n)| (n.id.clone(), i)).collect();
    let mut indeg = vec![0usize; nodes.len()];
    let mut succ: Vec<Vec<usize>> = vec![vec![]; nodes.len()];
    for e in edges {
        if let (Some(&a), Some(&b)) = (ids.get(&e.from), ids.get(&e.to)) {
            if a != b {
                succ[a].push(b);
                indeg[b] += 1;
            }
        }
    }
    let mut ready: Vec<usize> = (0..nodes.len()).filter(|&i| indeg[i] == 0).collect();
    let mut order = Vec::with_capacity(nodes.len());
    while !ready.is_empty() {
        // oldest first, source before fork at equal date
        ready.sort_by_key(|&i| std::cmp::Reverse((nodes[i].ts, nodes[i].lane == Lane::Fork)));
        let i = ready.pop().unwrap();
        order.push(i);
        for &s in &succ[i] {
            indeg[s] -= 1;
            if indeg[s] == 0 {
                ready.push(s);
            }
        }
    }
    // Unlikely cycle: append the remaining ones.
    for i in 0..nodes.len() {
        if !order.contains(&i) {
            order.push(i);
        }
    }
    let mut slots: Vec<Option<GraphNode>> = nodes.into_iter().map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}
