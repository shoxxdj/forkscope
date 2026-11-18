//! ForkScope: analyses the differences between a fork and its source repository,
//! for security audits.
//!
//! Organisation :
//! * [`git`] — temporary repository, source fetch, reference
//!   identification, history, patch IDs;
//! * [`diff`] — snapshots, comparison, renames, similarity;
//! * [`analysis`] — security rules, dependencies, secrets;
//! * [`report`] — Markdown/JSON reports and console;
//! * [`pipeline`] — orchestration.

pub mod analysis;
pub mod cli;
pub mod config;
pub mod diff;
pub mod git;
pub mod info;
pub mod pipeline;
pub mod report;
pub mod utils;
