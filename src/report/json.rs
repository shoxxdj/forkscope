//! JSON report (versioned) and its JSON schema.

use super::ForkScopeReport;
use anyhow::Result;
use std::path::Path;

/// Name of the generated JSON file.
pub const REPORT_FILE: &str = "forkscope-report.json";
/// Name of the generated JSON schema file.
pub const SCHEMA_FILE: &str = "forkscope-report.schema.json";

/// Serialises the report. Without `full_diff`, hunks are removed (diffs
/// remain available in the `diffs/` directory).
pub fn to_json(report: &ForkScopeReport, full_diff: bool) -> Result<String> {
    if full_diff {
        return Ok(serde_json::to_string_pretty(report)?);
    }
    let mut r = report.clone();
    for f in &mut r.diff.files {
        f.hunks.clear();
    }
    Ok(serde_json::to_string_pretty(&r)?)
}

/// JSON schema (draft-07) of the report, generated from the Rust types.
pub fn schema() -> Result<String> {
    let schema = schemars::schema_for!(ForkScopeReport);
    Ok(serde_json::to_string_pretty(&schema)?)
}

/// Writes the report and its schema to `dir`.
pub fn write(report: &ForkScopeReport, dir: &Path, full_diff: bool) -> Result<()> {
    std::fs::write(dir.join(REPORT_FILE), to_json(report, full_diff)?)?;
    std::fs::write(dir.join(SCHEMA_FILE), schema()?)?;
    Ok(())
}
