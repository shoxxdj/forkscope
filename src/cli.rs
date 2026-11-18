//! Command-line interface definition.

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// ForkScope — analyses the differences between a fork and its source repository.
#[derive(Parser, Debug)]
#[command(
    name = "forkscope",
    version,
    about = "Analyses the differences between a fork and its source Git repository (security audit)",
    long_about = None,
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub analyze: AnalyzeArgs,

    /// Verbose logs (-v info, -vv debug, -vvv trace)
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Disable colours
    #[arg(long = "no-color", global = true)]
    pub no_color: bool,
}

/// Arguments of the full analysis (default command).
#[derive(Args, Debug, Clone)]
pub struct AnalyzeArgs {
    /// Path of the fork to analyse (Git repository or plain source folder)
    #[arg(
        short = 'f',
        long = "fork",
        visible_alias = "client",
        visible_short_alias = 'c',
        value_name = "PATH",
        required = true
    )]
    pub client: Option<PathBuf>,

    /// Git URL (or path) of the source (original) repository
    #[arg(
        short = 's',
        long = "source",
        visible_alias = "upstream",
        visible_short_alias = 'u',
        value_name = "URL",
        required = true
    )]
    pub upstream: Option<String>,

    /// Output directory
    #[arg(short = 'o', long = "output", default_value = "./forkscope-report")]
    pub output: PathBuf,

    /// Source branch to favour (default: the repository's default branch)
    #[arg(long = "branch")]
    pub branch: Option<String>,

    /// Git fetch depth for the source (shallow fetch)
    #[arg(long = "depth")]
    pub depth: Option<u32>,

    /// Include full diffs in the Markdown and JSON reports
    #[arg(long = "full-diff")]
    pub full_diff: bool,

    /// Output format
    #[arg(long = "format", value_enum, default_value_t = OutputFormat::Both)]
    pub format: OutputFormat,

    /// TOML configuration file (exclusions, rules, thresholds)
    #[arg(long = "config")]
    pub config: Option<PathBuf>,

    /// Ignore the fork's Git history and estimate the reference by content comparison
    #[arg(long = "force-snapshot")]
    pub force_snapshot: bool,
}

/// Report formats.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Markdown report only
    #[value(alias = "md")]
    Markdown,
    /// JSON report only
    Json,
    /// Markdown and JSON
    Both,
}

impl OutputFormat {
    pub fn markdown(self) -> bool {
        matches!(self, Self::Markdown | Self::Both)
    }
    pub fn json(self) -> bool {
        matches!(self, Self::Json | Self::Both)
    }
}

/// Subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Information about a repository (local path or URL) without running the full analysis
    Info(InfoArgs),
    /// List the built-in security rules (and those from the configuration file)
    Rules(RulesArgs),
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Local path or Git URL
    pub target: String,
    /// JSON output
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    /// Configuration file containing custom rules
    #[arg(long = "config")]
    pub config: Option<PathBuf>,
}
