//! ForkScope CLI entry point.

use anyhow::{Context, Result};
use clap::Parser;
use console::style;
use forkscope::cli::{Cli, Command};
use forkscope::config::Config;
use forkscope::pipeline::{run, AnalyzeOptions};
use forkscope::report::console::{print_banner, print_summary, ConsoleProgress};
use forkscope::{analysis, info, utils};
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let color = !cli.no_color
        && std::env::var_os("NO_COLOR").is_none()
        && console::Term::stderr().features().colors_supported();
    console::set_colors_enabled(color);
    console::set_colors_enabled_stderr(color);
    utils::logging::init(cli.verbose, color);
    match dispatch(cli, color) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {:#}", style("error:").red().bold(), e);
            ExitCode::from(1)
        }
    }
}

fn dispatch(cli: Cli, color: bool) -> Result<()> {
    match cli.command {
        Some(Command::Info(args)) => {
            let i = info::collect(&args.target)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&i)?);
            } else {
                info::print(&i);
            }
            Ok(())
        }
        Some(Command::Rules(args)) => {
            let cfg = Config::load(args.config.as_deref())?;
            let rules = analysis::rules::RuleSet::load(&cfg.security)?;
            let mut t = comfy_table::Table::new();
            t.load_preset(comfy_table::presets::UTF8_FULL_CONDENSED);
            t.set_header(vec!["ID", "Category", "Severity", "Trigger", "Title"]);
            for r in &rules.rules {
                t.add_row(vec![
                    r.id.clone(),
                    r.category.label().to_string(),
                    r.severity.label().to_string(),
                    format!("{:?}", r.trigger),
                    r.title.clone(),
                ]);
            }
            println!("{t}\n{} active rules", rules.rules.len());
            Ok(())
        }
        None => {
            let a = cli.analyze;
            let config = Config::load(a.config.as_deref())?;
            let mut opts = AnalyzeOptions::new(
                a.client.context("--fork is required")?,
                a.upstream.context("--source is required")?,
            );
            opts.output = Some(a.output.clone());
            opts.branch = a.branch;
            opts.depth = a.depth;
            opts.full_diff = a.full_diff;
            opts.write_markdown = a.format.markdown();
            opts.write_json = a.format.json();
            opts.config = config;
            opts.config_file = a.config;
            opts.force_snapshot = a.force_snapshot;
            print_banner();
            let progress = ConsoleProgress::new();
            let report = run(&opts, &progress)?;
            eprintln!();
            print_summary(&report, color);
            println!(
                "\nReports written to {}{}{}",
                style(a.output.display()).bold(),
                if opts.write_markdown {
                    "\n  • forkscope-report.md"
                } else {
                    ""
                },
                if opts.write_json {
                    "\n  • forkscope-report.json (+ schema)"
                } else {
                    ""
                }
            );
            println!("  • changed-files.txt / changed-files.csv\n  • divergence-graph.svg\n  • diffs/");
            Ok(())
        }
    }
}
