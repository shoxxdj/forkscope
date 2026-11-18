//! Structured logging setup (`tracing`).

use tracing_subscriber::EnvFilter;

/// Initialises logging on standard error.
///
/// `verbose` : 0 = avertissements, 1 = info, 2 = debug, 3+ = trace.
/// The `FORKSCOPE_LOG` environment variable overrides the filter.
pub fn init(verbose: u8, color: bool) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_env("FORKSCOPE_LOG").unwrap_or_else(|_| EnvFilter::new(format!("forkscope={level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(color)
        .with_target(false)
        .try_init();
}
