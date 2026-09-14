use clap::{Parser, Subcommand};
use fixd::quickfix::run_quickfix_daemon;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "fixd", about = "Pure Rust FIX session daemon")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Connect to a FIX venue described by a QuickFIX-style cfg
    /// (tag-only parsing, no data dictionary).
    RunReal {
        #[arg(long)]
        cfg: PathBuf,
        /// Directory for QuickFIX-style Messages/Event log files
        /// (default: cfg FileLogPath, else "logs").
        #[arg(long)]
        log_dir: Option<PathBuf>,
        /// Journal database (default: data/{sender}-{target}.redb).
        #[arg(long)]
        database: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::RunReal {
            cfg,
            log_dir,
            database,
        } => run_quickfix_daemon(&cfg, log_dir.as_deref(), database).await?,
    }
    Ok(())
}
