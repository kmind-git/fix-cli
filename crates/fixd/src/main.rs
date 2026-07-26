use clap::{Parser, Subcommand};
use fixd::{run_daemon, validate_daemon_files};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "fixd", about = "Pure Rust FIX session daemon")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        profile: PathBuf,
    },
    Validate {
        #[arg(long)]
        profile: PathBuf,
    },
    Schema {
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Arguments::parse().command {
        Command::Run { profile } => run_daemon(profile).await?,
        Command::Validate { profile } => {
            validate_daemon_files(&profile)?;
            println!("{{\"ok\":true}}");
        }
        Command::Schema { output } => {
            let schema = serde_json::to_vec_pretty(&fix_control::control_request_schema())?;
            if let Some(output) = output {
                std::fs::write(output, schema)?;
            } else {
                println!("{}", String::from_utf8(schema)?);
            }
        }
    }
    Ok(())
}
