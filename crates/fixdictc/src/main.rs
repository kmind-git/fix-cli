use clap::Parser;
use fixdictc::compile_orchestra;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "fixdictc", about = "Compile FIX Orchestra XML using pure Rust")]
struct Arguments {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    begin_string: String,
    #[arg(long)]
    output: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let xml = std::fs::read(&arguments.input)?;
    let dictionary = compile_orchestra(&xml, &arguments.begin_string)?;
    let json = serde_json::to_vec_pretty(&dictionary)?;
    std::fs::write(&arguments.output, json)?;
    Ok(())
}
