#![forbid(unsafe_code)]

use clap::Parser;
use fix_mock::{MockConfig, run_mock_session};
use fix_session::SystemTimeSource;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "fix-mock", about = "Deterministic pure-Rust FIX test acceptor")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:19876")]
    listen: SocketAddr,
    #[arg(long, default_value = "FIX.4.4")]
    begin_string: String,
    #[arg(long, default_value = "SERVER")]
    sender_comp_id: String,
    #[arg(long, default_value = "CLIENT")]
    target_comp_id: String,
    #[arg(long, default_value_t = 30)]
    heartbeat_interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;
    let config = MockConfig {
        begin_string: args.begin_string,
        sender_comp_id: args.sender_comp_id,
        target_comp_id: args.target_comp_id,
        heartbeat_interval_secs: args.heartbeat_interval_secs,
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let session_config = config.clone();
        tokio::spawn(async move {
            if let Err(error) =
                run_mock_session(stream, session_config, Arc::new(SystemTimeSource)).await
            {
                eprintln!("{error}");
            }
        });
    }
}
