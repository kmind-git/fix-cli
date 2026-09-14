#![forbid(unsafe_code)]

use clap::Parser;
use fix_mock::{MockConfig, SessionLogger, run_mock_session_logged};
use fix_session::SystemTimeSource;
use fix_session::quickfix_cfg::{parse_acceptor_cfg, read_cfg_lossy};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "fix-mock", about = "Deterministic pure-Rust FIX test acceptor")]
struct Args {
    /// QuickFIX-style acceptor cfg (ConnectionType=acceptor), e.g.
    /// config/mock/SERVER.CFG.
    #[arg(long)]
    cfg: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let text = read_cfg_lossy(&args.cfg).map_err(|error| error.to_string())?;
    let session = parse_acceptor_cfg(&text).map_err(|error| error.to_string())?;
    let listen = SocketAddr::new(session.host.parse()?, session.port);
    let config = MockConfig {
        begin_string: session.begin_string,
        sender_comp_id: session.sender_comp_id,
        target_comp_id: session.target_comp_id,
        heartbeat_interval_secs: session.heartbeat_interval_secs,
    };
    let log_dir = session
        .log_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("logs"));
    let listener = TcpListener::bind(listen).await?;
    let log_prefix = format!(
        "{}-{}-{}",
        config.begin_string, config.sender_comp_id, config.target_comp_id
    );
    let logger = Arc::new(SessionLogger::new(&log_dir, log_prefix));

    loop {
        let (stream, peer) = listener.accept().await?;
        logger.info(format!("{peer} OnConnected"));
        let session_config = config.clone();
        let logger = Arc::clone(&logger);
        tokio::spawn(async move {
            let result = run_mock_session_logged(
                stream,
                session_config,
                Arc::new(SystemTimeSource),
                &logger,
            )
            .await;
            logger.info("Disconnecting");
            logger.info(format!("{peer} OnDisconnected"));
            if let Err(error) = result {
                logger.error(format!("{error}"));
                eprintln!("{error}");
            }
        });
    }
}
