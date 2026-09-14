#![forbid(unsafe_code)]

pub mod quickfix;

use std::sync::Arc;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub host: String,
    pub port: u16,
    pub connect_timeout_ms: u64,
    pub reconnect_initial_ms: u64,
    pub reconnect_max_ms: u64,
}

#[derive(Clone, Debug)]
pub struct SessionConfigFile {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heartbeat_interval_secs: u64,
    pub reset_on_logon: bool,
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("IPC error: {0}")]
    Ipc(String),
}

pub async fn run_connection_manager(
    transport: TransportConfig,
    session_config: SessionConfigFile,
    logon_fields: Vec<fix_protocol::Field>,
    store: fix_store::StoreHandle,
    sessions: fix_control::SessionSlot,
    logger: fix_session::SessionLogger,
) {
    use fix_session::{
        SessionConfig, SessionEvent, SessionPhase, SystemTimeSource, spawn_initiator_logged,
    };
    use tokio::net::TcpStream;
    use tokio::sync::broadcast::error::RecvError;
    use tokio::time::{Duration, sleep, timeout};

    let initial_delay = Duration::from_millis(transport.reconnect_initial_ms);
    let maximum_delay = Duration::from_millis(transport.reconnect_max_ms);
    let connect_timeout = Duration::from_millis(transport.connect_timeout_ms);
    let mut reconnect_delay = initial_delay;

    loop {
        let connection = timeout(
            connect_timeout,
            TcpStream::connect((transport.host.as_str(), transport.port)),
        )
        .await;
        if let Ok(Ok(stream)) = connection {
            let peer = stream
                .peer_addr()
                .map(|address| address.to_string())
                .unwrap_or_else(|_| format!("{}:{}", transport.host, transport.port));
            logger.info(format!("{peer} OnConnected"));
            let session = spawn_initiator_logged(
                stream,
                SessionConfig {
                    begin_string: session_config.begin_string.clone(),
                    sender_comp_id: session_config.sender_comp_id.clone(),
                    target_comp_id: session_config.target_comp_id.clone(),
                    heartbeat_interval_secs: session_config.heartbeat_interval_secs,
                    reset_on_logon: session_config.reset_on_logon,
                },
                logon_fields.clone(),
                store.clone(),
                Arc::new(SystemTimeSource),
                logger.clone(),
            );
            let mut events = session.subscribe();
            sessions.replace(session.clone());
            let mut established = false;

            loop {
                tokio::select! {
                    event = events.recv() => {
                        match event {
                            Ok(SessionEvent::PhaseChanged(SessionPhase::Established)) => {
                                established = true;
                                reconnect_delay = initial_delay;
                            }
                            Ok(SessionEvent::PhaseChanged(
                                SessionPhase::Disconnected | SessionPhase::Blocked
                            ) | SessionEvent::TransportClosed) => break,
                            Ok(_) | Err(RecvError::Lagged(_)) => {}
                            Err(RecvError::Closed) => break,
                        }
                    }
                    () = sleep(Duration::from_secs(1)) => {
                        match session.status().await {
                            Ok(status) if matches!(
                                status.phase,
                                SessionPhase::Disconnected | SessionPhase::Blocked
                            ) => break,
                            Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
            }
            sessions.clear();
            logger.info("Disconnecting");
            logger.info(format!("{peer} OnDisconnected"));
            if established {
                reconnect_delay = initial_delay;
            }
        }

        sleep(reconnect_delay).await;
        reconnect_delay = reconnect_delay
            .checked_mul(2)
            .unwrap_or(maximum_delay)
            .min(maximum_delay);
    }
}

#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct ConfigError {
    code: &'static str,
    message: String,
}

impl ConfigError {
    pub(crate) fn message(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
