//! Daemon runtime for connecting to a FIX venue described by a
//! QuickFIX-style client cfg. Message parsing is structural by tag
//! (`UseDataDictionary=N` semantics); logon and heartbeat behaviour match a
//! plain FIX 4.4 initiator. The cfg grammar itself lives in
//! `fix_session::quickfix_cfg`.
//!
//! Supported keys (all optional unless noted): BeginString*, SenderCompID*,
//! TargetCompID*, SocketConnectHost*, SocketConnectPort*,
//! ConnectionType (must be `initiator`), HeartBtInt (30), ReconnectInterval
//! (10), ConnectTimeoutMs (5000), ResetSeqNumFlag (N, or Y to send Logon
//! 141=Y and reset both sequence counters to 1),
//! UseDataDictionary (N only; Y is rejected because parsing is structural
//! by tag), FileLogPath (log directory), FileStorePath
//! (journal directory), LogonField.<tag>=<value> (custom Logon
//! fields, e.g. `LogonField.554=secret`), MaxQuantity (10000), MaxNotional
//! (100000000), AllowMarketOrders (N), MaxMessagesPerSecond (20).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;

use crate::{DaemonError, TransportConfig, run_connection_manager};
use fix_session::quickfix_cfg::{parse_client_cfg, read_cfg_lossy};

/// Run a daemon wired to a real venue described by a QuickFIX-style cfg.
/// Paths resolve as: CLI argument > cfg key > built-in default.
pub async fn run_quickfix_daemon(
    cfg_path: &Path,
    log_dir: Option<&Path>,
    database: Option<PathBuf>,
) -> Result<(), DaemonError> {
    use fix_control::{
        CommandPlanner, ControlRequest, ControlService, Policy, RuntimeMode, SessionSlot,
    };
    use fix_ipc::{LocalListener, endpoint_for_profile, read_json_frame, write_json_frame};
    use fix_session::SessionLogger;
    use fix_store::{RedbStore, StoreWorker};

    let text = read_cfg_lossy(cfg_path).map_err(DaemonError::Io)?;
    let session = parse_client_cfg(&text).map_err(|error| {
        DaemonError::Config(crate::ConfigError::message(
            "INVALID_CONFIG",
            format!("quickfix cfg: {error}"),
        ))
    })?;
    let profile_name = format!("{}-{}", session.sender_comp_id, session.target_comp_id);

    let logon_fields = session
        .logon_fields
        .iter()
        .map(|(tag, value)| fix_protocol::Field::new(*tag, Bytes::from(value.clone())))
        .collect::<Vec<_>>();
    fix_session::validate_custom_logon_fields(&logon_fields).map_err(|error| {
        DaemonError::Config(crate::ConfigError::message(
            "INVALID_CONFIG",
            error.to_string(),
        ))
    })?;

    let database = database.unwrap_or_else(|| {
        let directory = session
            .file_store_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("data"));
        directory.join(format!("{profile_name}.redb"))
    });
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(|error| DaemonError::Io(error.to_string()))?;
    }

    let store =
        RedbStore::open(&database).map_err(|error| DaemonError::Store(error.to_string()))?;
    let store = StoreWorker::spawn(store);

    let log_directory = log_dir
        .map(Path::to_path_buf)
        .or_else(|| session.file_log_path.as_ref().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("logs"));
    let fix_logger = SessionLogger::new(
        &log_directory,
        format!(
            "{}-{}-{}",
            session.begin_string, session.sender_comp_id, session.target_comp_id
        ),
    );

    let policy = Policy {
        max_quantity: session.max_quantity,
        max_notional: session.max_notional,
        allow_market_orders: session.allow_market_orders,
        max_messages_per_second: session.max_messages_per_second,
    };
    let planner = CommandPlanner::new(&profile_name, RuntimeMode::Certification, policy);
    let sessions = SessionSlot::new();
    let control_store = store.clone();

    tokio::spawn(run_connection_manager(
        TransportConfig {
            host: session.host.clone(),
            port: session.port,
            connect_timeout_ms: session.connect_timeout_ms,
            reconnect_initial_ms: session.reconnect_interval_secs * 1000,
            reconnect_max_ms: session.reconnect_interval_secs * 1000,
        },
        crate::SessionConfigFile {
            begin_string: session.begin_string.clone(),
            sender_comp_id: session.sender_comp_id.clone(),
            target_comp_id: session.target_comp_id.clone(),
            heartbeat_interval_secs: session.heartbeat_interval_secs,
            reset_on_logon: session.reset_seq_num_flag,
        },
        logon_fields,
        store,
        sessions.clone(),
        fix_logger,
    ));

    let service = Arc::new(ControlService::new_dynamic_with_store(
        planner,
        sessions,
        control_store,
    ));
    let endpoint = endpoint_for_profile(&profile_name);
    let mut listener =
        LocalListener::bind(endpoint).map_err(|error| DaemonError::Ipc(error.to_string()))?;
    let client_slots = Arc::new(tokio::sync::Semaphore::new(64));
    let frame_timeout = tokio::time::Duration::from_secs(5);

    loop {
        let mut client = listener
            .accept()
            .await
            .map_err(|error| DaemonError::Ipc(error.to_string()))?;
        let Ok(client_slot) = Arc::clone(&client_slots).try_acquire_owned() else {
            drop(client);
            continue;
        };
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _client_slot = client_slot;
            loop {
                let request: ControlRequest = match tokio::time::timeout(
                    frame_timeout,
                    read_json_frame(&mut client, 256 * 1024),
                )
                .await
                {
                    Ok(Ok(request)) => request,
                    Ok(Err(_)) | Err(_) => return,
                };
                let response = service.execute(request).await;
                match tokio::time::timeout(
                    frame_timeout,
                    write_json_frame(&mut client, &response, 256 * 1024),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => return,
                }
            }
        });
    }
}
