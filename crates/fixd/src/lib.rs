#![forbid(unsafe_code)]

use rust_decimal::Decimal;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub profile: String,
    pub runtime_mode: RuntimeModeConfig,
    pub database: PathBuf,
    pub audit_key_file: PathBuf,
    pub dictionary: PathBuf,
    pub dictionary_sha256: String,
    pub transport: TransportConfig,
    pub session: SessionConfigFile,
    pub policy: PolicyConfig,
    pub ipc_endpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeModeConfig {
    Certification,
    Live,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    pub host: String,
    pub port: u16,
    pub security: TransportSecurity,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_reconnect_initial_ms")]
    pub reconnect_initial_ms: u64,
    #[serde(default = "default_reconnect_max_ms")]
    pub reconnect_max_ms: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportSecurity {
    PlaintextCert,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConfigFile {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub heartbeat_interval_secs: u64,
    pub default_appl_ver_id: Option<String>,
    pub logon_fields_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub allowed_symbols: Vec<String>,
    pub max_quantity: String,
    pub max_notional: String,
    pub allow_market_orders: bool,
    #[serde(default = "default_max_messages_per_second")]
    pub max_messages_per_second: u32,
}

impl DaemonConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(input).map_err(|error| ConfigError::new("INVALID_CONFIG", error))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::new("INVALID_CONFIG", error))?;
        Self::parse(&content)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.runtime_mode == RuntimeModeConfig::Live {
            return Err(ConfigError::message(
                "PRODUCTION_LIVE_DISABLED",
                "strict pure-Rust production TLS provider is not approved",
            ));
        }
        if self.profile.is_empty()
            || !self
                .profile
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "profile must contain lowercase ASCII letters, digits, or '-'",
            ));
        }
        if self.transport.host.is_empty() {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "transport host is empty",
            ));
        }
        if self.transport.connect_timeout_ms == 0
            || self.transport.reconnect_initial_ms == 0
            || self.transport.reconnect_max_ms < self.transport.reconnect_initial_ms
        {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "transport timeouts must be positive and reconnect_max_ms must be >= reconnect_initial_ms",
            ));
        }
        if self.session.heartbeat_interval_secs == 0 {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "heartbeat_interval_secs must be positive",
            ));
        }
        if !matches!(self.session.begin_string.as_str(), "FIX.4.4" | "FIXT.1.1") {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "begin_string must be FIX.4.4 or FIXT.1.1",
            ));
        }
        match (
            self.session.begin_string.as_str(),
            self.session.default_appl_ver_id.as_deref(),
        ) {
            ("FIXT.1.1", Some(value))
                if !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii() && !matches!(byte, b'=' | 0x01)) => {}
            ("FIXT.1.1", _) => {
                return Err(ConfigError::message(
                    "INVALID_CONFIG",
                    "FIXT.1.1 requires a non-empty ASCII default_appl_ver_id",
                ));
            }
            ("FIX.4.4", Some(_)) => {
                return Err(ConfigError::message(
                    "INVALID_CONFIG",
                    "default_appl_ver_id is only valid with FIXT.1.1",
                ));
            }
            _ => {}
        }
        if self.policy.allowed_symbols.is_empty() {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "policy allowed_symbols must not be empty",
            ));
        }
        if self.policy.max_messages_per_second == 0 {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "max_messages_per_second must be positive",
            ));
        }
        if self.policy.allow_market_orders {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "allow_market_orders cannot be enabled until a bounded reference-price policy is implemented",
            ));
        }
        for (name, value) in [
            ("max_quantity", self.policy.max_quantity.as_str()),
            ("max_notional", self.policy.max_notional.as_str()),
        ] {
            let decimal = Decimal::from_str(value).map_err(|_| {
                ConfigError::message("INVALID_CONFIG", format!("{name} is not a decimal"))
            })?;
            if decimal <= Decimal::ZERO {
                return Err(ConfigError::message(
                    "INVALID_CONFIG",
                    format!("{name} must be positive"),
                ));
            }
        }
        if self.dictionary_sha256.len() != 64
            || !self
                .dictionary_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "dictionary_sha256 must contain 64 hexadecimal characters",
            ));
        }
        if self
            .audit_key_file
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("example"))
        {
            return Err(ConfigError::message(
                "INVALID_CONFIG",
                "audit_key_file must not point at a tracked example file",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("dictionary error: {0}")]
    Dictionary(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("IPC error: {0}")]
    Ipc(String),
    #[error("policy error: {0}")]
    Policy(String),
}

pub async fn run_daemon(config_path: PathBuf) -> Result<(), DaemonError> {
    use fix_control::{
        CommandPlanner, ControlRequest, ControlService, Policy, RuntimeMode, SessionSlot,
    };
    use fix_ipc::{LocalListener, endpoint_for_profile, read_json_frame, write_json_frame};
    use fix_store::{RedbStore, StoreWorker};

    let config = DaemonConfig::load(&config_path)?;
    let base = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let dictionary = load_dictionary(base, &config)?;
    let audit_key = load_audit_key(base, &config)?;
    let database_path = resolve(base, &config.database);
    if let Some(parent) = database_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| DaemonError::Io(error.to_string()))?;
    }
    let store = RedbStore::open(&database_path, &audit_key)
        .map_err(|error| DaemonError::Store(error.to_string()))?;
    let store = StoreWorker::spawn(store);
    let logon_fields = load_logon_fields(base, config.session.logon_fields_file.as_deref())?;

    let policy = Policy {
        allowed_symbols: config
            .policy
            .allowed_symbols
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        max_quantity: Decimal::from_str(&config.policy.max_quantity)
            .map_err(|error| DaemonError::Policy(error.to_string()))?,
        max_notional: Decimal::from_str(&config.policy.max_notional)
            .map_err(|error| DaemonError::Policy(error.to_string()))?,
        allow_market_orders: config.policy.allow_market_orders,
        max_messages_per_second: config.policy.max_messages_per_second,
    };
    let planner = CommandPlanner::new(&config.profile, RuntimeMode::Certification, policy);
    let sessions = SessionSlot::new();
    let control_store = store.clone();
    tokio::spawn(run_connection_manager(
        config.transport.clone(),
        config.session.clone(),
        Arc::new(dictionary),
        logon_fields,
        store,
        sessions.clone(),
    ));
    let service = Arc::new(ControlService::new_dynamic_with_store(
        planner,
        sessions,
        control_store,
    ));
    let endpoint = config
        .ipc_endpoint
        .clone()
        .unwrap_or_else(|| endpoint_for_profile(&config.profile));
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
                };
            }
        });
    }
}

pub async fn run_connection_manager(
    transport: TransportConfig,
    session_config: SessionConfigFile,
    dictionary: Arc<fix_protocol::CompiledDictionary>,
    logon_fields: Vec<fix_protocol::Field>,
    store: fix_store::StoreHandle,
    sessions: fix_control::SessionSlot,
) {
    use fix_session::{
        SessionConfig, SessionEvent, SessionPhase, SystemTimeSource,
        spawn_initiator_with_dictionary_and_logon_fields,
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
            let session = spawn_initiator_with_dictionary_and_logon_fields(
                stream,
                SessionConfig {
                    begin_string: session_config.begin_string.clone(),
                    sender_comp_id: session_config.sender_comp_id.clone(),
                    target_comp_id: session_config.target_comp_id.clone(),
                    heartbeat_interval_secs: session_config.heartbeat_interval_secs,
                    default_appl_ver_id: session_config.default_appl_ver_id.clone(),
                },
                Arc::clone(&dictionary),
                logon_fields.clone(),
                store.clone(),
                Arc::new(SystemTimeSource),
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

pub fn validate_daemon_files(config_path: &std::path::Path) -> Result<(), DaemonError> {
    let config = DaemonConfig::load(config_path)?;
    let base = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    load_dictionary(base, &config)?;
    load_logon_fields(base, config.session.logon_fields_file.as_deref())?;
    load_audit_key(base, &config)?;
    Ok(())
}

fn load_dictionary(
    base: &std::path::Path,
    config: &DaemonConfig,
) -> Result<fix_protocol::CompiledDictionary, DaemonError> {
    let dictionary_bytes = std::fs::read(resolve(base, &config.dictionary))
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    let actual_dictionary_hash = hex(&Sha256::digest(&dictionary_bytes));
    if !actual_dictionary_hash.eq_ignore_ascii_case(&config.dictionary_sha256) {
        return Err(DaemonError::Dictionary(format!(
            "dictionary SHA-256 mismatch: expected {}, got {actual_dictionary_hash}",
            config.dictionary_sha256
        )));
    }
    let dictionary: fix_protocol::CompiledDictionary = serde_json::from_slice(&dictionary_bytes)
        .map_err(|error| DaemonError::Dictionary(error.to_string()))?;
    if dictionary.artifact_version != 1 {
        return Err(DaemonError::Dictionary(format!(
            "unsupported dictionary artifact_version {}; expected 1",
            dictionary.artifact_version
        )));
    }
    if !dictionary
        .begin_strings
        .iter()
        .any(|value| value == &config.session.begin_string)
    {
        return Err(DaemonError::Dictionary(
            "dictionary does not allow the configured BeginString".to_owned(),
        ));
    }
    Ok(dictionary)
}

fn load_audit_key(base: &std::path::Path, config: &DaemonConfig) -> Result<Vec<u8>, DaemonError> {
    let audit_key = std::fs::read(resolve(base, &config.audit_key_file))
        .map_err(|error| DaemonError::Io(error.to_string()))?;
    if audit_key.len() < 32 {
        return Err(DaemonError::Config(ConfigError::message(
            "INVALID_CONFIG",
            "audit key must contain at least 32 bytes",
        )));
    }
    Ok(audit_key)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogonFieldsDocument {
    fields: Vec<LogonFieldDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogonFieldDocument {
    tag: u32,
    value: String,
}

fn load_logon_fields(
    base: &std::path::Path,
    path: Option<&std::path::Path>,
) -> Result<Vec<fix_protocol::Field>, DaemonError> {
    use bytes::Bytes;
    use std::collections::BTreeSet;

    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let bytes =
        std::fs::read(resolve(base, path)).map_err(|error| DaemonError::Io(error.to_string()))?;
    let document: LogonFieldsDocument = serde_json::from_slice(&bytes)
        .map_err(|error| DaemonError::Config(ConfigError::new("INVALID_CONFIG", error)))?;
    if document.fields.len() > 16 {
        return Err(DaemonError::Config(ConfigError::message(
            "INVALID_CONFIG",
            "logon fields file exceeds the 16-field limit",
        )));
    }
    let mut tags = BTreeSet::new();
    let fields = document
        .fields
        .into_iter()
        .map(|field| {
            if field.tag == 0
                || field.value.len() > 4_096
                || field.value.as_bytes().contains(&0x01)
                || !tags.insert(field.tag)
            {
                return Err(DaemonError::Config(ConfigError::message(
                    "INVALID_CONFIG",
                    format!("invalid custom Logon field {}", field.tag),
                )));
            }
            Ok(fix_protocol::Field::new(
                field.tag,
                Bytes::from(field.value),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    fix_session::validate_custom_logon_fields(&fields).map_err(|error| {
        DaemonError::Config(ConfigError::message("INVALID_CONFIG", error.to_string()))
    })?;
    Ok(fields)
}

fn resolve(base: &std::path::Path, path: &std::path::Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

const fn default_max_messages_per_second() -> u32 {
    10
}

const fn default_connect_timeout_ms() -> u64 {
    5_000
}

const fn default_reconnect_initial_ms() -> u64 {
    250
}

const fn default_reconnect_max_ms() -> u64 {
    30_000
}

fn hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct ConfigError {
    code: &'static str,
    message: String,
}

impl ConfigError {
    fn new(code: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            code,
            message: error.to_string(),
        }
    }

    fn message(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
