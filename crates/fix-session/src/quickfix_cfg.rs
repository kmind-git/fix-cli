//! Parsing for QuickFIX-style client/acceptor configuration files
//! (`CLIENT.CFG` / acceptor cfg): `[DEFAULT]` merged under named sections,
//! `#` and `;` full-line comments, GBK-tolerant lossy reading.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

type SectionTable = BTreeMap<String, String>;

use rust_decimal::Decimal;

const LOGON_FIELD_PREFIX: &str = "LogonField.";

#[derive(Clone, Debug)]
pub struct InitiatorSession {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub host: String,
    pub port: u16,
    pub heartbeat_interval_secs: u64,
    pub reconnect_interval_secs: u64,
    pub connect_timeout_ms: u64,
    pub logon_fields: Vec<(u32, String)>,
    pub max_quantity: Decimal,
    pub max_notional: Decimal,
    pub allow_market_orders: bool,
    pub max_messages_per_second: u32,
    pub reset_seq_num_flag: bool,
    pub file_log_path: Option<String>,
    pub file_store_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AcceptorSession {
    pub begin_string: String,
    pub sender_comp_id: String,
    pub target_comp_id: String,
    pub host: String,
    pub port: u16,
    pub heartbeat_interval_secs: u64,
    pub log_dir: Option<String>,
}

/// Read a cfg file; real-world files carry GBK-encoded Chinese comments while
/// keys and values are ASCII, so a lossy decode keeps the parse intact.
pub fn read_cfg_lossy(path: impl AsRef<Path>) -> Result<String, String> {
    let path = path.as_ref();
    let raw = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    match String::from_utf8(raw) {
        Ok(text) => Ok(text),
        Err(error) => {
            eprintln!(
                "note: {} is not UTF-8; decoded lossily (non-UTF-8 comments are skipped)",
                path.display()
            );
            Ok(String::from_utf8_lossy(error.as_bytes()).into_owned())
        }
    }
}

fn merged_sections(text: &str) -> Result<Vec<(String, SectionTable)>, String> {
    let mut default_section = BTreeMap::new();
    let mut sections: BTreeMap<String, SectionTable> = BTreeMap::new();
    let mut current: Option<String> = None;

    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = Some(name.trim().to_owned());
            sections.entry(name.trim().to_owned()).or_default();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "line {}: expected KEY=VALUE, got {raw_line:?}",
                index + 1
            ));
        };
        let entry = match &current {
            Some(name) if name != "DEFAULT" => {
                sections.get_mut(name).expect("section inserted above")
            }
            _ => &mut default_section,
        };
        entry.insert(key.trim().to_owned(), value.trim().to_owned());
    }

    Ok(sections
        .into_iter()
        .filter(|(name, _)| name != "DEFAULT")
        .map(|(name, own)| {
            let mut combined = default_section.clone();
            combined.extend(own);
            (name, combined)
        })
        .collect())
}

fn select_session(
    sections: Vec<(String, SectionTable)>,
    connection_type: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut matches = sections
        .into_iter()
        .filter(|(_, keys)| {
            keys.get("ConnectionType")
                .map(|value| value.eq_ignore_ascii_case(connection_type))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(format!(
            "no [section] with ConnectionType={connection_type} found"
        )),
        1 => Ok(matches.remove(0).1),
        n => Err(format!(
            "expected exactly one ConnectionType={connection_type} session, found {n}"
        )),
    }
}

/// Parse an initiator cfg (a real-venue client description).
pub fn parse_client_cfg(text: &str) -> Result<InitiatorSession, String> {
    let keys = select_session(merged_sections(text)?, "initiator")?;

    let required = |key: &str| {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("missing required key {key}"))
    };
    let optional = |key: &str| keys.get(key).filter(|value| !value.is_empty()).cloned();
    let parsed_u64 = |key: &str, default: u64| -> Result<u64, String> {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("key {key} is not a number: {value}"))
            })
            .unwrap_or(Ok(default))
    };
    let parsed_decimal = |key: &str, default: &str| -> Result<Decimal, String> {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .map(|value| {
                Decimal::from_str(value).map_err(|_| format!("key {key} is not a decimal: {value}"))
            })
            .unwrap_or_else(|| Ok(Decimal::from_str(default).expect("default decimal")))
    };
    let parsed_bool = |key: &str, default: bool| -> Result<bool, String> {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "y" | "yes" | "true" => Ok(true),
                "n" | "no" | "false" => Ok(false),
                _ => Err(format!("key {key} must be Y or N, got {value}")),
            })
            .unwrap_or(Ok(default))
    };

    if keys
        .get("UseDataDictionary")
        .is_some_and(|value| value.eq_ignore_ascii_case("Y"))
    {
        return Err(
            "UseDataDictionary=Y is not supported yet; set it to N for tag-only parsing".to_owned(),
        );
    }

    let mut logon_fields = Vec::new();
    for (key, value) in &keys {
        let Some(tag) = key.strip_prefix(LOGON_FIELD_PREFIX) else {
            continue;
        };
        let tag: u32 = tag
            .parse()
            .map_err(|_| format!("invalid LogonField tag {tag:?}"))?;
        if tag == 0 || value.is_empty() {
            return Err(format!("LogonField.{tag} has an invalid value"));
        }
        logon_fields.push((tag, value.clone()));
    }
    // QuickFIX-style credentials: Username(553)/Password(554) come from the
    // Account/Password keys and ride the Logon like any custom field.
    for (tag, key) in [(553_u32, "Account"), (554, "Password")] {
        if let Some(value) = keys.get(key).filter(|value| !value.is_empty()) {
            if logon_fields.iter().any(|(existing, _)| *existing == tag) {
                return Err(format!("{key} conflicts with LogonField.{tag}"));
            }
            logon_fields.push((tag, value.clone()));
        }
    }
    logon_fields.sort_by_key(|(tag, _)| *tag);

    let heartbeat_interval_secs = parsed_u64("HeartBtInt", 30)?;
    if heartbeat_interval_secs == 0 {
        return Err("HeartBtInt must be positive".to_owned());
    }
    let max_messages_per_second = parsed_u64("MaxMessagesPerSecond", 20)?;
    if max_messages_per_second == 0 {
        return Err("MaxMessagesPerSecond must be positive".to_owned());
    }

    Ok(InitiatorSession {
        begin_string: required("BeginString")?,
        sender_comp_id: required("SenderCompID")?,
        target_comp_id: required("TargetCompID")?,
        host: required("SocketConnectHost")?,
        port: parsed_u64("SocketConnectPort", 0)?
            .try_into()
            .map_err(|_| "SocketConnectPort must fit in u16".to_owned())?,
        heartbeat_interval_secs,
        reconnect_interval_secs: parsed_u64("ReconnectInterval", 10)?,
        connect_timeout_ms: parsed_u64("ConnectTimeoutMs", 5000)?,
        logon_fields,
        max_quantity: parsed_decimal("MaxQuantity", "10000")?,
        max_notional: parsed_decimal("MaxNotional", "100000000")?,
        allow_market_orders: parsed_bool("AllowMarketOrders", false)?,
        max_messages_per_second: max_messages_per_second as u32,
        reset_seq_num_flag: parsed_bool("ResetSeqNumFlag", false)?,
        file_log_path: optional("FileLogPath"),
        file_store_path: optional("FileStorePath"),
    })
}

/// Parse an acceptor cfg (a mock-venue listener description).
pub fn parse_acceptor_cfg(text: &str) -> Result<AcceptorSession, String> {
    let keys = select_session(merged_sections(text)?, "acceptor")?;

    let required = |key: &str| {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("missing required key {key}"))
    };
    let optional = |key: &str| keys.get(key).filter(|value| !value.is_empty()).cloned();
    let parsed_u64 = |key: &str, default: u64| -> Result<u64, String> {
        keys.get(key)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("key {key} is not a number: {value}"))
            })
            .unwrap_or(Ok(default))
    };

    let heartbeat_interval_secs = parsed_u64("HeartBtInt", 30)?;
    if heartbeat_interval_secs == 0 {
        return Err("HeartBtInt must be positive".to_owned());
    }

    Ok(AcceptorSession {
        begin_string: required("BeginString")?,
        sender_comp_id: required("SenderCompID")?,
        target_comp_id: required("TargetCompID")?,
        host: optional("SocketAcceptHost").unwrap_or_else(|| "127.0.0.1".to_owned()),
        port: parsed_u64("SocketAcceptPort", 0)?
            .try_into()
            .map_err(|_| "SocketAcceptPort must fit in u16".to_owned())?,
        heartbeat_interval_secs,
        log_dir: optional("FileLogPath"),
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_acceptor_cfg, parse_client_cfg};

    const SAMPLE: &str = "# comment\n[DEFAULT]\nReconnectInterval=10\nUseDataDictionary=N\n\n[trade]\nBeginString=FIX.4.4\nTargetCompID=HUNDSUNSTRD\nAccount=110853\nPassword=admin@123\nResetSeqNumFlag=N\nSenderCompID=CLIENTCOMPIDT_gq\nConnectionType=initiator\nSenderSubID=1000\nSocketConnectPort=20007\nSocketConnectHost=10.189.111.200\n";

    #[test]
    fn parses_the_real_client_cfg_shape() {
        let session = parse_client_cfg(SAMPLE).expect("parse");
        assert_eq!(session.begin_string, "FIX.4.4");
        assert_eq!(session.sender_comp_id, "CLIENTCOMPIDT_gq");
        assert_eq!(session.target_comp_id, "HUNDSUNSTRD");
        assert_eq!(session.host, "10.189.111.200");
        assert_eq!(session.port, 20007);
        assert_eq!(session.heartbeat_interval_secs, 30);
        assert_eq!(session.reconnect_interval_secs, 10);
        assert_eq!(session.connect_timeout_ms, 5000);
        assert_eq!(session.max_quantity.to_string(), "10000");
        assert_eq!(
            session.logon_fields,
            vec![
                (553_u32, "110853".to_owned()),
                (554, "admin@123".to_owned())
            ]
        );
    }

    #[test]
    fn reads_policy_logon_field_and_path_overrides() {
        let text = format!(
            "{SAMPLE}MaxQuantity=5000\nMaxNotional=999\nAllowMarketOrders=Y\nMaxMessagesPerSecond=50\nConnectTimeoutMs=2500\nHeartBtInt=15\nFileLogPath=./log/c_log\nFileStorePath=./store\nLogonField.50=1000\nLogonField.1090=trader01\n"
        );
        let session = parse_client_cfg(&text).expect("parse");
        assert_eq!(session.max_quantity.to_string(), "5000");
        assert_eq!(session.max_notional.to_string(), "999");
        assert!(session.allow_market_orders);
        assert_eq!(session.max_messages_per_second, 50);
        assert_eq!(session.connect_timeout_ms, 2500);
        assert_eq!(session.heartbeat_interval_secs, 15);
        assert_eq!(session.file_log_path.as_deref(), Some("./log/c_log"));
        assert_eq!(session.file_store_path.as_deref(), Some("./store"));
        // LogonField tags coexist; 553/554 fall back to Account/Password.
        assert_eq!(
            session.logon_fields,
            vec![
                (50, "1000".to_owned()),
                (553, "110853".to_owned()),
                (554, "admin@123".to_owned()),
                (1090, "trader01".to_owned()),
            ]
        );
    }

    #[test]
    fn rejects_password_duplicating_logon_field_554() {
        let text = format!("{SAMPLE}LogonField.554=other\n");
        let error = parse_client_cfg(&text).expect_err("must reject");
        assert!(error.contains("Password conflicts with LogonField.554"));
    }

    #[test]
    fn parses_reset_seq_num_flag() {
        let session = parse_client_cfg(SAMPLE).expect("parse default N");
        assert!(!session.reset_seq_num_flag);
        let text = SAMPLE.replace("ResetSeqNumFlag=N", "ResetSeqNumFlag=Y");
        let session = parse_client_cfg(&text).expect("parse Y");
        assert!(session.reset_seq_num_flag);
        let text = SAMPLE.replace("ResetSeqNumFlag=N", "ResetSeqNumFlag=maybe");
        assert!(parse_client_cfg(&text).is_err());
    }

    #[test]
    fn rejects_data_dictionary_mode() {
        let text = SAMPLE.replace("UseDataDictionary=N", "UseDataDictionary=Y");
        let error = parse_client_cfg(&text).expect_err("must reject");
        assert!(error.contains("UseDataDictionary=Y is not supported"));
    }

    #[test]
    fn requires_an_initiator_session() {
        let text = SAMPLE.replace("ConnectionType=initiator", "ConnectionType=acceptor");
        assert!(parse_client_cfg(&text).is_err());
    }

    const ACCEPTOR: &str = "[DEFAULT]\nFileLogPath=./logs\n\n[mock]\nBeginString=FIX.4.4\nSenderCompID=SERVER\nTargetCompID=CLIENT\nConnectionType=acceptor\nSocketAcceptHost=127.0.0.1\nSocketAcceptPort=19876\nHeartBtInt=30\n";

    #[test]
    fn parses_acceptor_cfg() {
        let session = parse_acceptor_cfg(ACCEPTOR).expect("parse");
        assert_eq!(session.begin_string, "FIX.4.4");
        assert_eq!(session.sender_comp_id, "SERVER");
        assert_eq!(session.target_comp_id, "CLIENT");
        assert_eq!(session.host, "127.0.0.1");
        assert_eq!(session.port, 19876);
        assert_eq!(session.heartbeat_interval_secs, 30);
        assert_eq!(session.log_dir.as_deref(), Some("./logs"));
    }

    #[test]
    fn acceptor_parser_ignores_initiator_sections() {
        let text = format!("{SAMPLE}{ACCEPTOR}");
        let session = parse_acceptor_cfg(&text).expect("parse");
        assert_eq!(session.port, 19876);
        assert!(parse_client_cfg(&text).is_ok());
    }
}
