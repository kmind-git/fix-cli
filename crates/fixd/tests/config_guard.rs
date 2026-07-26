use fixd::DaemonConfig;

#[test]
fn live_daemon_is_rejected_until_a_production_pure_rust_tls_provider_is_approved() {
    let config = r#"
profile = "broker-a-live"
runtime_mode = "live"
database = "data/broker-a-live.redb"
audit_key_file = "secrets/audit.key"
dictionary = "dictionaries/compiled/fix44.json"
dictionary_sha256 = "00"

[transport]
host = "127.0.0.1"
port = 19876
security = "plaintext_cert"

[session]
begin_string = "FIX.4.4"
sender_comp_id = "CLIENT"
target_comp_id = "SERVER"
heartbeat_interval_secs = 30

[policy]
allowed_symbols = ["IBM"]
max_quantity = "1000"
max_notional = "1000000"
allow_market_orders = false
"#;

    let error = DaemonConfig::parse(config).expect_err("live must fail closed");

    assert_eq!(error.code(), "PRODUCTION_LIVE_DISABLED");
}

#[test]
fn fixt_requires_an_explicit_default_application_version() {
    let config = r#"
profile = "broker-a-uat"
runtime_mode = "certification"
database = "data/broker-a-uat.redb"
audit_key_file = "secrets/audit.key"
dictionary = "dictionaries/compiled/fixt11.json"
dictionary_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[transport]
host = "127.0.0.1"
port = 19876
security = "plaintext_cert"

[session]
begin_string = "FIXT.1.1"
sender_comp_id = "CLIENT"
target_comp_id = "SERVER"
heartbeat_interval_secs = 30

[policy]
allowed_symbols = ["IBM"]
max_quantity = "1000"
max_notional = "1000000"
allow_market_orders = false
"#;

    let error = DaemonConfig::parse(config).expect_err("FIXT default app version is required");

    assert_eq!(error.code(), "INVALID_CONFIG");
    assert!(error.to_string().contains("default_appl_ver_id"));
}

#[test]
fn fixt_accepts_an_explicit_fix50sp2_default_application_version() {
    let config = r#"
profile = "broker-a-uat"
runtime_mode = "certification"
database = "data/broker-a-uat.redb"
audit_key_file = "secrets/audit.key"
dictionary = "dictionaries/compiled/fixt11.json"
dictionary_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[transport]
host = "127.0.0.1"
port = 19876
security = "plaintext_cert"

[session]
begin_string = "FIXT.1.1"
sender_comp_id = "CLIENT"
target_comp_id = "SERVER"
heartbeat_interval_secs = 30
default_appl_ver_id = "9"

[policy]
allowed_symbols = ["IBM"]
max_quantity = "1000"
max_notional = "1000000"
allow_market_orders = false
"#;

    let config = DaemonConfig::parse(config).expect("valid FIXT profile");

    assert_eq!(config.session.default_appl_ver_id.as_deref(), Some("9"));
}
