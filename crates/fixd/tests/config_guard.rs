use fix_protocol::CompiledDictionary;
use fixd::{DaemonConfig, validate_daemon_files};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

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

#[test]
fn market_orders_cannot_be_enabled_without_a_bounded_reference_price() {
    let config = r#"
profile = "broker-a-uat"
runtime_mode = "certification"
database = "data/broker-a-uat.redb"
audit_key_file = "secrets/audit.key"
dictionary = "dictionaries/compiled/fix44.json"
dictionary_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

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
allow_market_orders = true
"#;

    let error = DaemonConfig::parse(config).expect_err("market orders must fail closed");

    assert_eq!(error.code(), "INVALID_CONFIG");
    assert!(error.to_string().contains("reference-price"));
}

#[test]
fn file_validation_rejects_a_dictionary_with_the_wrong_begin_string() {
    let directory = fixture_directory("wrong-begin-string");
    let dictionary = CompiledDictionary::new("FIXT.1.1");
    let config = write_validation_fixture(&directory, &dictionary, None);

    let error = validate_daemon_files(&config).expect_err("BeginString mismatch must fail");

    assert!(
        error
            .to_string()
            .contains("does not allow the configured BeginString")
    );
    std::fs::remove_dir_all(directory).expect("remove fixture directory");
}

#[test]
fn file_validation_rejects_an_unknown_dictionary_artifact_version() {
    let directory = fixture_directory("artifact-version");
    let mut dictionary = CompiledDictionary::new("FIX.4.4");
    dictionary.artifact_version = 2;
    let config = write_validation_fixture(&directory, &dictionary, None);

    let error = validate_daemon_files(&config).expect_err("unknown artifact version must fail");

    assert!(error.to_string().contains("artifact_version 2"));
    std::fs::remove_dir_all(directory).expect("remove fixture directory");
}

#[test]
fn file_validation_rejects_daemon_managed_custom_logon_tags() {
    let directory = fixture_directory("managed-logon-tag");
    let dictionary = CompiledDictionary::new("FIX.4.4");
    let config = write_validation_fixture(
        &directory,
        &dictionary,
        Some(r#"{"fields":[{"tag":35,"value":"A"}]}"#),
    );

    let error = validate_daemon_files(&config).expect_err("managed Logon tag must fail validate");

    assert!(error.to_string().contains("custom Logon field 35"));
    std::fs::remove_dir_all(directory).expect("remove fixture directory");
}

fn fixture_directory(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-data")
        .join(format!("fixd-{name}-{}", std::process::id()))
}

fn write_validation_fixture(
    directory: &Path,
    dictionary: &CompiledDictionary,
    logon_fields: Option<&str>,
) -> PathBuf {
    std::fs::create_dir_all(directory).expect("create fixture directory");
    let dictionary_bytes = serde_json::to_vec(dictionary).expect("serialize dictionary");
    std::fs::write(directory.join("dictionary.json"), &dictionary_bytes).expect("write dictionary");
    std::fs::write(directory.join("audit.key"), [0x5a_u8; 32]).expect("write audit key");
    let digest = Sha256::digest(&dictionary_bytes);
    let dictionary_sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let logon_fields_setting = if let Some(logon_fields) = logon_fields {
        std::fs::write(directory.join("logon-fields.json"), logon_fields)
            .expect("write Logon fields");
        "logon_fields_file = \"logon-fields.json\"\n"
    } else {
        ""
    };
    let config = format!(
        r#"
profile = "broker-a-uat"
runtime_mode = "certification"
database = "database.redb"
audit_key_file = "audit.key"
dictionary = "dictionary.json"
dictionary_sha256 = "{dictionary_sha256}"

[transport]
host = "127.0.0.1"
port = 19876
security = "plaintext_cert"

[session]
begin_string = "FIX.4.4"
sender_comp_id = "CLIENT"
target_comp_id = "SERVER"
heartbeat_interval_secs = 30
{logon_fields_setting}

[policy]
allowed_symbols = ["IBM"]
max_quantity = "1000"
max_notional = "1000000"
allow_market_orders = false
"#
    );
    let path = directory.join("fixd.toml");
    std::fs::write(&path, config).expect("write config");
    path
}
