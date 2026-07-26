use fix_control::SessionSlot;
use fix_protocol::{
    CompiledDictionary, Field, FrameDecoder, MemberDefinition, MessageDefinition, ParseDictionary,
    ParsedMessage, encode_message, parse_frame,
};
use fix_store::{MemoryStore, StoreWorker};
use fixd::{SessionConfigFile, TransportConfig, TransportSecurity, run_connection_manager};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn connection_manager_reconnects_with_persisted_sequences_after_transport_loss() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind FIX venue");
    let address = listener.local_addr().expect("venue address");
    let manager = tokio::spawn(run_connection_manager(
        TransportConfig {
            host: address.ip().to_string(),
            port: address.port(),
            security: TransportSecurity::PlaintextCert,
            connect_timeout_ms: 250,
            reconnect_initial_ms: 10,
            reconnect_max_ms: 40,
        },
        SessionConfigFile {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            default_appl_ver_id: None,
            logon_fields_file: None,
        },
        Arc::new(logon_dictionary()),
        Vec::new(),
        StoreWorker::spawn(MemoryStore::new(b"reconnect-audit-key")),
        SessionSlot::new(),
    ));

    let (mut first, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("first connection timeout")
        .expect("first connection");
    let first_logon = read_message(&mut first).await;
    assert_eq!(first_logon.values(34).next(), Some(b"1".as_slice()));
    first
        .write_all(&server_logon(1))
        .await
        .expect("write first server Logon");
    first.shutdown().await.expect("close first connection");
    drop(first);

    let (mut second, _) = timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("reconnect timeout")
        .expect("second connection");
    let second_logon = read_message(&mut second).await;
    assert_eq!(second_logon.values(34).next(), Some(b"2".as_slice()));

    manager.abort();
}

async fn read_message(stream: &mut TcpStream) -> ParsedMessage {
    let mut decoder = FrameDecoder::new(16 * 1024);
    let mut bytes = vec![0_u8; 16 * 1024];
    loop {
        let count = stream.read(&mut bytes).await.expect("read FIX message");
        assert_ne!(count, 0, "transport closed before a FIX message");
        if let Some(frame) = decoder
            .ingest(&bytes[..count])
            .expect("frame FIX message")
            .into_iter()
            .next()
        {
            return parse_frame(&frame, &ParseDictionary::new()).expect("parse FIX message");
        }
    }
}

fn server_logon(sequence: u64) -> Vec<u8> {
    encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, "A".into()),
            Field::new(49, "SERVER".into()),
            Field::new(56, "CLIENT".into()),
            Field::new(34, sequence.to_string().into()),
            Field::new(52, "20260726-15:00:00.000".into()),
            Field::new(98, "0".into()),
            Field::new(108, "30".into()),
        ],
    )
    .expect("server Logon")
    .to_vec()
}

fn logon_dictionary() -> CompiledDictionary {
    CompiledDictionary::new("FIX.4.4").with_message(MessageDefinition {
        name: "Logon".to_owned(),
        msg_type: "A".to_owned(),
        members: vec![
            MemberDefinition::field(49, true),
            MemberDefinition::field(56, true),
            MemberDefinition::field(34, true),
            MemberDefinition::field(52, true),
            MemberDefinition::field(98, true),
            MemberDefinition::field(108, true),
        ],
    })
}
