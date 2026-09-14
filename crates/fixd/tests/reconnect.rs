use fix_control::SessionSlot;
use fix_protocol::{Field, FrameDecoder, ParsedMessage, encode_message, parse_frame};
use fixd::{SessionConfigFile, TransportConfig, run_connection_manager};
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
            connect_timeout_ms: 250,
            reconnect_initial_ms: 10,
            reconnect_max_ms: 40,
        },
        SessionConfigFile {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        Vec::new(),
        test_store(),
        SessionSlot::new(),
        fix_session::SessionLogger::disabled(),
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
            return parse_frame(&frame).expect("parse FIX message");
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

fn test_store() -> fix_store::StoreHandle {
    fix_store::StoreWorker::spawn(test_redb())
}

fn test_redb() -> fix_store::RedbStore {
    fix_store::RedbStore::open_in_memory()
}
