use bytes::Bytes;
use fix_mock::{MockConfig, run_mock_session};
use fix_protocol::{Field, FrameDecoder, encode_message, parse_frame};
use fix_session::StaticTimeSource;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn mock_logs_on_and_acknowledges_a_new_order_with_execution_report() {
    let (mut client, server) = duplex(16384);
    let mock = tokio::spawn(run_mock_session(
        server,
        MockConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "SERVER".to_owned(),
            target_comp_id: "CLIENT".to_owned(),
            heartbeat_interval_secs: 30,
        },
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    ));
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"CLIENT")),
            Field::new(56, Bytes::from_static(b"SERVER")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("client Logon");
    client.write_all(&logon).await.expect("write Logon");
    let mut bytes = vec![0_u8; 16384];
    let count = timeout(Duration::from_secs(1), client.read(&mut bytes))
        .await
        .expect("server Logon timeout")
        .expect("read server Logon");
    let mut decoder = FrameDecoder::new(16384);
    let server_logon = decoder.ingest(&bytes[..count]).expect("framed Logon");
    let server_logon = parse_frame(&server_logon[0]).expect("parsed Logon");
    assert_eq!(server_logon.msg_type(), Some(b"A".as_slice()));

    let order = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"D")),
            Field::new(49, Bytes::from_static(b"CLIENT")),
            Field::new(56, Bytes::from_static(b"SERVER")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(11, Bytes::from_static(b"FC-ORDER-1")),
            Field::new(55, Bytes::from_static(b"IBM")),
            Field::new(54, Bytes::from_static(b"1")),
            Field::new(60, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(38, Bytes::from_static(b"100")),
            Field::new(40, Bytes::from_static(b"2")),
            Field::new(44, Bytes::from_static(b"187.25")),
        ],
    )
    .expect("NewOrderSingle");
    client.write_all(&order).await.expect("write order");
    let count = timeout(Duration::from_secs(1), client.read(&mut bytes))
        .await
        .expect("ExecutionReport timeout")
        .expect("read ExecutionReport");
    let reports = decoder.ingest(&bytes[..count]).expect("framed report");
    let report = parse_frame(&reports[0]).expect("parsed report");

    assert_eq!(report.msg_type(), Some(b"8".as_slice()));
    assert_eq!(report.values(11).next(), Some(b"FC-ORDER-1".as_slice()));
    assert_eq!(report.values(150).next(), Some(b"0".as_slice()));
    assert_eq!(report.values(39).next(), Some(b"0".as_slice()));

    drop(client);
    mock.await.expect("mock task").expect("mock session");
}
