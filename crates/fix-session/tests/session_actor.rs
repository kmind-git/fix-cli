use bytes::Bytes;
use fix_protocol::{Field, FrameDecoder, encode_message, parse_frame};
use fix_session::{
    ApplicationRequest, SessionConfig, SessionEvent, SessionPhase, StaticTimeSource,
    spawn_initiator,
};
use fix_store::{CommandPhase, OutboundCommit, StoreOp, StorePort};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn initiator_journals_and_sends_logon_using_the_recovered_sequence() {
    let (client, mut server) = duplex(4096);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );

    let mut bytes = vec![0_u8; 4096];
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("logon timeout")
        .expect("read logon");
    let mut decoder = FrameDecoder::new(4096);
    let frames = decoder.ingest(&bytes[..count]).expect("framed Logon");
    let logon = parse_frame(&frames[0]).expect("parsed Logon");
    let status = handle.status().await.expect("session status");

    assert_eq!(logon.msg_type(), Some(b"A".as_slice()));
    assert_eq!(logon.values(34).next(), Some(b"1".as_slice()));
    assert_eq!(logon.values(49).next(), Some(b"CLIENT".as_slice()));
    assert_eq!(logon.values(56).next(), Some(b"SERVER".as_slice()));
    assert_eq!(
        logon.values(52).next(),
        Some(b"20260726-15:00:00.000".as_slice())
    );
    assert_eq!(logon.values(98).next(), Some(b"0".as_slice()));
    assert_eq!(logon.values(108).next(), Some(b"30".as_slice()));
    assert_eq!(status.phase, SessionPhase::LogonSent);
    assert_eq!(status.next_out, 2);
    assert_eq!(status.next_in, 1);
}

#[tokio::test]
async fn inbound_test_request_is_committed_then_answered_with_matching_heartbeat() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");

    let server_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server
        .write_all(&server_logon)
        .await
        .expect("send server Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("establish timeout");

    let test_request = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"1")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(112, Bytes::from_static(b"PEER-LIVENESS-1")),
        ],
    )
    .expect("TestRequest");
    server
        .write_all(&test_request)
        .await
        .expect("send TestRequest");

    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("Heartbeat timeout")
        .expect("read Heartbeat");
    let mut decoder = FrameDecoder::new(8192);
    let frames = decoder.ingest(&bytes[..count]).expect("framed Heartbeat");
    let heartbeat = parse_frame(&frames[0]).expect("parsed Heartbeat");

    assert_eq!(heartbeat.msg_type(), Some(b"0".as_slice()));
    assert_eq!(
        heartbeat.values(112).next(),
        Some(b"PEER-LIVENESS-1".as_slice())
    );
    assert_eq!(handle.status().await.expect("status").next_in, 3);
}

#[tokio::test]
async fn matching_inbound_logon_is_committed_before_the_session_becomes_established() {
    let (client, mut server) = duplex(4096);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    let mut outbound_logon = vec![0_u8; 4096];
    timeout(Duration::from_secs(1), server.read(&mut outbound_logon))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");

    let inbound_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("encode server Logon");
    server
        .write_all(&inbound_logon)
        .await
        .expect("send server Logon");

    timeout(Duration::from_secs(1), async {
        loop {
            if events.recv().await == Ok(SessionEvent::PhaseChanged(SessionPhase::Established)) {
                break;
            }
        }
    })
    .await
    .expect("Established event timeout");
    let status = handle.status().await.expect("session status");

    assert_eq!(status.phase, SessionPhase::Established);
    assert_eq!(status.next_in, 2);
}

#[tokio::test]
async fn a_high_sequence_is_buffered_then_drained_after_a_gap_fill() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut outbound = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");

    let server_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&server_logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    let high_heartbeat = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"0")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"5")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
        ],
    )
    .expect("high sequence Heartbeat");
    server
        .write_all(&high_heartbeat)
        .await
        .expect("write high Heartbeat");

    let count = timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("ResendRequest timeout")
        .expect("read ResendRequest");
    let mut decoder = FrameDecoder::new(8192);
    let resend = decoder
        .ingest(&outbound[..count])
        .expect("framed ResendRequest");
    let resend = parse_frame(&resend[0]).expect("parsed ResendRequest");
    let status = handle.status().await.expect("status");

    assert_eq!(resend.msg_type(), Some(b"2".as_slice()));
    assert_eq!(resend.values(7).next(), Some(b"2".as_slice()));
    assert_eq!(resend.values(16).next(), Some(b"0".as_slice()));
    assert_eq!(status.phase, SessionPhase::Recovering);
    assert_eq!(status.next_in, 2);
    assert_eq!(status.next_out, 3);

    let gap_fill = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"4")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(123, Bytes::from_static(b"Y")),
            Field::new(36, Bytes::from_static(b"5")),
        ],
    )
    .expect("GapFill");
    server.write_all(&gap_fill).await.expect("write GapFill");

    timeout(Duration::from_secs(1), async {
        loop {
            let status = handle.status().await.expect("status");
            if status.phase == SessionPhase::Established && status.next_in == 6 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("gap recovery timeout");
}

#[tokio::test]
async fn a_gap_fill_discards_buffered_sequences_below_new_seq_no() {
    let (client, mut server) = duplex(8192);
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        test_store(),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut outbound = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("establish timeout");

    let stale = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"0")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"3")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
        ],
    )
    .expect("out-of-order Heartbeat");
    server.write_all(&stale).await.expect("write stale message");
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("ResendRequest timeout")
        .expect("read ResendRequest");

    let gap_fill = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"4")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(123, Bytes::from_static(b"Y")),
            Field::new(36, Bytes::from_static(b"4")),
        ],
    )
    .expect("GapFill");
    server.write_all(&gap_fill).await.expect("write GapFill");

    timeout(Duration::from_secs(1), async {
        loop {
            let status = handle.status().await.expect("status");
            if status.phase == SessionPhase::Established && status.next_in == 4 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stale buffered sequence must be discarded");
}

#[tokio::test]
async fn a_buffered_gap_fill_discards_messages_it_skips_during_drain() {
    let (client, mut server) = duplex(8192);
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        test_store(),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut outbound = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("establish timeout");

    let skipped = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"0")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"4")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:03.000")),
        ],
    )
    .expect("sequence 4 Heartbeat");
    server.write_all(&skipped).await.expect("write sequence 4");
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("ResendRequest timeout")
        .expect("read ResendRequest");

    let buffered_gap_fill = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"4")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"3")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(123, Bytes::from_static(b"Y")),
            Field::new(36, Bytes::from_static(b"5")),
        ],
    )
    .expect("buffered GapFill");
    server
        .write_all(&buffered_gap_fill)
        .await
        .expect("write buffered GapFill");

    let sequence_two = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"0")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
        ],
    )
    .expect("sequence 2 Heartbeat");
    server
        .write_all(&sequence_two)
        .await
        .expect("write sequence 2");

    timeout(Duration::from_secs(1), async {
        loop {
            let status = handle.status().await.expect("status");
            if status.phase == SessionPhase::Established && status.next_in == 5 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("buffered GapFill must remove skipped buffered messages");
}

#[tokio::test]
async fn a_low_sequence_possdup_is_verified_against_the_committed_original() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut outbound = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut outbound))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");

    let first_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("initial Logon");
    server
        .write_all(&first_logon)
        .await
        .expect("write initial Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    let duplicate_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(43, Bytes::from_static(b"Y")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
            Field::new(122, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("PossDup Logon");
    server
        .write_all(&duplicate_logon)
        .await
        .expect("write PossDup Logon");
    tokio::task::yield_now().await;

    let status = handle.status().await.expect("session remains available");
    assert_eq!(status.phase, SessionPhase::Established);
    assert_eq!(status.next_in, 2);

    let mut events = handle.subscribe();
    let tampered_duplicate = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(43, Bytes::from_static(b"Y")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(122, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"31")),
        ],
    )
    .expect("tampered PossDup Logon");
    server
        .write_all(&tampered_duplicate)
        .await
        .expect("write tampered PossDup Logon");
    let error = timeout(Duration::from_secs(1), async {
        loop {
            if let SessionEvent::ProtocolError(error) = events.recv().await.expect("session event")
            {
                break error;
            }
        }
    })
    .await
    .expect("tamper rejection timeout");
    assert!(error.contains("PossDup payload mismatch"), "{error}");
}

#[tokio::test]
async fn application_submit_is_idempotent_and_replays_with_possdup_on_request() {
    let (client, mut server) = duplex(16384);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 16384];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let server_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&server_logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    let request = ApplicationRequest {
        request_id: "agent-order-1".to_owned(),
        fingerprint: "f1".to_owned(),
        cl_ord_id: "FC-ORDER-1".to_owned(),
        msg_type: "D".to_owned(),
        fields: vec![
            Field::new(55, Bytes::from_static(b"IBM")),
            Field::new(54, Bytes::from_static(b"1")),
            Field::new(38, Bytes::from_static(b"100")),
            Field::new(40, Bytes::from_static(b"2")),
            Field::new(44, Bytes::from_static(b"187.25")),
            Field::new(59, Bytes::from_static(b"0")),
        ],
    };
    let first = handle.submit(request.clone()).await.expect("submit order");
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("order timeout")
        .expect("read order");
    let mut decoder = FrameDecoder::new(16384);
    let order = decoder.ingest(&bytes[..count]).expect("framed order");
    let order = parse_frame(&order[0]).expect("parsed order");

    assert_eq!(order.msg_type(), Some(b"D".as_slice()));
    assert_eq!(order.values(34).next(), Some(b"2".as_slice()));
    assert_eq!(order.values(11).next(), Some(b"FC-ORDER-1".as_slice()));
    assert_eq!(
        order.values(60).next(),
        Some(b"20260726-15:00:00.000".as_slice())
    );
    assert_eq!(first.msg_seq_num, 2);
    assert_eq!(first.phase, CommandPhase::Written);

    let retry = handle.submit(request).await.expect("idempotent retry");
    assert_eq!(retry, first);
    assert!(
        timeout(Duration::from_millis(50), server.read(&mut bytes))
            .await
            .is_err(),
        "idempotent retry must not produce another FIX frame"
    );

    let resend_request = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"2")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(7, Bytes::from_static(b"2")),
            Field::new(16, Bytes::from_static(b"2")),
        ],
    )
    .expect("ResendRequest");
    server
        .write_all(&resend_request)
        .await
        .expect("write ResendRequest");
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("replay timeout")
        .expect("read replay");
    let mut replay_decoder = FrameDecoder::new(16384);
    let replay = replay_decoder
        .ingest(&bytes[..count])
        .expect("framed replay");
    let replay = parse_frame(&replay[0]).expect("parsed replay");
    let status = handle.status().await.expect("status after replay");

    assert_eq!(replay.msg_type(), Some(b"D".as_slice()));
    assert_eq!(replay.values(34).next(), Some(b"2".as_slice()));
    assert_eq!(replay.values(43).next(), Some(b"Y".as_slice()));
    assert_eq!(
        replay.values(122).next(),
        Some(b"20260726-15:00:00.000".as_slice())
    );
    assert_eq!(status.next_out, 3);
    assert_eq!(status.next_in, 3);
}

#[tokio::test]
async fn resend_of_admin_only_range_uses_sequence_reset_gap_fill() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    let resend_request = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"2")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:02.000")),
            Field::new(7, Bytes::from_static(b"1")),
            Field::new(16, Bytes::from_static(b"1")),
        ],
    )
    .expect("ResendRequest");
    server
        .write_all(&resend_request)
        .await
        .expect("write ResendRequest");
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("GapFill timeout")
        .expect("read GapFill");
    let mut decoder = FrameDecoder::new(8192);
    let gap_fill = decoder.ingest(&bytes[..count]).expect("framed GapFill");
    let gap_fill = parse_frame(&gap_fill[0]).expect("parsed GapFill");

    assert_eq!(gap_fill.msg_type(), Some(b"4".as_slice()));
    assert_eq!(gap_fill.values(34).next(), Some(b"1".as_slice()));
    assert_eq!(gap_fill.values(43).next(), Some(b"Y".as_slice()));
    assert_eq!(gap_fill.values(123).next(), Some(b"Y".as_slice()));
    assert_eq!(gap_fill.values(36).next(), Some(b"2".as_slice()));
}

#[tokio::test]
async fn established_session_sends_heartbeat_after_outbound_inactivity() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 1,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"1")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    let count = timeout(Duration::from_secs(2), server.read(&mut bytes))
        .await
        .expect("Heartbeat timeout")
        .expect("read Heartbeat");
    let mut decoder = FrameDecoder::new(8192);
    let heartbeat = decoder.ingest(&bytes[..count]).expect("framed Heartbeat");
    let heartbeat = parse_frame(&heartbeat[0]).expect("parsed Heartbeat");

    assert_eq!(heartbeat.msg_type(), Some(b"0".as_slice()));
    assert_eq!(heartbeat.values(34).next(), Some(b"2".as_slice()));
}

#[tokio::test]
async fn inbound_silence_sends_test_request_and_matching_heartbeat_clears_it() {
    let (client, mut server) = duplex(16384);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 1,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 16384];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"1")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");

    let test_request = timeout(Duration::from_secs(4), async {
        let mut decoder = FrameDecoder::new(16384);
        loop {
            let count = server.read(&mut bytes).await.expect("read session message");
            for frame in decoder
                .ingest(&bytes[..count])
                .expect("framed session message")
            {
                let message = parse_frame(&frame).expect("parsed session message");
                if message.msg_type() == Some(b"1".as_slice()) {
                    return message;
                }
            }
        }
    })
    .await
    .expect("TestRequest timeout");
    let test_req_id = test_request.values(112).next().expect("TestReqID").to_vec();
    assert_eq!(
        handle
            .status()
            .await
            .expect("status")
            .test_request_outstanding
            .as_deref(),
        Some(std::str::from_utf8(&test_req_id).expect("ASCII TestReqID"))
    );

    let heartbeat = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"0")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:03.000")),
            Field::new(112, Bytes::from(test_req_id)),
        ],
    )
    .expect("matching Heartbeat");
    server
        .write_all(&heartbeat)
        .await
        .expect("write matching Heartbeat");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle
                .status()
                .await
                .expect("status")
                .test_request_outstanding
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("matching Heartbeat was not observed");
}

#[tokio::test]
async fn test_request_timeout_sends_logout_before_the_session_blocks() {
    let (client, mut server) = duplex(16384);
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 1,
            reset_on_logon: false,
        },
        test_store(),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    let mut bytes = vec![0_u8; 16384];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"1")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");

    let logout = timeout(Duration::from_secs(5), async {
        let mut decoder = FrameDecoder::new(16384);
        let mut saw_test_request = false;
        loop {
            let count = server.read(&mut bytes).await.expect("read session message");
            assert_ne!(count, 0, "session closed without Logout");
            for frame in decoder
                .ingest(&bytes[..count])
                .expect("framed session message")
            {
                let message = parse_frame(&frame).expect("parsed session message");
                if message.msg_type() == Some(b"1".as_slice()) {
                    saw_test_request = true;
                }
                if saw_test_request && message.msg_type() == Some(b"5".as_slice()) {
                    return message;
                }
            }
        }
    })
    .await
    .expect("Logout timeout");
    assert_eq!(
        logout.values(58).next(),
        Some(b"TestRequest response timeout".as_slice())
    );
    timeout(Duration::from_secs(1), async {
        loop {
            if events.recv().await == Ok(SessionEvent::PhaseChanged(SessionPhase::Blocked)) {
                break;
            }
        }
    })
    .await
    .expect("Blocked event timeout");
}

#[tokio::test]
async fn explicit_logout_transitions_to_logout_sent_and_accepts_peer_response() {
    let (client, mut server) = duplex(8192);
    let store = test_store();
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
        ],
    )
    .expect("server Logon");
    server.write_all(&logon).await.expect("write Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Established timeout");

    handle
        .logout(Some("operator request".to_owned()))
        .await
        .expect("initiate Logout");
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("Logout timeout")
        .expect("read Logout");
    let mut decoder = FrameDecoder::new(8192);
    let logout = decoder.ingest(&bytes[..count]).expect("framed Logout");
    let logout = parse_frame(&logout[0]).expect("parsed Logout");
    assert_eq!(logout.msg_type(), Some(b"5".as_slice()));
    assert_eq!(
        logout.values(58).next(),
        Some(b"operator request".as_slice())
    );
    assert_eq!(
        handle.status().await.expect("status").phase,
        SessionPhase::LogoutSent
    );

    let peer_logout = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"5")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
        ],
    )
    .expect("peer Logout");
    server
        .write_all(&peer_logout)
        .await
        .expect("write peer Logout");
    timeout(Duration::from_secs(1), async {
        loop {
            if handle.status().await.expect("status").phase == SessionPhase::Disconnected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Disconnected timeout");
}

#[tokio::test]
async fn reset_on_logon_sends_141y_and_restarts_sequences_at_one() {
    let (client, mut server) = duplex(8192);
    let mut memory = test_redb();
    memory
        .apply(StoreOp::CommitOutbound(OutboundCommit {
            request_id: "seed-1".to_owned(),
            fingerprint: "seed".to_owned(),
            cl_ord_id: String::new(),
            msg_seq_num: 1,
            wire: b"seed".to_vec(),
        }))
        .expect("seed journal so recovery starts above 1");
    let store = fix_store::StoreWorker::spawn(memory);
    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: true,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    let mut bytes = vec![0_u8; 8192];
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");

    let mut decoder = FrameDecoder::new(8192);
    let frame = decoder.ingest(&bytes[..count]).expect("frame Logon");
    let logon = parse_frame(&frame[0]).expect("parse Logon");
    assert_eq!(logon.values(141).next(), Some(b"Y".as_slice()));
    assert_eq!(logon.values(34).next(), Some(b"1".as_slice()));

    let server_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"30")),
            Field::new(141, Bytes::from_static(b"Y")),
        ],
    )
    .expect("server Logon");
    server
        .write_all(&server_logon)
        .await
        .expect("send server Logon");

    timeout(Duration::from_secs(1), async {
        loop {
            if events.recv().await == Ok(SessionEvent::PhaseChanged(SessionPhase::Established)) {
                break;
            }
        }
    })
    .await
    .expect("establish timeout");
    let status = handle.status().await.expect("status");
    assert_eq!(status.next_in, 2);
    assert_eq!(status.next_out, 2);
}

#[tokio::test]
async fn reset_epoch_survives_its_first_heartbeat_despite_stale_admin_records() {
    let (client, mut server) = duplex(8192);
    // Simulate a previous epoch: a journaled heartbeat at seq 2 with the
    // deterministic id/fingerprint a fresh epoch would reuse after a reset.
    let mut memory = test_redb();
    memory
        .apply(StoreOp::CommitOutbound(OutboundCommit {
            request_id: "seed-logon".to_owned(),
            fingerprint: "seed".to_owned(),
            cl_ord_id: String::new(),
            msg_seq_num: 1,
            wire: b"seed".to_vec(),
        }))
        .expect("seed outbound 1");
    memory
        .apply(StoreOp::CommitOutbound(OutboundCommit {
            request_id: "session:heartbeat:2".to_owned(),
            fingerprint: "admin:0:2".to_owned(),
            cl_ord_id: String::new(),
            msg_seq_num: 2,
            wire: b"stale-heartbeat".to_vec(),
        }))
        .expect("seed stale heartbeat command");
    let store = fix_store::StoreWorker::spawn(memory);

    let handle = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 1,
            reset_on_logon: true,
        },
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    let mut bytes = vec![0_u8; 8192];
    let count = timeout(Duration::from_secs(2), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let mut decoder = FrameDecoder::new(8192);
    let frame = decoder.ingest(&bytes[..count]).expect("frame Logon");
    let logon = parse_frame(&frame[0]).expect("parse Logon");
    assert_eq!(logon.values(34).next(), Some(b"1".as_slice()));

    let server_logon = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"A")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"1")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
            Field::new(98, Bytes::from_static(b"0")),
            Field::new(108, Bytes::from_static(b"1")),
            Field::new(141, Bytes::from_static(b"Y")),
        ],
    )
    .expect("server Logon");
    server
        .write_all(&server_logon)
        .await
        .expect("send server Logon");
    timeout(Duration::from_secs(2), async {
        loop {
            if events.recv().await == Ok(SessionEvent::PhaseChanged(SessionPhase::Established)) {
                break;
            }
        }
    })
    .await
    .expect("establish timeout");

    // HeartBtInt=1: the epoch's own heartbeat at seq 2 must journal cleanly
    // instead of colliding with the stale pre-reset command record.
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let status = handle.status().await.expect("status");
    assert_eq!(status.phase, SessionPhase::Established);
    assert_eq!(status.next_out, 3, "logon (1) plus heartbeat (2) were sent");
}

fn test_store() -> fix_store::StoreHandle {
    fix_store::StoreWorker::spawn(test_redb())
}

fn test_redb() -> fix_store::RedbStore {
    fix_store::RedbStore::open_in_memory()
}
