use bytes::Bytes;
use fix_protocol::{Field, encode_message};
use fix_session::{
    ApplicationRequest, SessionConfig, SessionError, SessionPhase, StaticTimeSource,
    spawn_initiator,
};
use fix_store::{
    MemoryStore, RecoveryState, StoreError, StoreOp, StorePort, StoreReply, StoreWorker,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

struct FailApplicationJournal {
    inner: MemoryStore,
}

impl StorePort for FailApplicationJournal {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        self.inner.recover()
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        if matches!(
            &operation,
            StoreOp::CommitOutbound(commit) if !commit.cl_ord_id.is_empty()
        ) {
            return Err(StoreError::Backend(
                "injected application journal failure".to_owned(),
            ));
        }
        self.inner.apply(operation)
    }
}

#[tokio::test]
async fn injected_journal_failure_prevents_any_application_socket_write() {
    let (client, mut server) = duplex(16 * 1024);
    let session = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            default_appl_ver_id: None,
        },
        StoreWorker::spawn(FailApplicationJournal {
            inner: MemoryStore::new(b"fault-injection-audit-key"),
        }),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 16 * 1024];
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
    server.write_all(&logon).await.expect("write server Logon");
    timeout(Duration::from_secs(1), async {
        loop {
            if session.status().await.expect("status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("establish timeout");

    let error = session
        .submit(ApplicationRequest {
            request_id: "fault-order-1".to_owned(),
            fingerprint: "fingerprint".to_owned(),
            cl_ord_id: "FC-FAULT-1".to_owned(),
            msg_type: "D".to_owned(),
            fields: vec![
                Field::new(55, Bytes::from_static(b"IBM")),
                Field::new(54, Bytes::from_static(b"1")),
                Field::new(38, Bytes::from_static(b"10")),
                Field::new(40, Bytes::from_static(b"2")),
                Field::new(44, Bytes::from_static(b"100")),
                Field::new(59, Bytes::from_static(b"0")),
            ],
        })
        .await
        .expect_err("injected journal failure");
    assert!(
        matches!(error, SessionError::Store(ref value) if value.contains("injected application journal failure"))
    );
    assert!(
        timeout(Duration::from_millis(100), server.read(&mut bytes))
            .await
            .is_err(),
        "application bytes were written despite journal failure"
    );
}
