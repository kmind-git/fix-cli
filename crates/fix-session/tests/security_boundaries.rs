use bytes::Bytes;
use fix_protocol::{Field, encode_message};
use fix_session::{SessionConfig, SessionEvent, SessionPhase, StaticTimeSource, spawn_initiator};
use fix_store::{
    MemoryStore, RecoveryState, StoreError, StoreOp, StorePort, StoreReply, StoreWorker,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[derive(Clone)]
struct SharedStore {
    inner: Arc<Mutex<MemoryStore>>,
}

impl StorePort for SharedStore {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recover()
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .apply(operation)
    }
}

#[tokio::test]
async fn invalid_logon_heartbeat_is_rejected_before_inbound_commit() {
    let shared = Arc::new(Mutex::new(MemoryStore::new(b"semantic-audit-key")));
    let (session, mut peer) = duplex(8192);
    let handle = spawn_initiator(
        session,
        config(),
        StoreWorker::spawn(SharedStore {
            inner: Arc::clone(&shared),
        }),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    discard_outbound_logon(&mut peer).await;

    let invalid_logon = inbound_logon(vec![Field::new(108, Bytes::from_static(b"31"))]);
    peer.write_all(&invalid_logon)
        .await
        .expect("write invalid Logon");
    let error = next_protocol_error(&mut events).await;

    assert!(error.contains("HeartBtInt 31"), "{error}");
    let mut store = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(store.recover().expect("recover").next_in, 1);
    assert!(matches!(
        store
            .apply(StoreOp::LoadInbound(1))
            .expect("lookup inbound"),
        StoreReply::StoredInbound(None)
    ));
}

#[tokio::test]
async fn inbound_sensitive_fields_are_rejected_before_persistence() {
    let shared = Arc::new(Mutex::new(MemoryStore::new(b"sensitive-audit-key")));
    let (session, mut peer) = duplex(8192);
    let handle = spawn_initiator(
        session,
        config(),
        StoreWorker::spawn(SharedStore {
            inner: Arc::clone(&shared),
        }),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    discard_outbound_logon(&mut peer).await;

    let sensitive_logon = inbound_logon(vec![
        Field::new(108, Bytes::from_static(b"30")),
        Field::new(554, Bytes::from_static(b"must-not-persist")),
    ]);
    peer.write_all(&sensitive_logon)
        .await
        .expect("write sensitive Logon");
    let error = next_protocol_error(&mut events).await;

    assert!(error.contains("sensitive tag 554"), "{error}");
    let mut store = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(store.recover().expect("recover").next_in, 1);
    assert!(matches!(
        store
            .apply(StoreOp::LoadInbound(1))
            .expect("lookup inbound"),
        StoreReply::StoredInbound(None)
    ));
}

#[tokio::test]
async fn invalid_resend_range_is_rejected_before_inbound_commit() {
    let shared = Arc::new(Mutex::new(MemoryStore::new(b"resend-audit-key")));
    let (session, mut peer) = duplex(8192);
    let handle = spawn_initiator(
        session,
        config(),
        StoreWorker::spawn(SharedStore {
            inner: Arc::clone(&shared),
        }),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut events = handle.subscribe();
    discard_outbound_logon(&mut peer).await;
    peer.write_all(&inbound_logon(vec![Field::new(
        108,
        Bytes::from_static(b"30"),
    )]))
    .await
    .expect("write valid Logon");
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

    let invalid_resend = encode_message(
        b"FIX.4.4",
        &[
            Field::new(35, Bytes::from_static(b"2")),
            Field::new(49, Bytes::from_static(b"SERVER")),
            Field::new(56, Bytes::from_static(b"CLIENT")),
            Field::new(34, Bytes::from_static(b"2")),
            Field::new(52, Bytes::from_static(b"20260726-15:00:01.000")),
            Field::new(7, Bytes::from_static(b"0")),
            Field::new(16, Bytes::from_static(b"0")),
        ],
    )
    .expect("invalid ResendRequest");
    peer.write_all(&invalid_resend)
        .await
        .expect("write invalid ResendRequest");
    let error = next_protocol_error(&mut events).await;

    assert!(error.contains("invalid ResendRequest range"), "{error}");
    let mut store = shared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(store.recover().expect("recover").next_in, 2);
    assert!(matches!(
        store
            .apply(StoreOp::LoadInbound(2))
            .expect("lookup inbound"),
        StoreReply::StoredInbound(None)
    ));
}

fn config() -> SessionConfig {
    SessionConfig {
        begin_string: "FIX.4.4".to_owned(),
        sender_comp_id: "CLIENT".to_owned(),
        target_comp_id: "SERVER".to_owned(),
        heartbeat_interval_secs: 30,
        default_appl_ver_id: None,
    }
}

fn inbound_logon(mut trailing: Vec<Field>) -> bytes::Bytes {
    let mut fields = vec![
        Field::new(35, Bytes::from_static(b"A")),
        Field::new(49, Bytes::from_static(b"SERVER")),
        Field::new(56, Bytes::from_static(b"CLIENT")),
        Field::new(34, Bytes::from_static(b"1")),
        Field::new(52, Bytes::from_static(b"20260726-15:00:00.000")),
        Field::new(98, Bytes::from_static(b"0")),
    ];
    fields.append(&mut trailing);
    encode_message(b"FIX.4.4", &fields).expect("encode inbound Logon")
}

async fn discard_outbound_logon(peer: &mut tokio::io::DuplexStream) {
    let mut bytes = vec![0_u8; 8192];
    timeout(Duration::from_secs(1), peer.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
}

async fn next_protocol_error(
    events: &mut tokio::sync::broadcast::Receiver<SessionEvent>,
) -> String {
    timeout(Duration::from_secs(1), async {
        loop {
            if let SessionEvent::ProtocolError(error) = events.recv().await.expect("session event")
            {
                break error;
            }
        }
    })
    .await
    .expect("protocol error timeout")
}
