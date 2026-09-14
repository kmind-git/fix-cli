use bytes::Bytes;
use fix_protocol::{Field, FrameDecoder, parse_frame};
use fix_session::{SessionConfig, SessionLogger, StaticTimeSource, spawn_initiator_logged};
use fix_store::{RecoveryState, StoreError, StoreOp, StorePort, StoreReply};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, duplex};
use tokio::time::{Duration, timeout};

struct CaptureLogonJournal {
    inner: fix_store::RedbStore,
    wire: Arc<Mutex<Option<Vec<u8>>>>,
}

impl StorePort for CaptureLogonJournal {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        self.inner.recover()
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        if let StoreOp::CommitOutbound(commit) = &operation
            && commit.msg_seq_num == 1
        {
            *self
                .wire
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(commit.wire.clone());
        }
        self.inner.apply(operation)
    }
}

#[tokio::test]
async fn logon_credentials_are_sent_but_redacted_from_the_replay_journal() {
    let captured = Arc::new(Mutex::new(None));
    let store = fix_store::StoreWorker::spawn(CaptureLogonJournal {
        inner: test_redb(),
        wire: Arc::clone(&captured),
    });
    let (client, mut server) = duplex(8192);
    let _session = spawn_initiator_logged(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            reset_on_logon: false,
        },
        vec![
            Field::new(9001, Bytes::from_static(b"test-user")),
            Field::new(9002, Bytes::from_static(b"test-password")),
        ],
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
        SessionLogger::disabled(),
    );
    let mut bytes = vec![0_u8; 8192];
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("Logon timeout")
        .expect("read Logon");
    let mut decoder = FrameDecoder::new(8192);
    let frame = decoder.ingest(&bytes[..count]).expect("frame Logon");
    let sent = parse_frame(&frame[0]).expect("parse sent Logon");
    let journal = captured
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .expect("captured journal");
    let journal = parse_frame(&journal).expect("parse journaled Logon");

    assert_eq!(sent.values(9001).next(), Some(b"test-user".as_slice()));
    assert_eq!(sent.values(9002).next(), Some(b"test-password".as_slice()));
    assert_eq!(journal.values(9001).next(), Some(b"<redacted>".as_slice()));
    assert_eq!(journal.values(9002).next(), Some(b"<redacted>".as_slice()));
    assert!(
        !journal
            .fields
            .iter()
            .any(|field| field.value.as_ref() == b"test-password")
    );
}

fn test_redb() -> fix_store::RedbStore {
    fix_store::RedbStore::open_in_memory()
}
