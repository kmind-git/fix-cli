use bytes::Bytes;
use fix_protocol::{
    CompiledDictionary, Field, FrameDecoder, MemberDefinition, MessageDefinition, ParseDictionary,
    parse_frame,
};
use fix_session::{
    SessionConfig, StaticTimeSource, spawn_initiator_with_dictionary_and_logon_fields,
};
use fix_store::{
    MemoryStore, RecoveryState, StoreError, StoreOp, StorePort, StoreReply, StoreWorker,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, duplex};
use tokio::time::{Duration, timeout};

struct CaptureLogonJournal {
    inner: MemoryStore,
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
    let store = StoreWorker::spawn(CaptureLogonJournal {
        inner: MemoryStore::new(b"credential-audit-key"),
        wire: Arc::clone(&captured),
    });
    let (client, mut server) = duplex(8192);
    let mut dictionary = CompiledDictionary::new("FIX.4.4").with_message(MessageDefinition {
        name: "Logon".to_owned(),
        msg_type: "A".to_owned(),
        members: vec![
            MemberDefinition::field(49, true),
            MemberDefinition::field(56, true),
            MemberDefinition::field(34, true),
            MemberDefinition::field(52, true),
            MemberDefinition::field(98, true),
            MemberDefinition::field(108, true),
            MemberDefinition::field(553, true),
            MemberDefinition::field(554, true),
        ],
    });
    dictionary.sensitive_tags.extend([553, 554]);
    let _session = spawn_initiator_with_dictionary_and_logon_fields(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            default_appl_ver_id: None,
        },
        Arc::new(dictionary),
        vec![
            Field::new(553, Bytes::from_static(b"test-user")),
            Field::new(554, Bytes::from_static(b"test-password")),
        ],
        store,
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 8192];
    let count = timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("Logon timeout")
        .expect("read Logon");
    let mut decoder = FrameDecoder::new(8192);
    let frame = decoder.ingest(&bytes[..count]).expect("frame Logon");
    let sent = parse_frame(&frame[0], &ParseDictionary::new()).expect("parse sent Logon");
    let journal = captured
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .expect("captured journal");
    let journal = parse_frame(&journal, &ParseDictionary::new()).expect("parse journaled Logon");

    assert_eq!(sent.values(553).next(), Some(b"test-user".as_slice()));
    assert_eq!(sent.values(554).next(), Some(b"test-password".as_slice()));
    assert_eq!(journal.values(553).next(), Some(b"<redacted>".as_slice()));
    assert_eq!(journal.values(554).next(), Some(b"<redacted>".as_slice()));
    assert!(
        !journal
            .fields
            .iter()
            .any(|field| field.value.as_ref() == b"test-password")
    );
}
