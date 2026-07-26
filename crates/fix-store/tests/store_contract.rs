use fix_store::{
    AuditEvent, CommandPhase, EventRecord, InboundCommit, MarkOutboundWritten, MemoryStore,
    OutboundCommit, RedbStore, StoreOp, StorePort, StoreReply, StoreWorker,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn commit(request_id: &str, fingerprint: &str) -> StoreOp {
    StoreOp::CommitOutbound(OutboundCommit {
        request_id: request_id.to_owned(),
        fingerprint: fingerprint.to_owned(),
        cl_ord_id: "FC-0001".to_owned(),
        msg_seq_num: 1,
        wire: b"8=FIX.4.4\x019=5\x0135=0\x0110=163\x01".to_vec(),
        audit: AuditEvent {
            kind: "outbound_journaled".to_owned(),
            details: BTreeMap::from([("request_id".to_owned(), request_id.to_owned())]),
        },
    })
}

fn audit(kind: &str) -> AuditEvent {
    AuditEvent {
        kind: kind.to_owned(),
        details: BTreeMap::new(),
    }
}

fn test_database_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-data")
        .join(format!("{name}-{}.redb", std::process::id()))
}

#[test]
fn marking_a_socket_write_updates_the_persisted_command_phase() {
    let mut store = MemoryStore::new(b"audit-test-key");
    store
        .apply(commit("agent-1", "fingerprint-a"))
        .expect("journal outbound");

    let reply = store
        .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
            request_id: "agent-1".to_owned(),
            msg_seq_num: 1,
            audit: audit("outbound_written"),
        }))
        .expect("mark written");

    let StoreReply::Command(command) = reply else {
        panic!("mark written must return the command");
    };
    assert_eq!(command.phase, CommandPhase::Written);
    assert_eq!(store.audit_records().len(), 2);
}

#[test]
fn outbound_commit_atomically_advances_sequence_and_is_idempotent() {
    let mut store = MemoryStore::new(b"audit-test-key");

    let first = store
        .apply(commit("agent-1", "fingerprint-a"))
        .expect("first commit");
    let recovered = store.recover().expect("recover state");
    let retry = store
        .apply(commit("agent-1", "fingerprint-a"))
        .expect("idempotent retry");

    let StoreReply::Command(first_command) = first else {
        panic!("commit must return its command record");
    };
    let StoreReply::Command(retry_command) = retry else {
        panic!("retry must return the original command record");
    };

    assert_eq!(recovered.next_out, 2);
    assert_eq!(first_command, retry_command);
    assert_eq!(first_command.phase, CommandPhase::Journaled);
    assert_eq!(store.audit_records().len(), 1);
}

#[test]
fn redb_store_recovers_the_same_sequence_and_idempotency_record_after_reopen() {
    let path = test_database_path("recovery");
    std::fs::create_dir_all(path.parent().expect("test database parent"))
        .expect("create test database parent");
    let _ = std::fs::remove_file(&path);

    {
        let mut store = RedbStore::open(&path, b"audit-test-key").expect("create redb store");
        store
            .apply(commit("agent-1", "fingerprint-a"))
            .expect("persist outbound");
    }

    {
        let mut store = RedbStore::open(&path, b"audit-test-key").expect("reopen redb store");
        let recovered = store.recover().expect("recover redb state");
        let retry = store
            .apply(commit("agent-1", "fingerprint-a"))
            .expect("recover idempotent result");

        assert_eq!(recovered.next_out, 2);
        let StoreReply::Command(command) = retry else {
            panic!("retry must return the persisted command");
        };
        assert_eq!(command.cl_ord_id, "FC-0001");
    }

    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn redb_store_rejects_an_audit_chain_opened_with_the_wrong_key() {
    let path = test_database_path("audit-key-mismatch");
    std::fs::create_dir_all(path.parent().expect("test database parent"))
        .expect("create test database parent");
    let _ = std::fs::remove_file(&path);
    {
        let mut store = RedbStore::open(&path, b"first-audit-key").expect("create redb store");
        store
            .apply(commit("agent-1", "fingerprint-a"))
            .expect("persist audited record");
    }

    let error = match RedbStore::open(&path, b"different-audit-key") {
        Ok(_) => panic!("wrong audit key must fail chain verification"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        fix_store::StoreError::AuditChainInvalid { .. }
    ));
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn inbound_commit_advances_next_in_and_persists_the_agent_event() {
    let mut store = MemoryStore::new(b"audit-test-key");

    let reply = store
        .apply(StoreOp::CommitInbound(InboundCommit {
            msg_seq_num: 1,
            next_in_after: 2,
            msg_type: "8".to_owned(),
            wire: b"execution-report".to_vec(),
            event: EventRecord {
                id: 1,
                kind: "execution_report".to_owned(),
                details: BTreeMap::from([("ord_status".to_owned(), "new".to_owned())]),
            },
            audit: audit("inbound_committed"),
        }))
        .expect("commit inbound");

    let StoreReply::Inbound(record) = reply else {
        panic!("inbound commit must return its record");
    };
    assert_eq!(record.msg_seq_num, 1);
    assert_eq!(store.recover().expect("recover").next_in, 2);
    assert_eq!(store.events()[0].kind, "execution_report");

    let loaded = store
        .apply(StoreOp::LoadInbound(1))
        .expect("load committed inbound");
    let StoreReply::StoredInbound(Some(loaded)) = loaded else {
        panic!("stored inbound lookup must return its record");
    };
    assert_eq!(loaded.wire, b"execution-report");
}

#[tokio::test]
async fn store_worker_exposes_the_same_contract_without_blocking_the_runtime() {
    let store = MemoryStore::new(b"audit-test-key");
    let handle = StoreWorker::spawn(store);

    handle
        .apply(commit("agent-1", "fingerprint-a"))
        .await
        .expect("worker commit");
    let recovered = handle.recover().await.expect("worker recovery");

    assert_eq!(recovered.next_out, 2);
}
