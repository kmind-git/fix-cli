use fix_store::{
    CommandPhase, EventRecord, InboundCommit, MarkOutboundWritten, MarkTransmissionWritten,
    OutboundCommit, RedbStore, StoreOp, StorePort, StoreReply, StoreWorker, TransmissionCommit,
    TransmissionPhase,
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
    })
}

fn fresh_redb() -> RedbStore {
    RedbStore::open_in_memory()
}

fn test_database_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-data")
        .join(format!("{name}-{}.redb", std::process::id()))
}

#[test]
fn marking_a_socket_write_updates_the_persisted_command_phase() {
    let mut store = fresh_redb();
    store
        .apply(commit("agent-1", "fingerprint-a"))
        .expect("journal outbound");

    let reply = store
        .apply(StoreOp::MarkOutboundWritten(MarkOutboundWritten {
            request_id: "agent-1".to_owned(),
            msg_seq_num: 1,
        }))
        .expect("mark written");

    let StoreReply::Command(command) = reply else {
        panic!("mark written must return the command");
    };
    assert_eq!(command.phase, CommandPhase::Written);
}

#[test]
fn outbound_commit_atomically_advances_sequence_and_is_idempotent() {
    let mut store = fresh_redb();

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

    let lookup = store
        .apply(StoreOp::LoadCommand("agent-1".to_owned()))
        .expect("lookup command");
    assert!(matches!(
        lookup,
        StoreReply::StoredCommand(Some(ref command)) if command == &first_command
    ));
}

#[test]
fn resend_transmission_is_durably_journaled_before_it_is_marked_written() {
    let mut store = fresh_redb();
    let journaled = store
        .apply(StoreOp::CommitTransmission(TransmissionCommit {
            msg_seq_num: 7,
            kind: "application_replay".to_owned(),
            wire: b"replay-wire".to_vec(),
        }))
        .expect("journal transmission");
    let StoreReply::Transmission(journaled) = journaled else {
        panic!("transmission commit must return its record");
    };
    assert_eq!(journaled.phase, TransmissionPhase::Journaled);
    assert_eq!(journaled.wire, b"replay-wire");

    let written = store
        .apply(StoreOp::MarkTransmissionWritten(MarkTransmissionWritten {
            id: journaled.id,
        }))
        .expect("mark transmission written");
    let StoreReply::Transmission(written) = written else {
        panic!("mark transmission must return its record");
    };
    assert_eq!(written.phase, TransmissionPhase::Written);
}

#[test]
fn redb_store_recovers_the_same_sequence_and_idempotency_record_after_reopen() {
    let path = test_database_path("recovery");
    std::fs::create_dir_all(path.parent().expect("test database parent"))
        .expect("create test database parent");
    let _ = std::fs::remove_file(&path);

    {
        let mut store = RedbStore::open(&path).expect("create redb store");
        store
            .apply(commit("agent-1", "fingerprint-a"))
            .expect("persist outbound");
    }

    {
        let mut store = RedbStore::open(&path).expect("reopen redb store");
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
fn redb_reopens_a_journaled_resend_transmission() {
    let path = test_database_path("transmission-recovery");
    std::fs::create_dir_all(path.parent().expect("test database parent"))
        .expect("create test database parent");
    let _ = std::fs::remove_file(&path);
    let transmission_id = {
        let mut store = RedbStore::open(&path).expect("create redb store");
        let reply = store
            .apply(StoreOp::CommitTransmission(TransmissionCommit {
                msg_seq_num: 4,
                kind: "gap_fill".to_owned(),
                wire: b"gap-fill-wire".to_vec(),
            }))
            .expect("persist transmission");
        let StoreReply::Transmission(record) = reply else {
            panic!("expected transmission record");
        };
        record.id
    };

    {
        let mut store = RedbStore::open(&path).expect("reopen redb store");
        let reply = store
            .apply(StoreOp::LoadTransmission(transmission_id))
            .expect("load transmission");
        let StoreReply::StoredTransmission(Some(record)) = reply else {
            panic!("reopened transmission must exist");
        };
        assert_eq!(record.kind, "gap_fill");
        assert_eq!(record.phase, TransmissionPhase::Journaled);
        assert_eq!(record.wire, b"gap-fill-wire");
    }

    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn inbound_commit_advances_next_in_and_persists_the_agent_event() {
    let mut store = fresh_redb();

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
        }))
        .expect("commit inbound");

    let StoreReply::Inbound(record) = reply else {
        panic!("inbound commit must return its record");
    };
    assert_eq!(record.msg_seq_num, 1);
    assert_eq!(store.recover().expect("recover").next_in, 2);

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
    let handle = StoreWorker::spawn(fresh_redb());

    handle
        .apply(commit("agent-1", "fingerprint-a"))
        .await
        .expect("worker commit");
    let recovered = handle.recover().await.expect("worker recovery");

    assert_eq!(recovered.next_out, 2);
}

#[test]
fn sequence_reset_clears_journaled_traffic_and_restarts_counters() {
    let mut store = fresh_redb();
    store
        .apply(commit("agent-1", "fingerprint-a"))
        .expect("journal outbound");
    store
        .apply(StoreOp::CommitInbound(InboundCommit {
            msg_seq_num: 1,
            next_in_after: 2,
            msg_type: "8".to_owned(),
            wire: b"execution-report".to_vec(),
            event: EventRecord {
                id: 1,
                kind: "execution_report".to_owned(),
                details: BTreeMap::new(),
            },
        }))
        .expect("journal inbound");

    let reply = store.apply(StoreOp::ResetSequences).expect("reset");
    let StoreReply::SequencesReset(new_next_event) = reply else {
        panic!("reset must report the post-reset event counter");
    };

    let recovered = store.recover().expect("recover after reset");
    assert_eq!(recovered.next_out, 1);
    assert_eq!(recovered.next_in, 1);
    assert_eq!(recovered.next_event, 3);
    assert_eq!(new_next_event, recovered.next_event);
    let outbound = store
        .apply(StoreOp::LoadOutboundRange(fix_store::OutboundRange {
            begin: 1,
            end: 10,
        }))
        .expect("load outbound after reset");
    assert!(matches!(outbound, StoreReply::Outbound(records) if records.is_empty()));
    let inbound = store
        .apply(StoreOp::LoadInbound(1))
        .expect("load inbound after reset");
    assert!(matches!(inbound, StoreReply::StoredInbound(None)));
}

#[test]
fn redb_sequence_reset_survives_reopen() {
    let path = test_database_path("sequence-reset");
    std::fs::create_dir_all(path.parent().expect("test database parent"))
        .expect("create test database parent");
    let _ = std::fs::remove_file(&path);

    {
        let mut store = RedbStore::open(&path).expect("create redb store");
        store
            .apply(commit("agent-1", "fingerprint-a"))
            .expect("persist outbound");
        store.apply(StoreOp::ResetSequences).expect("persist reset");
    }

    {
        let mut store = RedbStore::open(&path).expect("reopen redb store");
        let recovered = store.recover().expect("recover redb state");
        assert_eq!(recovered.next_out, 1);
        assert_eq!(recovered.next_in, 1);
        let outbound = store
            .apply(StoreOp::LoadOutboundRange(fix_store::OutboundRange {
                begin: 1,
                end: 10,
            }))
            .expect("load outbound");
        assert!(matches!(outbound, StoreReply::Outbound(records) if records.is_empty()));
    }

    std::fs::remove_file(path).expect("remove test database");
}
