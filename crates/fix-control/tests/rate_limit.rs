use bytes::Bytes;
use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, NewOrderSingle,
    OrderType, Policy, RuntimeMode, Side, TimeInForce,
};
use fix_protocol::{Field, encode_message};
use fix_session::{SessionConfig, SessionPhase, StaticTimeSource, spawn_initiator};
use fix_store::{
    MemoryStore, RecoveryState, StoreError, StoreOp, StorePort, StoreReply, StoreWorker,
};
use rust_decimal::Decimal;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, sleep, timeout};

#[tokio::test]
async fn certification_orders_are_rejected_when_the_policy_rate_is_exhausted() {
    let (client, mut server) = duplex(16 * 1024);
    let application_commits = Arc::new(AtomicUsize::new(0));
    let session = spawn_initiator(
        client,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            default_appl_ver_id: None,
        },
        StoreWorker::spawn(CountApplicationCommits {
            inner: MemoryStore::new(b"rate-limit-audit-key"),
            commits: Arc::clone(&application_commits),
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
    let service = ControlService::new(planner(), session);

    let (first, concurrent_retry) = tokio::join!(
        service.execute(order("rate-order-1")),
        service.execute(order("rate-order-1"))
    );
    let second = service.execute(order("rate-order-2")).await;

    assert!(first.ok, "{first:?}");
    assert!(concurrent_retry.ok, "{concurrent_retry:?}");
    assert_eq!(
        application_commits.load(Ordering::SeqCst),
        1,
        "concurrent duplicate request reached SessionActor submit more than once"
    );
    assert_eq!(
        first
            .result
            .as_ref()
            .and_then(|value| value["msg_seq_num"].as_u64()),
        concurrent_retry
            .result
            .as_ref()
            .and_then(|value| value["msg_seq_num"].as_u64())
    );
    assert_eq!(
        second.error.as_ref().map(|error| error.code.as_str()),
        Some("RATE_LIMITED")
    );
    assert_eq!(second.exit_code(), 8);

    sleep(Duration::from_millis(1_050)).await;
    let idempotent_retry = service.execute(order("rate-order-1")).await;
    let next_new_command = service.execute(order("rate-order-2")).await;
    let third = service.execute(order("rate-order-3")).await;

    assert!(idempotent_retry.ok, "{idempotent_retry:?}");
    assert!(
        next_new_command.ok,
        "persistent idempotent lookup must happen before rate acquisition: {next_new_command:?}"
    );
    assert_eq!(
        third.error.as_ref().map(|error| error.code.as_str()),
        Some("RATE_LIMITED")
    );
}

#[tokio::test]
async fn a_not_established_submit_releases_its_rate_reservation() {
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
        StoreWorker::spawn(MemoryStore::new(b"rate-refund-audit-key")),
        Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
    );
    let mut bytes = vec![0_u8; 16 * 1024];
    timeout(Duration::from_secs(1), server.read(&mut bytes))
        .await
        .expect("outbound Logon timeout")
        .expect("read outbound Logon");
    let service = ControlService::new(planner(), session.clone());

    let rejected = service.execute(order("pre-logon-order")).await;

    assert_eq!(
        rejected.error.as_ref().map(|error| error.code.as_str()),
        Some("SESSION_NOT_ESTABLISHED")
    );

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

    let accepted = service.execute(order("post-logon-order")).await;
    let limited = service.execute(order("next-order")).await;

    assert!(
        accepted.ok,
        "failed pre-Logon submission leaked its reservation: {accepted:?}"
    );
    assert_eq!(
        limited.error.as_ref().map(|error| error.code.as_str()),
        Some("RATE_LIMITED")
    );
}

fn planner() -> CommandPlanner {
    CommandPlanner::new(
        "rate-test",
        RuntimeMode::Certification,
        Policy {
            allowed_symbols: BTreeSet::from(["IBM".to_owned()]),
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from(1_000_000),
            allow_market_orders: false,
            max_messages_per_second: 1,
        },
    )
}

struct CountApplicationCommits {
    inner: MemoryStore,
    commits: Arc<AtomicUsize>,
}

impl StorePort for CountApplicationCommits {
    fn recover(&mut self) -> Result<RecoveryState, StoreError> {
        self.inner.recover()
    }

    fn apply(&mut self, operation: StoreOp) -> Result<StoreReply, StoreError> {
        if matches!(
            &operation,
            StoreOp::CommitOutbound(commit) if !commit.cl_ord_id.is_empty()
        ) {
            self.commits.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.apply(operation)
    }
}

fn order(request_id: &str) -> ControlRequest {
    ControlRequest {
        version: 1,
        request_id: request_id.to_owned(),
        profile: "rate-test".to_owned(),
        execution_mode: ExecutionMode::Certification,
        command: Command::NewOrderSingle(NewOrderSingle {
            symbol: "IBM".to_owned(),
            side: Side::Buy,
            quantity: "10".to_owned(),
            order_type: OrderType::Limit,
            price: Some("100".to_owned()),
            time_in_force: TimeInForce::Day,
        }),
        auth: None,
    }
}
