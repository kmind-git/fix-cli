use bytes::Bytes;
use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, NewOrderSingle,
    OrderType, Policy, RuntimeMode, Side, TimeInForce,
};
use fix_protocol::{Field, encode_message};
use fix_session::{SessionConfig, SessionPhase, StaticTimeSource, spawn_initiator};
use fix_store::{MemoryStore, StoreWorker};
use rust_decimal::Decimal;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn certification_orders_are_rejected_when_the_policy_rate_is_exhausted() {
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
        StoreWorker::spawn(MemoryStore::new(b"rate-limit-audit-key")),
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
    let planner = CommandPlanner::new(
        "rate-test",
        RuntimeMode::Certification,
        Policy {
            allowed_symbols: BTreeSet::from(["IBM".to_owned()]),
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from(1_000_000),
            allow_market_orders: false,
            max_messages_per_second: 1,
        },
    );
    let service = ControlService::new(planner, session);

    let first = service.execute(order("rate-order-1")).await;
    let second = service.execute(order("rate-order-2")).await;

    assert!(first.ok, "{first:?}");
    assert_eq!(
        second.error.as_ref().map(|error| error.code.as_str()),
        Some("RATE_LIMITED")
    );
    assert_eq!(second.exit_code(), 8);
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
