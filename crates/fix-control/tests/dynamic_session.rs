use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, NewOrderSingle,
    OrderType, PlannedCommand, Policy, RuntimeMode, SessionSlot, Side, TimeInForce,
};
use fix_store::{AuditEvent, MemoryStore, OutboundCommit, StoreOp, StoreWorker};
use rust_decimal::Decimal;
use std::collections::{BTreeMap, BTreeSet};

#[tokio::test]
async fn dynamic_control_service_reports_disconnected_while_reconnect_is_pending() {
    let planner = CommandPlanner::new(
        "reconnect-test",
        RuntimeMode::Certification,
        Policy::deny_all(),
    );
    let service = ControlService::new_dynamic(planner, SessionSlot::new());

    let response = service
        .execute(ControlRequest {
            version: 1,
            request_id: "status-reconnect-1".to_owned(),
            profile: "reconnect-test".to_owned(),
            execution_mode: ExecutionMode::Inspect,
            command: Command::SessionStatus,
            auth: None,
        })
        .await;

    assert!(response.ok, "{response:?}");
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|value| value["phase"].as_str()),
        Some("disconnected")
    );
}

#[tokio::test]
async fn persisted_idempotency_is_available_while_the_session_slot_is_disconnected() {
    let planner = CommandPlanner::new(
        "reconnect-test",
        RuntimeMode::Certification,
        Policy {
            allowed_symbols: BTreeSet::from(["IBM".to_owned()]),
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from(1_000_000),
            allow_market_orders: false,
            max_messages_per_second: 1,
        },
    );
    let request = order("persistent-order-1", "100");
    let PlannedCommand::Application(application) =
        planner.plan(&request).expect("valid application plan")
    else {
        panic!("expected application command");
    };
    let store = StoreWorker::spawn(MemoryStore::new(b"control-store-audit-key"));
    store
        .apply(StoreOp::CommitOutbound(OutboundCommit {
            request_id: application.request_id,
            fingerprint: application.fingerprint,
            cl_ord_id: application.cl_ord_id,
            msg_seq_num: 1,
            wire: b"persisted-wire".to_vec(),
            audit: AuditEvent {
                kind: "application_journaled".to_owned(),
                details: BTreeMap::new(),
            },
        }))
        .await
        .expect("persist command");
    let service = ControlService::new_dynamic_with_store(planner, SessionSlot::new(), store);

    let retry = service.execute(request).await;
    let conflict = service.execute(order("persistent-order-1", "101")).await;

    assert!(retry.ok, "{retry:?}");
    assert_eq!(
        retry
            .result
            .as_ref()
            .and_then(|value| value["phase"].as_str()),
        Some("journaled")
    );
    assert_eq!(
        conflict.error.as_ref().map(|error| error.code.as_str()),
        Some("IDEMPOTENCY_CONFLICT")
    );
}

fn order(request_id: &str, price: &str) -> ControlRequest {
    ControlRequest {
        version: 1,
        request_id: request_id.to_owned(),
        profile: "reconnect-test".to_owned(),
        execution_mode: ExecutionMode::Certification,
        command: Command::NewOrderSingle(NewOrderSingle {
            symbol: "IBM".to_owned(),
            side: Side::Buy,
            quantity: "10".to_owned(),
            order_type: OrderType::Limit,
            price: Some(price.to_owned()),
            time_in_force: TimeInForce::Day,
        }),
        auth: None,
    }
}
