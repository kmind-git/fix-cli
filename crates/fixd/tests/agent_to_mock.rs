use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, NewOrderSingle,
    OrderType, Policy, RuntimeMode, SessionSlot, Side, TimeInForce,
};
use fix_mock::{MockConfig, run_mock_session};
use fix_session::{SessionConfig, SessionPhase, StaticTimeSource, spawn_initiator};
use rust_decimal::Decimal;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn agent_control_request_reaches_mock_venue_and_receives_execution_report() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock venue");
    let address = listener.local_addr().expect("mock address");
    let mock = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept FIX initiator");
        run_mock_session(
            stream,
            MockConfig {
                begin_string: "FIX.4.4".to_owned(),
                sender_comp_id: "SERVER".to_owned(),
                target_comp_id: "CLIENT".to_owned(),
                heartbeat_interval_secs: 30,
            },
            Arc::new(StaticTimeSource::new("20260726-15:00:00.000")),
        )
        .await
        .expect("mock session");
    });
    let stream = TcpStream::connect(address)
        .await
        .expect("connect mock venue");
    let store = test_store();
    let session = spawn_initiator(
        stream,
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
    timeout(Duration::from_secs(2), async {
        loop {
            if session.status().await.expect("session status").phase == SessionPhase::Established {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Logon handshake timeout");

    let planner = CommandPlanner::new(
        "broker-a-uat",
        RuntimeMode::Certification,
        Policy {
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from(1_000_000),
            allow_market_orders: false,
            max_messages_per_second: 10,
        },
    );
    let service = ControlService::new_dynamic(planner, SessionSlot::with_session(session.clone()));
    let response = service
        .execute(ControlRequest {
            version: 1,
            request_id: "agent-e2e-order-1".to_owned(),
            profile: "broker-a-uat".to_owned(),
            execution_mode: ExecutionMode::Certification,
            command: Command::NewOrderSingle(NewOrderSingle {
                symbol: "IBM".to_owned(),
                account: "110853".to_owned(),
                security_exchange: "XSGE".to_owned(),
                security_group: "FUT".to_owned(),
                side: Side::Buy,
                quantity: "100".to_owned(),
                order_type: OrderType::Limit,
                price: Some("187.25".to_owned()),
                time_in_force: TimeInForce::Day,
                maturity_month_year: None,
                extra_tags: Vec::new(),
            }),
            auth: None,
        })
        .await;

    assert!(response.ok, "{response:?}");
    assert_eq!(
        response
            .result
            .as_ref()
            .and_then(|value| value["phase"].as_str()),
        Some("written_to_socket")
    );
    timeout(Duration::from_secs(2), async {
        loop {
            if session.status().await.expect("session status").next_in == 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ExecutionReport commit timeout");

    drop(service);
    drop(session);
    timeout(Duration::from_secs(2), mock)
        .await
        .expect("mock shutdown timeout")
        .expect("mock task");
}

fn test_store() -> fix_store::StoreHandle {
    fix_store::StoreWorker::spawn(test_redb())
}

fn test_redb() -> fix_store::RedbStore {
    fix_store::RedbStore::open_in_memory()
}
