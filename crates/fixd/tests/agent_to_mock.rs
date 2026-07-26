use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, NewOrderSingle,
    OrderType, Policy, RuntimeMode, Side, TimeInForce,
};
use fix_mock::{MockConfig, run_mock_session};
use fix_protocol::{CompiledDictionary, MemberDefinition, MessageDefinition};
use fix_session::{SessionConfig, SessionPhase, StaticTimeSource, spawn_initiator_with_dictionary};
use fix_store::{MemoryStore, StoreWorker};
use rust_decimal::Decimal;
use std::collections::BTreeSet;
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
    let dictionary = Arc::new(test_dictionary());
    let store = StoreWorker::spawn(MemoryStore::new(b"integration-audit-key"));
    let session = spawn_initiator_with_dictionary(
        stream,
        SessionConfig {
            begin_string: "FIX.4.4".to_owned(),
            sender_comp_id: "CLIENT".to_owned(),
            target_comp_id: "SERVER".to_owned(),
            heartbeat_interval_secs: 30,
            default_appl_ver_id: None,
        },
        dictionary,
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
            allowed_symbols: BTreeSet::from(["IBM".to_owned()]),
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from(1_000_000),
            allow_market_orders: false,
            max_messages_per_second: 10,
        },
    );
    let service = ControlService::new(planner, session.clone());
    let response = service
        .execute(ControlRequest {
            version: 1,
            request_id: "agent-e2e-order-1".to_owned(),
            profile: "broker-a-uat".to_owned(),
            execution_mode: ExecutionMode::Certification,
            command: Command::NewOrderSingle(NewOrderSingle {
                symbol: "IBM".to_owned(),
                side: Side::Buy,
                quantity: "100".to_owned(),
                order_type: OrderType::Limit,
                price: Some("187.25".to_owned()),
                time_in_force: TimeInForce::Day,
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

fn test_dictionary() -> CompiledDictionary {
    let header = || {
        vec![
            MemberDefinition::field(49, true),
            MemberDefinition::field(56, true),
            MemberDefinition::field(34, true),
            MemberDefinition::field(52, true),
        ]
    };
    let mut logon = header();
    logon.extend([
        MemberDefinition::field(98, true),
        MemberDefinition::field(108, true),
    ]);
    let mut order = header();
    order.extend([
        MemberDefinition::field(11, true),
        MemberDefinition::field(21, true),
        MemberDefinition::field(55, true),
        MemberDefinition::field(54, true),
        MemberDefinition::field(60, true),
        MemberDefinition::field(38, true),
        MemberDefinition::field(40, true),
        MemberDefinition::field(44, false),
        MemberDefinition::field(59, true),
    ]);
    let mut execution_report = header();
    execution_report.extend([
        MemberDefinition::field(37, true),
        MemberDefinition::field(17, true),
        MemberDefinition::field(150, true),
        MemberDefinition::field(39, true),
        MemberDefinition::field(11, true),
        MemberDefinition::field(41, false),
        MemberDefinition::field(55, true),
        MemberDefinition::field(54, true),
        MemberDefinition::field(151, true),
        MemberDefinition::field(14, true),
        MemberDefinition::field(6, true),
    ]);

    CompiledDictionary::new("FIX.4.4")
        .with_message(MessageDefinition {
            name: "Logon".to_owned(),
            msg_type: "A".to_owned(),
            members: logon,
        })
        .with_message(MessageDefinition {
            name: "NewOrderSingle".to_owned(),
            msg_type: "D".to_owned(),
            members: order,
        })
        .with_message(MessageDefinition {
            name: "ExecutionReport".to_owned(),
            msg_type: "8".to_owned(),
            members: execution_report,
        })
}
