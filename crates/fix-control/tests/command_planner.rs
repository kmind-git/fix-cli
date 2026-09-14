use fix_control::{
    Command, CommandPlanner, ControlRequest, ExecutionMode, LiveAuth, NewOrderSingle, OrderType,
    PlannedCommand, Policy, RuntimeMode, Side, TimeInForce,
};
use rust_decimal::Decimal;
use std::str::FromStr;

#[test]
fn dry_run_new_order_is_policy_checked_and_mapped_to_a_d_message() {
    let planner = CommandPlanner::new(
        "broker-a-uat",
        RuntimeMode::Certification,
        Policy {
            max_quantity: Decimal::from(1_000),
            max_notional: Decimal::from_str("1000000").expect("decimal"),
            allow_market_orders: false,
            max_messages_per_second: 10,
        },
    );
    let request = ControlRequest {
        version: 1,
        request_id: "agent-order-1".to_owned(),
        profile: "broker-a-uat".to_owned(),
        execution_mode: ExecutionMode::DryRun,
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
    };

    let planned = planner.plan(&request).expect("valid order");

    let PlannedCommand::Application(application) = planned else {
        panic!("expected application message plan");
    };
    assert_eq!(application.msg_type, "D");
    assert_eq!(application.cl_ord_id, "FC-cfe328e87ac37454d37f2f40");
    assert_eq!(
        application
            .fields
            .iter()
            .find(|field| field.tag == 55)
            .expect("Symbol")
            .value,
        "IBM"
    );
    assert_eq!(
        application
            .fields
            .iter()
            .find(|field| field.tag == 44)
            .expect("Price")
            .value,
        "187.25"
    );
}

#[test]
fn certification_runtime_rejects_live_execution() {
    let planner = CommandPlanner::new(
        "broker-a-uat",
        RuntimeMode::Certification,
        Policy::deny_all(),
    );
    let request = ControlRequest {
        version: 1,
        request_id: "status-1".to_owned(),
        profile: "broker-a-uat".to_owned(),
        execution_mode: ExecutionMode::Live,
        command: Command::SessionStatus,
        auth: None,
    };

    let error = planner.plan(&request).expect_err("live must fail closed");

    assert_eq!(error.code(), "LIVE_GUARD_NOT_ARMED");
}

#[test]
fn live_runtime_still_rejects_unimplemented_capability_proofs() {
    let planner = CommandPlanner::new("broker-a-live", RuntimeMode::Live, Policy::deny_all());
    let request = ControlRequest {
        version: 1,
        request_id: "status-live-1".to_owned(),
        profile: "broker-a-live".to_owned(),
        execution_mode: ExecutionMode::Live,
        command: Command::SessionStatus,
        auth: Some(LiveAuth {
            key_id: "operator-key".to_owned(),
            unix_ms: 1,
            nonce: "nonce".to_owned(),
            mac_hex: "00".repeat(32),
        }),
    };

    let error = planner
        .plan(&request)
        .expect_err("unverified live capability must fail closed");

    assert_eq!(error.code(), "LIVE_GUARD_NOT_ARMED");
}

#[test]
fn priceless_market_orders_are_accepted_and_omit_price() {
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
    let request = ControlRequest {
        version: 1,
        request_id: "market-1".to_owned(),
        profile: "broker-a-uat".to_owned(),
        execution_mode: ExecutionMode::Certification,
        command: Command::NewOrderSingle(NewOrderSingle {
            symbol: "IBM".to_owned(),
            account: "110853".to_owned(),
            security_exchange: "XSGE".to_owned(),
            security_group: "FUT".to_owned(),
            side: Side::Buy,
            quantity: "10".to_owned(),
            order_type: OrderType::Market,
            price: None,
            time_in_force: TimeInForce::Day,
            maturity_month_year: None,
            extra_tags: Vec::new(),
        }),
        auth: None,
    };

    let planned = planner
        .plan(&request)
        .expect("priceless market order plans");

    let PlannedCommand::Application(application) = planned else {
        panic!("market order must plan to an application command");
    };
    assert!(!application.fields.iter().any(|field| field.tag == 44));
}

#[test]
fn dry_run_logout_cannot_mutate_the_session() {
    let planner = CommandPlanner::new(
        "broker-a-uat",
        RuntimeMode::Certification,
        Policy::deny_all(),
    );
    let request = ControlRequest {
        version: 1,
        request_id: "logout-dry-run".to_owned(),
        profile: "broker-a-uat".to_owned(),
        execution_mode: ExecutionMode::DryRun,
        command: Command::SessionLogout,
        auth: None,
    };

    let error = planner
        .plan(&request)
        .expect_err("dry-run must never send Logout");

    assert_eq!(error.code(), "INVALID_REQUEST");
}
