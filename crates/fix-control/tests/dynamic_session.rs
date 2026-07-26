use fix_control::{
    Command, CommandPlanner, ControlRequest, ControlService, ExecutionMode, Policy, RuntimeMode,
    SessionSlot,
};

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
