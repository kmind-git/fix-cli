use fix_ipc::{
    LocalListener, connect_local, endpoint_for_profile, read_json_frame, write_json_frame,
};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, timeout};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Message {
    request_id: String,
    command: String,
}

#[tokio::test]
async fn local_transport_round_trips_a_framed_request_and_response() {
    let profile = format!("test-{}", std::process::id());
    let endpoint = endpoint_for_profile(&profile);
    let mut listener = LocalListener::bind(&endpoint).expect("bind local transport");
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("accept local client");
        let request: Message = read_json_frame(&mut stream, 4_096)
            .await
            .expect("read request");
        write_json_frame(&mut stream, &request, 4_096)
            .await
            .expect("write response");
    });

    let mut client = timeout(Duration::from_secs(2), connect_local(&endpoint))
        .await
        .expect("connect timeout")
        .expect("connect local transport");
    let expected = Message {
        request_id: "ipc-e2e-1".to_owned(),
        command: "session_status".to_owned(),
    };
    write_json_frame(&mut client, &expected, 4_096)
        .await
        .expect("write request");
    let response: Message = read_json_frame(&mut client, 4_096)
        .await
        .expect("read response");

    assert_eq!(response, expected);
    server.await.expect("server task");
}
