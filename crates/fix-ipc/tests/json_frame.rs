use fix_ipc::{read_json_frame, write_json_frame};
use serde::{Deserialize, Serialize};
use tokio::io::duplex;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Message {
    request_id: String,
    command: String,
}

#[tokio::test]
async fn json_frame_round_trips_over_a_fragmentable_stream() {
    let (mut client, mut server) = duplex(64);
    let expected = Message {
        request_id: "agent-1".to_owned(),
        command: "session_status".to_owned(),
    };

    let send = tokio::spawn(async move {
        write_json_frame(&mut client, &expected, 1024)
            .await
            .expect("write JSON frame");
        expected
    });
    let received: Message = read_json_frame(&mut server, 1024)
        .await
        .expect("read JSON frame");

    assert_eq!(received, send.await.expect("writer task"));
}
