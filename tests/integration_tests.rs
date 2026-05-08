use s_udp::{Engine, Event};
use std::net::SocketAddr;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn test_full_handshake_and_data_exchange() {
    let server_engine = Engine::new();
    let client_engine = Engine::new();

    let server_addr = "127.0.0.1:6000";
    let client_token = "client_secret_123".to_string();
    let server_token = "server_secret_456".to_string();

    // 1. Start Server
    let mut server_rx = server_engine
        .listen(server_addr, client_token.clone(), server_token.clone())
        .await
        .expect("Server failed to listen");

    // 2. Start Client
    let mut client_rx = client_engine
        .connect(server_addr, 0, client_token, server_token)
        .await
        .expect("Client failed to connect");

    // 3. Verify Connection on both ends
    let client_connected = timeout(Duration::from_secs(2), client_rx.recv()).await;
    let server_connected = timeout(Duration::from_secs(2), server_rx.recv()).await;

    assert!(
        matches!(client_connected, Ok(Some(Event::Connected))),
        "Client did not receive Connected event"
    );
    assert!(
        matches!(server_connected, Ok(Some(Event::Connected))),
        "Server did not receive Connected event"
    );

    // 4. Exchange Data
    let test_data = vec![0u8; 5000]; // Multi-window payload
    let target: SocketAddr = server_addr.parse().unwrap();

    let client_engine_c = client_engine.clone();
    let send_handle = tokio::spawn(async move { client_engine_c.send(target, &test_data).await });

    let server_event = timeout(Duration::from_secs(5), server_rx.recv()).await;

    if let Ok(Some(Event::Data(report))) = server_event {
        assert_eq!(report.total_bytes, 5000);
        assert!(report.windows_used >= 1);
        println!("Integration: Received 5000 bytes correctly");
    } else {
        panic!(
            "Server failed to receive expected data. Got: {:?}",
            server_event
        );
    }

    send_handle
        .await
        .expect("Send task failed")
        .expect("Send operation failed");

    // 5. Graceful Disconnect
    client_engine
        .disconnect(target, "Test finished")
        .await
        .expect("Disconnect failed");

    let disconnect_event = timeout(Duration::from_secs(2), server_rx.recv()).await;
    assert!(
        matches!(disconnect_event, Ok(Some(Event::Disconnected(_)))),
        "Server did not receive Disconnect event"
    );
}

#[tokio::test]
async fn test_invalid_token_rejected() {
    let server_engine = Engine::new();
    let client_engine = Engine::new();

    let server_addr = "127.0.0.1:6001";

    // Server expects "A", Client sends "B"
    let _server_rx = server_engine
        .listen(server_addr, "SECRET_A".into(), "SERVER_PASS".into())
        .await
        .expect("Server listen failed");

    let connection_result = timeout(
        Duration::from_secs(2),
        client_engine.connect(server_addr, 0, "SECRET_B".into(), "SERVER_PASS".into()),
    )
    .await;

    assert!(
        connection_result.is_err() || connection_result.unwrap().is_err(),
        "Client should have failed to connect with wrong token"
    );
}
