use anyhow::Result;
use s_udp::{Engine, Event, LogCategory};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_full_protocol_refactor_verification() -> Result<()> {
    let server_engine = Engine::new();
    let client_engine = Engine::new();
    let mut log_rx = server_engine.enable_logging();

    // 1. Setup Server on 6001
    let mut server_rx = server_engine.listen("127.0.0.1:6001", "C".into(), "S".into()).await?;

    // 2. Setup Client and Connect
    let mut client_rx = client_engine.connect("127.0.0.1:6001", 0, "C".into(), "S".into()).await?;

    // Verify Handshake
    timeout(Duration::from_secs(2), client_rx.recv()).await?.unwrap();
    timeout(Duration::from_secs(2), server_rx.recv()).await?.unwrap();

    // 3. Send 100 packets (Adaptive Bitmask & Unique Nonce Test)
    let chunk_size = 1375;
    let total_packets = 100;
    let data = vec![0xAAu8; total_packets * chunk_size];

    let target: std::net::SocketAddr = "127.0.0.1:6001".parse().unwrap();
    client_engine.send_data(target, &data, None).await?;

    // 4. Verify Data Reassembly First
    let event = timeout(Duration::from_secs(5), server_rx.recv()).await?.unwrap();
    if let Event::Data(report) = event {
        assert_eq!(report.total_chunks, 100);
        assert_eq!(report.windows_used, 1);
    } else {
        panic!("Expected Data event, got {:?}", event);
    }

    // 5. Verify ACK log
    let mut found_ack = false;
    while let Ok(Some(entry)) = timeout(Duration::from_millis(500), log_rx.recv()).await {
        if entry.category == LogCategory::Ack && entry.message.contains("Full ACK sent") {
            assert!(entry.message.contains("seq=8000000000002001"));
            found_ack = true;
            break;
        }
    }
    assert!(found_ack);

    Ok(())
}

#[tokio::test]
async fn test_sequential_ack_nonce_increment() -> Result<()> {
    let server_engine = Engine::new();
    let client_engine = Engine::new();
    let mut log_rx = server_engine.enable_logging();

    server_engine.listen("127.0.0.1:6003", "C".into(), "S".into()).await?;
    client_engine.connect("127.0.0.1:6003", 0, "C".into(), "S".into()).await?;
    let target: std::net::SocketAddr = "127.0.0.1:6003".parse().unwrap();

    // 1. Send first part
    let data1 = vec![0x11u8; 1375]; // 1 packet
    client_engine.send_data(target, &data1, None).await?;

    // 2. Send second part (Trigger second ACK)
    let data2 = vec![0x22u8; 1375]; // 1 packet
    client_engine.send_data(target, &data2, None).await?;

    let mut acks = Vec::new();
    while let Ok(Some(entry)) = timeout(Duration::from_secs(2), log_rx.recv()).await {
        if entry.category == LogCategory::Ack && entry.message.contains("Full ACK sent") {
            acks.push(entry.message);
        }
    }

    // We expect at least 2 ACKs for window 1.
    // The first should be ...2001 (counter 0)
    // The second should be ...2005 (counter 1 -> 1 << 2 = 4, so 0x2000 | 4 | 1 = 0x2005)
    assert!(acks.iter().any(|m| m.contains("seq=8000000000002001")), "First ACK should have counter 0");
    // Note: It might send more ACKs depending on timing, but we check for the incremented one
    assert!(acks.iter().any(|m| m.contains("seq=8000000000002005")), "Subsequent ACK for same window must have counter 1 (0x2005)");

    Ok(())
}
