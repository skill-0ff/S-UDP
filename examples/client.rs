use anyhow::Result;
use s_udp::{Engine, Event};
use std::net::SocketAddr;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // 🚀 Initialize the S-UDP Engine
    let engine = Engine::new();

    // Enable logging
    let mut logs = engine.enable_logging();
    tokio::spawn(async move {
        while let Some(log) = logs.recv().await {
            println!("{}", log);
        }
    });

    let target_addr: SocketAddr = "127.0.0.1:5001".parse()?;
    println!("Connecting to S-UDP Server at {}...", target_addr);

    // 🤝 Initiate Authenticated Handshake
    // Arguments: server_addr, local_port (0 for auto), our_token, expected_server_token
    let mut rx = engine
        .connect(
            "127.0.0.1:5001",
            0,
            "CLIENT_SECRET".into(),
            "SERVER_SECRET".into(),
        )
        .await?;

    // Wait for connection confirmation
    if let Some(Event::Connected) = rx.recv().await {
        println!("\n\r[✅] Connection established and secured!");

        // 📤 Send a test payload
        let message =
            "Hello S-UDP! This is a reliable, encrypted message sent over the custom protocol.";
        println!("\n\r[📤] Sending data ({} bytes)...", message.len());

        let report = engine
            .send_data(target_addr, message.as_bytes(), None)
            .await?;

        println!("\n\r[📊] Send Complete:");
        println!("  - Chunks:  {}", report.total_chunks);
        println!(
            "  - Elapsed: {:.2}ms",
            report.elapsed.as_secs_f64() * 1000.0
        );
        println!("  - Stalls:  {} (throttle events)", report.throttle_stalls);

        // Wait a bit to ensure all background tasks finish
        tokio::time::sleep(Duration::from_secs(1)).await;

        // 🔌 Graceful Disconnect
        println!("\n\r[🔌] Closing connection...");
        engine.disconnect(target_addr, "Example finished").await?;
    } else {
        println!("Failed to connect.");
    }

    Ok(())
}
