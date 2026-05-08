use anyhow::Result;
use s_udp::{Engine, Event};

#[tokio::main]
async fn main() -> Result<()> {
    // 🚀 Initialize the S-UDP Engine
    let engine = Engine::new();

    // Enable logging to see the protocol internals (handshakes, ACKs, etc.)
    let mut logs = engine.enable_logging();
    tokio::spawn(async move {
        while let Some(log) = logs.recv().await {
            println!("{}", log);
        }
    });

    println!("Starting S-UDP Server Example...");
    println!("Listening on 127.0.0.1:5001");

    // 📡 Listen for incoming connections
    // Arguments: bind_addr, expected_client_token, our_server_token
    let mut rx = engine
        .listen(
            "127.0.0.1:5001",
            "CLIENT_SECRET".into(),
            "SERVER_SECRET".into(),
        )
        .await?;

    while let Some(event) = rx.recv().await {
        match event {
            Event::Connected => {
                println!("\n\r[✅] New agent authenticated successfully!");
            }
            Event::Data(report) => {
                println!("\n\r[📦] Received Data Stream:");
                println!("  - Size:    {} bytes", report.total_bytes);
                println!("  - Windows: {}", report.windows_used);
                println!(
                    "  - Elapsed: {:.2}ms",
                    report.elapsed.as_secs_f64() * 1000.0
                );
                println!(
                    "  - Speed:   {:.2} MB/s",
                    (report.throughput_bps / 1024.0 / 1024.0)
                );

                let content = String::from_utf8_lossy(&report.payload);
                println!("  - Content: \"{}\"", content);
            }
            Event::Disconnected(info) => {
                println!(
                    "\n\r[🔌] Peer {} disconnected: {}",
                    info.peer_addr, info.reason
                );
                println!(
                    "  - Final Stats: Sent {} bytes, Received {} bytes",
                    info.session.total_bytes_sent, info.session.total_bytes_received
                );
            }
        }
    }

    Ok(())
}
