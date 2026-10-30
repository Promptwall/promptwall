//! Connection limits: past `--max-connections`, new connections wait until
//! one closes.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn health(addr: std::net::SocketAddr) -> std::io::Result<String> {
    let mut conn = TcpStream::connect(addr).await?;
    conn.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await?;
    let mut out = String::new();
    conn.read_to_string(&mut out).await?;
    Ok(out)
}

#[tokio::test]
async fn waits_for_a_free_connection_slot() {
    let proxy = promptwall::Proxy::new("http://127.0.0.1:9").unwrap();
    proxy.set_max_connections(1);
    let (listener, addr) = promptwall::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    tokio::spawn(proxy.serve(listener, std::future::pending()));

    assert!(health(addr).await.unwrap().starts_with("HTTP/1.1 200"));
    // An idle client takes the only slot...
    let idle = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiting = tokio::spawn(health(addr));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished(), "served past the limit");
    // ...and the next one is served once it leaves.
    drop(idle);
    let answer = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"));
}
