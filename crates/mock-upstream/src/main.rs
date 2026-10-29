use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;

/// Mock OpenAI-compatible upstream for benchmarks.
#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
    /// Delay before responding, in milliseconds.
    #[arg(long, default_value_t = 50)]
    delay_ms: u64,
    /// Chunks per streamed response.
    #[arg(long, default_value_t = 20)]
    chunks: usize,
    /// Milliseconds between streamed chunks.
    #[arg(long, default_value_t = 20)]
    chunk_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = pw_mock_upstream::Config {
        delay: Duration::from_millis(args.delay_ms),
        chunks: args.chunks,
        chunk_interval: Duration::from_millis(args.chunk_ms),
    };
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("mock upstream listening on {}", listener.local_addr()?);
    pw_mock_upstream::serve(listener, config).await;
    Ok(())
}
