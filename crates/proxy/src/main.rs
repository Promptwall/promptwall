use std::net::SocketAddr;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Promptwall: open source AI firewall.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "PROMPTWALL_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Upstream LLM API, e.g. https://api.openai.com
    #[arg(
        long,
        env = "PROMPTWALL_UPSTREAM",
        default_value = "https://api.openai.com"
    )]
    upstream: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let proxy = promptwall::Proxy::new(&args.upstream)?;
    let (listener, addr) = promptwall::bind(args.listen).await?;
    tracing::info!(%addr, upstream = %args.upstream, "promptwall listening");

    proxy
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
}
