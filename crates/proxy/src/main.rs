use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Promptwall: open source AI firewall.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on.
    #[arg(long, env = "PROMPTWALL_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Upstream LLM API, e.g. https://api.openai.com. Used when no policy file is given.
    #[arg(
        long,
        env = "PROMPTWALL_UPSTREAM",
        default_value = "https://api.openai.com"
    )]
    upstream: String,

    /// Policy file (YAML) with routes, upstreams and detectors. Without one,
    /// every request is forwarded to --upstream uninspected.
    #[arg(long, env = "PROMPTWALL_POLICY", conflicts_with = "upstream")]
    policy: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let policy = match &args.policy {
        Some(path) => promptwall::Policy::load(path)?,
        None => promptwall::Policy::passthrough(&args.upstream)?,
    };
    let routes: Vec<&str> = policy.routes.iter().map(|r| r.name.as_str()).collect();
    tracing::info!(?routes, policy = ?args.policy, "policy loaded");
    let proxy = promptwall::Proxy::with_policy(policy)?;
    let (listener, addr) = promptwall::bind(args.listen).await?;
    tracing::info!(%addr, "promptwall listening");

    proxy
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
}
