use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

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

    /// Directory with an ONNX prompt-injection classifier (model.onnx,
    /// tokenizer.json, config.json). Without one, the prompt_injection detector
    /// uses its Tier 1 patterns only.
    #[arg(long, env = "PROMPTWALL_INJECTION_MODEL")]
    injection_model: Option<PathBuf>,

    /// Directory with an ONNX moderation model for the content_safety detector,
    /// such as a content-safety guard (an `unsafe` label plus harm categories)
    /// or a toxicity model. An optional thresholds.json sets per-category
    /// thresholds.
    #[arg(long, env = "PROMPTWALL_SAFETY_MODEL")]
    safety_model: Option<PathBuf>,

    /// Directory with an ONNX zero-shot (NLI) model for the topics detector.
    #[arg(long, env = "PROMPTWALL_TOPIC_MODEL")]
    topic_model: Option<PathBuf>,

    /// Classifier sessions that run in parallel (each holds a copy of the model).
    /// Defaults to the number of CPUs, at most 4.
    #[arg(long, env = "PROMPTWALL_MODEL_SESSIONS")]
    model_sessions: Option<usize>,
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
    let mut options = promptwall_classify::Options::default();
    if let Some(n) = args.model_sessions {
        options.sessions = n;
    }
    let load = |what: &str, dir: &std::path::Path| {
        tracing::info!(model = %dir.display(), sessions = options.sessions, "loading {what} model");
        std::time::Instant::now()
    };
    let mut models = promptwall::Models::default();
    if let Some(dir) = &args.injection_model {
        let started = load("injection", dir);
        models.injection = Some(Arc::new(promptwall_classify::Classifier::load(
            dir, &options,
        )?));
        tracing::info!(
            load_ms = started.elapsed().as_millis() as u64,
            "injection classifier loaded"
        );
    }
    if let Some(dir) = &args.safety_model {
        let started = load("safety", dir);
        let model = promptwall::moderation::Safety::load(dir, &options)?;
        let categories: Vec<&str> = model.categories().collect();
        tracing::info!(
            load_ms = started.elapsed().as_millis() as u64,
            ?categories,
            "safety model loaded"
        );
        models.safety = Some(Arc::new(model));
    }
    if let Some(dir) = &args.topic_model {
        let started = load("topic", dir);
        models.topics = Some(Arc::new(promptwall::moderation::Topics::load(
            dir, &options,
        )?));
        tracing::info!(
            load_ms = started.elapsed().as_millis() as u64,
            "topic model loaded"
        );
    }
    let proxy = promptwall::Proxy::with_models(policy, models)?;
    let (listener, addr) = promptwall::bind(args.listen).await?;
    tracing::info!(%addr, "promptwall listening");

    proxy
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
}
