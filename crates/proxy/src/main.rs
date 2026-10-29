use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// Promptwall: open source AI firewall. Without a command, it runs the proxy.
#[derive(Parser)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Address to listen on.
    #[arg(long, env = "PROMPTWALL_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Upstream LLM API, e.g. https://api.openai.com. Used when no policy file is given.
    #[arg(
        long,
        global = true,
        env = "PROMPTWALL_UPSTREAM",
        default_value = "https://api.openai.com"
    )]
    upstream: String,

    /// Policy file (YAML) with routes, upstreams and detectors. Without one,
    /// every request is forwarded to --upstream uninspected.
    #[arg(
        long,
        global = true,
        env = "PROMPTWALL_POLICY",
        conflicts_with = "upstream"
    )]
    policy: Option<PathBuf>,

    /// Directory with an ONNX prompt-injection classifier (model.onnx,
    /// tokenizer.json, config.json). Without one, the prompt_injection detector
    /// uses its Tier 1 patterns only.
    #[arg(long, global = true, env = "PROMPTWALL_INJECTION_MODEL")]
    injection_model: Option<PathBuf>,

    /// Directory with an ONNX moderation model for the content_safety detector,
    /// such as a content-safety guard (an `unsafe` label plus harm categories)
    /// or a toxicity model. An optional thresholds.json sets per-category
    /// thresholds.
    #[arg(long, global = true, env = "PROMPTWALL_SAFETY_MODEL")]
    safety_model: Option<PathBuf>,

    /// Directory with an ONNX zero-shot (NLI) model for the topics detector.
    #[arg(long, global = true, env = "PROMPTWALL_TOPIC_MODEL")]
    topic_model: Option<PathBuf>,

    /// Directory with an ONNX token-classification (NER) model that finds
    /// names, addresses and other personal data without a fixed pattern. Its
    /// entity types (B-PERSON becomes `person`) can then be listed under the
    /// pii detector.
    #[arg(long, global = true, env = "PROMPTWALL_PII_MODEL")]
    pii_model: Option<PathBuf>,

    /// Classifier sessions that run in parallel (each holds a copy of the model).
    /// Defaults to the number of CPUs, at most 4.
    #[arg(long, global = true, env = "PROMPTWALL_MODEL_SESSIONS")]
    model_sessions: Option<usize>,

    /// Address for Prometheus metrics (`GET /metrics`), such as
    /// 127.0.0.1:9464. Off unless set; keep it off the public network.
    #[arg(long, env = "PROMPTWALL_METRICS_LISTEN")]
    metrics_listen: Option<SocketAddr>,

    /// Seconds between checks of the policy file for changes, which are
    /// applied without a restart. 0 turns reloading off.
    #[arg(long, env = "PROMPTWALL_RELOAD_INTERVAL", default_value_t = 2)]
    reload_interval: u64,

    /// Threads each classifier session may use for one inference (default 1).
    /// More threads make each check faster; more sessions let more checks run
    /// at the same time.
    #[arg(long, global = true, env = "PROMPTWALL_MODEL_THREADS")]
    model_threads: Option<usize>,
}

#[derive(Subcommand)]
enum Command {
    /// Ask a few questions and write a policy file.
    Init {
        /// Where to write it.
        #[arg(default_value = "promptwall.yaml")]
        file: PathBuf,
    },
    /// Check the policy file and that the models it needs are loaded.
    Validate,
    /// Run the test cases in the policy's `tests` section.
    Test,
    /// Show what a route does with one prompt (or, with --output, an answer).
    Scan {
        /// The route whose checks apply.
        #[arg(long)]
        route: String,
        /// Check the text as the provider's answer instead of a prompt.
        #[arg(long)]
        output: bool,
        /// The text to check.
        text: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(Command::Init { file }) = &args.command {
        return promptwall::init::run(file);
    }
    // Commands other than the proxy print their own results.
    let default_filter = if args.command.is_some() {
        "warn,ort=warn"
    } else {
        "info,ort=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| default_filter.into()),
        )
        .with_writer(std::io::stderr)
        .init();
    if args.command.is_some() && args.policy.is_none() {
        anyhow::bail!("this command needs a policy file (--policy)");
    }

    let policy = match &args.policy {
        Some(path) => promptwall::Policy::load(path)?,
        None => promptwall::Policy::passthrough(&args.upstream)?,
    };
    let routes: Vec<String> = policy.routes.iter().map(|r| r.name.clone()).collect();
    tracing::info!(?routes, policy = ?args.policy, "policy loaded");
    let mut options = promptwall_classify::Options::default();
    if let Some(n) = args.model_sessions {
        options.sessions = n;
    }
    if let Some(n) = args.model_threads {
        options.threads_per_session = n;
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
    if let Some(dir) = &args.pii_model {
        let started = load("PII", dir);
        let model = promptwall::ner::PiiModel::load(dir, &options)?;
        tracing::info!(
            load_ms = started.elapsed().as_millis() as u64,
            entities = ?model.entities(),
            "PII model loaded"
        );
        models.pii = Some(Arc::new(model));
    }
    let proxy = promptwall::Proxy::with_models(policy, models)?;
    match args.command {
        None => {}
        Some(Command::Init { .. }) => unreachable!("handled above"),
        Some(Command::Validate) => {
            println!("policy is valid: {}", routes.join(", "));
            return Ok(());
        }
        Some(Command::Test) => {
            let results = proxy.run_tests();
            let failed = results.iter().filter(|r| r.failure.is_some()).count();
            for result in &results {
                match &result.failure {
                    None => println!("ok    {}", result.name),
                    Some(why) => println!("FAIL  {}\n      {why}", result.name),
                }
            }
            println!("{} passed, {failed} failed", results.len() - failed);
            if failed > 0 {
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(Command::Scan {
            route,
            output,
            text,
        }) => {
            let sample = if output {
                promptwall::Sample::Output(&text)
            } else {
                promptwall::Sample::Input(&text)
            };
            let verdict = proxy.check(&route, sample)?;
            println!(
                "action: {}",
                verdict.action.map_or("allow", promptwall::Action::as_str)
            );
            for (label, n) in &verdict.findings {
                println!("finding: {label} ({n})");
            }
            println!("text: {}", verdict.text);
            return Ok(());
        }
    }
    if let Some(addr) = args.metrics_listen {
        let (listener, addr) = promptwall::bind(addr).await?;
        tracing::info!(%addr, "metrics on /metrics");
        tokio::spawn(promptwall::metrics::serve(listener));
    }
    if let Some(path) = args.policy.filter(|_| args.reload_interval > 0) {
        tokio::spawn(promptwall::reload::watch(
            proxy.clone(),
            path,
            std::time::Duration::from_secs(args.reload_interval),
        ));
    }
    let (listener, addr) = promptwall::bind(args.listen).await?;
    tracing::info!(%addr, "promptwall listening");

    proxy
        .serve(listener, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await
}
