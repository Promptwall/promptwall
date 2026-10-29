//! Promptwall data plane.
//!
//! The proxy routes each request by its [`Policy`]. Routes without detectors
//! stream the body straight through; routes with detectors read the request
//! body once, run the Tier 1 detectors and then forward, redact or block.
//! Responses are always streamed back without buffering.

pub mod inspect;
pub mod output;
pub mod policy;
pub mod tools;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::PathAndQuery;
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use promptwall_classify::Classifier;
use promptwall_detect::{Kind, SystemPromptIndex};
use tokio::net::TcpListener;

pub use policy::Policy;
use policy::{Action, FailMode};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Largest request body accepted on an inspected route.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Largest request body that is scanned; larger ones follow the route's fail mode.
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Response header telling the client what Promptwall did (not set in shadow mode).
const ACTION_HEADER: &str = "x-promptwall-action";

/// Headers that apply to a single connection and must not be forwarded
/// (RFC 9110, section 7.6.1).
const HOP_BY_HOP: [HeaderName; 7] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::UPGRADE,
];

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    policy: Policy,
    classifier: Option<Arc<Classifier>>,
    client: Client<HttpsConnector<HttpConnector>, ProxyBody>,
}

impl Proxy {
    /// Creates a proxy that forwards everything to `upstream`, for example
    /// `https://api.openai.com`, without inspection.
    pub fn new(upstream: &str) -> anyhow::Result<Self> {
        Self::with_policy(Policy::passthrough(upstream)?)
    }

    pub fn with_policy(policy: Policy) -> anyhow::Result<Self> {
        Self::with_classifier(policy, None)
    }

    /// Like [`Proxy::with_policy`], with the Tier 2 prompt-injection classifier.
    /// Without one, `prompt_injection` uses the Tier 1 patterns only.
    pub fn with_classifier(
        policy: Policy,
        classifier: Option<Arc<Classifier>>,
    ) -> anyhow::Result<Self> {
        if classifier.is_none() {
            if let Some(route) = policy.routes.iter().find(|r| r.threshold.is_some()) {
                anyhow::bail!(
                    "route {:?} sets a prompt_injection threshold, but no injection model is loaded (--injection-model)",
                    route.name
                );
            }
        }
        let mut http = HttpConnector::new();
        http.set_nodelay(true);
        http.enforce_http(false);
        http.set_keepalive(Some(Duration::from_secs(60)));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))
            .context("TLS setup failed")?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(https);

        Ok(Self {
            inner: Arc::new(Inner {
                policy,
                classifier,
                client,
            }),
        })
    }

    /// Handles one request. Never fails: errors become an HTTP error response.
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<ProxyBody>, Infallible> {
        if req.uri().path() == "/healthz" {
            return Ok(text(StatusCode::OK, "ok\n"));
        }
        let Some(route) = self.inner.policy.route(req.uri().path(), req.headers()) else {
            return Ok(json_error(
                StatusCode::NOT_FOUND,
                "promptwall_no_route",
                "No Promptwall route matches this request",
                &[],
            ));
        };

        let (mut parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        parts.uri = match Uri::builder()
            .scheme(route.upstream.scheme.clone())
            .authority(route.upstream.authority.clone())
            .path_and_query(path)
            .build()
        {
            Ok(uri) => uri,
            Err(_) => return Ok(text(StatusCode::BAD_REQUEST, "invalid request URI\n")),
        };
        // The client picks the upstream HTTP version; the inbound one may differ.
        parts.version = http::Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        parts
            .headers
            .insert(header::HOST, route.upstream.host.clone());

        if let Some(rules) = &route.output {
            // Answers must arrive uncompressed to be scanned.
            parts.headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
            parts.extensions.insert(Arc::new(output::OutputCheck {
                route: route.name.clone(),
                rules: rules.clone(),
                shadow: route.shadow,
                fail_closed: route.fail_mode == FailMode::Closed,
                system: None,
                tools: route.tools.clone(),
            }));
        }

        if !route.reads_request() {
            return Ok(self
                .forward(Request::from_parts(parts, body.boxed()), None)
                .await);
        }

        let compressed = parts
            .headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| v != "identity");
        let body = match Limited::new(body, MAX_BODY_BYTES).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Ok(json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "promptwall_body_too_large",
                    "Request body is too large or could not be read",
                    &[],
                ))
            }
        };

        let classifier = route.classifier().zip(self.inner.classifier.clone());
        let leak_words = route.output.as_ref().and_then(|o| o.leak_words);
        let leak_check = leak_words.is_some();
        let outcome = if compressed || body.len() > MAX_SCAN_BYTES {
            Err(inspect::Unscannable)
        } else {
            inspect::inspect(
                &route.detector,
                &route.input,
                &body,
                inspect::Collect {
                    untrusted: classifier.is_some(),
                    trusted: leak_check,
                },
            )
        };
        let mut outcome = match outcome {
            Ok(mut outcome) => {
                if let Some(rules) = &route.tools {
                    check_offered_tools(rules, &body, &mut outcome);
                }
                if let (Some(words), Some(rules)) = (leak_words, &route.output) {
                    let system = std::mem::take(&mut outcome.trusted_text);
                    parts.extensions.insert(Arc::new(output::OutputCheck {
                        route: route.name.clone(),
                        rules: rules.clone(),
                        shadow: route.shadow,
                        fail_closed: route.fail_mode == FailMode::Closed,
                        system: Some(SystemPromptIndex::new(&system, words)),
                        tools: route.tools.clone(),
                    }));
                }
                outcome
            }
            Err(inspect::Unscannable) => {
                tracing::warn!(route = %route.name, bytes = body.len(), compressed, fail_mode = ?route.fail_mode, "request body could not be inspected");
                return Ok(self.uninspected(route, parts, body).await);
            }
        };

        // Tier 2 runs only when Tier 1 has not already blocked the request.
        let scoring = match classifier {
            Some(((threshold, action), model))
                if outcome.action != Some(Action::Block) && !outcome.untrusted_text.is_empty() =>
            {
                let text = std::mem::take(&mut outcome.untrusted_text);
                let started = Instant::now();
                let task = tokio::task::spawn_blocking(move || {
                    model.score(&text).map(|score| (score, started.elapsed()))
                });
                Some((threshold, action, task))
            }
            _ => None,
        };
        let Some((threshold, model_action, task)) = scoring else {
            return Ok(self.decide(route, parts, body, outcome).await);
        };

        if !route.classifier_parallel {
            return Ok(match classifier_verdict(route, task, threshold).await {
                Some(hit) => {
                    if hit {
                        add_classifier_finding(&mut outcome, model_action);
                    }
                    self.decide(route, parts, body, outcome).await
                }
                None => self.uninspected(route, parts, body).await,
            });
        }

        // Forward what Tier 1 allows while the classifier runs, and hold the
        // response until it has decided. Its latency then hides behind the
        // provider's time to first token instead of adding to it.
        let tier1 = if route.shadow { None } else { outcome.action };
        let body_out = match tier1 {
            Some(Action::Redact) => outcome.redacted_body.take().unwrap_or(body),
            _ => body,
        };
        let proxy = self.clone();
        let upstream =
            tokio::spawn(async move { proxy.forward(with_body(parts, body_out), tier1).await });
        let hit = match classifier_verdict(route, task, threshold).await {
            Some(hit) => hit,
            None if route.fail_mode == FailMode::Closed && !route.shadow => {
                upstream.abort();
                return Ok(uninspectable());
            }
            None => false,
        };
        if hit {
            add_classifier_finding(&mut outcome, model_action);
        }
        if let Some(action) = outcome.action {
            log_findings(route, action, &outcome);
        }
        if hit && !route.shadow && model_action == Action::Block {
            upstream.abort();
            return Ok(policy_violation(&outcome));
        }
        let mut resp = match upstream.await {
            Ok(resp) => resp,
            Err(_) => text(StatusCode::BAD_GATEWAY, "upstream unavailable\n"),
        };
        if hit && !route.shadow && !resp.headers().contains_key(ACTION_HEADER) {
            resp.headers_mut().insert(
                ACTION_HEADER,
                HeaderValue::from_static(model_action.as_str()),
            );
        }
        Ok(resp)
    }

    /// Applies the inspection outcome: forwards, redacts or blocks.
    async fn decide(
        &self,
        route: &policy::Route,
        parts: http::request::Parts,
        body: Bytes,
        outcome: inspect::Outcome,
    ) -> Response<ProxyBody> {
        let Some(action) = outcome.action else {
            return self.forward(with_body(parts, body), None).await;
        };
        log_findings(route, action, &outcome);
        if route.shadow {
            return self.forward(with_body(parts, body), None).await;
        }
        match action {
            Action::Block => policy_violation(&outcome),
            Action::Redact => {
                let body = outcome.redacted_body.unwrap_or(body);
                self.forward(with_body(parts, body), Some(action)).await
            }
            Action::Flag => self.forward(with_body(parts, body), Some(action)).await,
        }
    }

    /// A request whose body could not be fully inspected: blocked or forwarded
    /// unchanged, depending on the route's fail mode.
    async fn uninspected(
        &self,
        route: &policy::Route,
        parts: http::request::Parts,
        body: Bytes,
    ) -> Response<ProxyBody> {
        if route.fail_mode == FailMode::Closed && !route.shadow {
            return uninspectable();
        }
        self.forward(with_body(parts, body), None).await
    }

    async fn forward(
        &self,
        req: Request<ProxyBody>,
        action: Option<Action>,
    ) -> Response<ProxyBody> {
        let check = req.extensions().get::<Arc<output::OutputCheck>>().cloned();
        match self.inner.client.request(req).await {
            Ok(resp) => {
                let (mut parts, body) = resp.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                if let Some(action) = action {
                    parts
                        .headers
                        .insert(ACTION_HEADER, HeaderValue::from_static(action.as_str()));
                }
                match check {
                    Some(check) => output::check(check, parts, body).await,
                    None => Response::from_parts(parts, body.boxed()),
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "upstream request failed");
                text(StatusCode::BAD_GATEWAY, "upstream unavailable\n")
            }
        }
    }

    /// Accepts connections on `listener` until `shutdown` resolves.
    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        tokio::pin!(shutdown);
        loop {
            let (stream, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!(error = %err, "accept failed");
                        continue;
                    }
                },
                _ = &mut shutdown => return Ok(()),
            };
            let _ = stream.set_nodelay(true);
            let proxy = self.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(req).await }
                });
                if let Err(err) = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    tracing::debug!(%peer, error = %err, "connection closed with error");
                }
            });
        }
    }
}

/// Waits for the classifier. `None` means it failed and the route's fail mode
/// decides.
async fn classifier_verdict(
    route: &policy::Route,
    task: tokio::task::JoinHandle<anyhow::Result<(f32, Duration)>>,
    threshold: f32,
) -> Option<bool> {
    match task.await {
        Ok(Ok((score, elapsed))) => {
            tracing::debug!(route = %route.name, score, elapsed_us = elapsed.as_micros() as u64, "injection classifier");
            Some(score >= threshold)
        }
        Ok(Err(err)) => {
            tracing::warn!(route = %route.name, error = %format!("{err:#}"), "injection classifier failed");
            None
        }
        Err(err) => {
            tracing::warn!(route = %route.name, error = %err, "injection classifier panicked");
            None
        }
    }
}

fn add_classifier_finding(outcome: &mut inspect::Outcome, action: Action) {
    *outcome
        .findings
        .entry(Kind::InjectionClassifier.id())
        .or_default() += 1;
    outcome.action = outcome.action.max(Some(action));
}

fn log_findings(route: &policy::Route, action: Action, outcome: &inspect::Outcome) {
    tracing::info!(
        route = %route.name,
        action = action.as_str(),
        shadow = route.shadow,
        findings = ?outcome.findings.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>(),
        "sensitive data in request"
    );
}

/// Records the tools a request offers that the route does not allow.
fn check_offered_tools(rules: &tools::ToolRules, body: &[u8], outcome: &mut inspect::Outcome) {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return;
    };
    let denied = tools::offered(&json)
        .iter()
        .filter(|name| !rules.allows(name))
        .count();
    if denied > 0 {
        *outcome
            .findings
            .entry(tools::NOT_ALLOWED.to_owned())
            .or_default() += denied;
        outcome.action = outcome.action.max(Some(rules.action));
    }
}

fn policy_violation(outcome: &inspect::Outcome) -> Response<ProxyBody> {
    let kinds: Vec<String> = outcome.findings.keys().cloned().collect();
    json_error(
        StatusCode::FORBIDDEN,
        "promptwall_policy_violation",
        &format!("Request blocked by Promptwall policy: {}", kinds.join(", ")),
        &kinds,
    )
}

fn uninspectable() -> Response<ProxyBody> {
    json_error(
        StatusCode::FORBIDDEN,
        "promptwall_uninspectable",
        "Request blocked by Promptwall: the body could not be inspected",
        &[],
    )
}

/// Binds `addr` and returns the listener and its actual address (useful with port 0).
pub async fn bind(addr: SocketAddr) -> anyhow::Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot listen on {addr}"))?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Headers named in `Connection` are hop-by-hop too.
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named.iter().chain(HOP_BY_HOP.iter()) {
        headers.remove(name);
    }
}

/// Rebuilds a request around a body that was read into memory.
fn with_body(mut parts: http::request::Parts, body: Bytes) -> Request<ProxyBody> {
    parts.headers.remove(header::TRANSFER_ENCODING);
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    Request::from_parts(parts, full(body))
}

fn full(body: Bytes) -> ProxyBody {
    Full::new(body).map_err(|e| match e {}).boxed()
}

/// An error in the OpenAI error shape, so existing clients surface the message.
fn json_error(
    status: StatusCode,
    kind: &str,
    message: &str,
    findings: &[String],
) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": { "message": message, "type": kind, "code": status.as_u16(), "findings": findings }
    });
    let mut resp = Response::new(full(body.to_string().into()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if status == StatusCode::FORBIDDEN {
        resp.headers_mut()
            .insert(ACTION_HEADER, HeaderValue::from_static("block"));
    }
    resp
}

fn text(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut resp = Response::new(full(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
