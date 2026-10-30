//! Promptwall data plane.
//!
//! The proxy routes each request by its [`Policy`]. Routes without detectors
//! stream the body straight through; routes with detectors read the request
//! body once, run the Tier 1 detectors and then forward, redact or block.
//! Responses are always streamed back without buffering.

pub mod decision;
pub mod init;
pub mod metrics;
pub mod output;
pub mod reload;
pub mod signing;

pub use promptwall_engine::{inspect, limits, moderation, ner, policy, text, tools};

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock, RwLock};
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

pub use policy::Action;
use policy::FailMode;
pub use policy::Policy;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Largest request body accepted on an inspected route.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Largest request body that is scanned; larger ones follow the route's fail mode.
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// Response header telling the client what Promptwall did (not set in shadow mode).
const ACTION_HEADER: &str = "x-promptwall-action";
/// The ID of the request in the decision log.
const REQUEST_ID_HEADER: &str = "x-promptwall-request-id";
/// Where the check API is served, when it is on. Under `/promptwall/` so that
/// it cannot clash with a provider's own paths.
pub const CHECK_PATH: &str = "/promptwall/v1/check";

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
    /// Swapped as a whole on reload; each request keeps the one it started with.
    policy: RwLock<Arc<Policy>>,
    models: Models,
    client: Client<HttpsConnector<HttpConnector>, ProxyBody>,
    /// The check API, when it is on: `Some(token)` if callers need one.
    check_api: OnceLock<Option<String>>,
}

impl Proxy {
    /// Creates a proxy that forwards everything to `upstream`, for example
    /// `https://api.openai.com`, without inspection.
    pub fn new(upstream: &str) -> anyhow::Result<Self> {
        Self::with_policy(Policy::passthrough(upstream)?)
    }

    pub fn with_policy(policy: Policy) -> anyhow::Result<Self> {
        Self::with_models(policy, Models::default())
    }

    /// Like [`Proxy::with_policy`], with the Tier 2 prompt-injection classifier.
    /// Without one, `prompt_injection` uses the Tier 1 patterns only.
    pub fn with_classifier(
        policy: Policy,
        classifier: Option<Arc<Classifier>>,
    ) -> anyhow::Result<Self> {
        Self::with_models(
            policy,
            Models {
                injection: classifier,
                ..Models::default()
            },
        )
    }

    /// Like [`Proxy::with_policy`], with Tier 2 models. Fails when a route
    /// needs a model that is not loaded.
    pub fn with_models(policy: Policy, models: Models) -> anyhow::Result<Self> {
        check_models(&policy, &models)?;
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
                policy: RwLock::new(Arc::new(policy)),
                models,
                client,
                check_api: OnceLock::new(),
            }),
        })
    }

    /// Serves the check API on `/promptwall/v1/check`: apps (and the npm
    /// package) send it one prompt or answer and get the route's verdict,
    /// models included. With a token, callers must send it as a bearer token.
    /// Takes effect once; later calls do nothing.
    pub fn enable_check_api(&self, token: Option<String>) {
        let _ = self.inner.check_api.set(token.filter(|t| !t.is_empty()));
    }

    /// Answers one call of the check API.
    async fn check_api(&self, req: Request<Incoming>, token: Option<&str>) -> Response<ProxyBody> {
        if req.method() != http::Method::POST {
            return json_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "promptwall_method_not_allowed",
                "Use POST",
                &[],
            );
        }
        if let Some(token) = token {
            let sent = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or_default();
            if !same(sent.as_bytes(), token.as_bytes()) {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "promptwall_unauthorized",
                    "Missing or wrong bearer token for the check API",
                    &[],
                );
            }
        }
        let body = match Limited::new(req.into_body(), MAX_SCAN_BYTES)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "promptwall_body_too_large",
                    "Request body is too large or could not be read",
                    &[],
                )
            }
        };
        #[derive(serde::Deserialize)]
        struct CheckRequest {
            route: Option<String>,
            #[serde(default)]
            direction: Direction,
            text: String,
        }
        #[derive(Default, serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Direction {
            #[default]
            Input,
            Output,
        }
        let call: CheckRequest = match serde_json::from_slice(&body) {
            Ok(call) => call,
            Err(err) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "promptwall_invalid_check",
                    &format!("Invalid check request: {err}"),
                    &[],
                )
            }
        };
        let route = match call.route {
            Some(route) => route,
            None => {
                let policy = self.policy();
                match policy
                    .routes
                    .iter()
                    .find(|r| r.name == "default")
                    .or(policy.routes.first())
                {
                    Some(route) => route.name.clone(),
                    None => String::new(),
                }
            }
        };
        let proxy = self.clone();
        let started = Instant::now();
        let checked = {
            let route = route.clone();
            tokio::task::spawn_blocking(move || {
                let sample = match call.direction {
                    Direction::Input => Sample::Input(&call.text),
                    Direction::Output => Sample::Output(&call.text),
                };
                proxy.check(&route, sample)
            })
            .await
        };
        let verdict = match checked {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(err)) => {
                let unknown = !self.policy().routes.iter().any(|r| r.name == route);
                let (status, code) = if unknown {
                    (StatusCode::NOT_FOUND, "promptwall_no_route")
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, "promptwall_check_failed")
                };
                return json_error(status, code, &format!("{err:#}"), &[]);
            }
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "promptwall_check_failed",
                    "The check failed",
                    &[],
                )
            }
        };
        let action = verdict.action.map_or("allow", Action::as_str);
        metrics::count(
            "promptwall_checks_total",
            &[("route", &route), ("action", action)],
            1,
        );
        metrics::observe(
            "promptwall_check_duration_seconds",
            &[("route", &route), ("stage", "check_api")],
            started.elapsed(),
        );
        let mut body = serde_json::to_value(&verdict).unwrap_or_default();
        body["route"] = route.into();
        Response::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(full(Bytes::from(body.to_string())))
            .unwrap_or_else(|_| text(StatusCode::INTERNAL_SERVER_ERROR, "error\n"))
    }

    /// The policy in force.
    pub fn policy(&self) -> Arc<Policy> {
        self.inner
            .policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Replaces the policy. Requests already running finish under the old
    /// one. Fails, and keeps the old policy, when the new one needs a model
    /// that is not loaded. Rate-limit counters carry over for routes whose
    /// name and limits are unchanged.
    pub fn reload(&self, mut policy: Policy) -> anyhow::Result<()> {
        check_models(&policy, &self.inner.models)?;
        let old = self.policy();
        for route in &mut policy.routes {
            let kept = old
                .routes
                .iter()
                .find(|r| r.name == route.name)
                .and_then(|r| r.limits.as_ref())
                .filter(|l| route.limits.as_ref().is_some_and(|n| n.limits == l.limits));
            if let Some(limiter) = kept {
                route.limits = Some(limiter.clone());
            }
        }
        *self.inner.policy.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(policy);
        Ok(())
    }

    /// Handles one request. Never fails: errors become an HTTP error response.
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<ProxyBody>, Infallible> {
        if req.uri().path() == "/healthz" {
            return Ok(text(StatusCode::OK, "ok\n"));
        }
        if req.uri().path() == CHECK_PATH {
            if let Some(token) = self.inner.check_api.get() {
                return Ok(self.check_api(req, token.as_deref()).await);
            }
        }
        let started = Instant::now();
        let policy = self.policy();
        let (route, shadow) = policy
            .route(req.uri().path(), req.headers())
            .map_or_else(|| (String::new(), false), |r| (r.name.clone(), r.shadow));
        let record = decision::enabled().then(|| decision::Record::new(&policy.digest));
        drop(policy);
        let mut resp = match &record {
            Some(record) => decision::scope(record.clone(), self.handle_request(req)).await?,
            None => self.handle_request(req).await?,
        };
        let action = match (resp.status(), resp.headers().get(ACTION_HEADER)) {
            (StatusCode::TOO_MANY_REQUESTS, _) => "rate_limited",
            (StatusCode::NOT_FOUND, _) if route.is_empty() => "no_route",
            (_, Some(v)) => match v.as_bytes() {
                b"flag" => "flag",
                b"redact" => "redact",
                b"block" => "block",
                _ => "allow",
            },
            (StatusCode::FORBIDDEN, None) => "block",
            (StatusCode::BAD_GATEWAY, None) => "error",
            _ => "allow",
        };
        metrics::count(
            "promptwall_requests_total",
            &[("route", &route), ("action", action)],
            1,
        );
        metrics::observe(
            "promptwall_request_duration_seconds",
            &[("route", &route)],
            started.elapsed(),
        );
        if let Some(record) = record {
            record.update(|e| {
                e.route = route;
                e.action = action;
                e.shadow = shadow;
                e.status = resp.status().as_u16();
            });
            record.headers_sent();
            if let Ok(id) = HeaderValue::from_str(&record.id()) {
                resp.headers_mut().insert(REQUEST_ID_HEADER, id);
            }
            // The event is written once the whole response has been sent.
            resp = resp.map(|body| {
                body.map_frame(move |frame| {
                    let _ = &record;
                    frame
                })
                .boxed()
            });
        }
        Ok(resp)
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let policy = self.policy();
        let Some(route) = policy.route(req.uri().path(), req.headers()) else {
            return Ok(json_error(
                StatusCode::NOT_FOUND,
                "promptwall_no_route",
                "No Promptwall route matches this request",
                &[],
            ));
        };

        let (mut parts, body) = req.into_parts();
        if let Some(limiter) = &route.limits {
            match limiter.admit(&parts.headers, limits::now()) {
                Ok(ticket) if limiter.counts_tokens() => {
                    parts.extensions.insert(Arc::new(ticket));
                }
                Ok(_) => {}
                Err(over) => {
                    tracing::info!(route = %route.name, limit = over.what, max = over.limit, shadow = route.shadow, "rate limit reached");
                    if !route.shadow {
                        return Ok(rate_limited(&over));
                    }
                }
            }
        }
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
                safety: rules.safety.clone().zip(self.inner.models.safety.clone()),
                pii: rules.pii.clone().zip(self.inner.models.pii.clone()),
                prompt: String::new(),
                decision: decision::current(),
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

        let models = &self.inner.models;
        let jobs = Tier2 {
            injection: route.classifier().zip(models.injection.clone()),
            safety: route.safety.clone().zip(models.safety.clone()),
            topics: route.topics.clone().zip(models.topics.clone()),
        };
        let output_safety = route.output.as_ref().and_then(|o| o.safety.clone());
        let leak_words = route.output.as_ref().and_then(|o| o.leak_words);
        let checking = Instant::now();
        let outcome = if compressed || body.len() > MAX_SCAN_BYTES {
            Err(inspect::Unscannable)
        } else {
            inspect::inspect(
                &route.detector,
                &route.input,
                &body,
                inspect::Collect {
                    untrusted: !jobs.is_empty() || output_safety.is_some(),
                    trusted: leak_words.is_some(),
                },
                &route.except,
            )
        };
        metrics::observe(
            "promptwall_check_duration_seconds",
            &[("route", &route.name), ("stage", "rules")],
            checking.elapsed(),
        );
        decision::check_time("rules", checking.elapsed());
        let mut outcome = match outcome {
            Ok(mut outcome) => {
                if let Some(rules) = &route.tools {
                    check_offered_tools(rules, &body, &mut outcome);
                }
                if let Some(rules) = route
                    .output
                    .as_ref()
                    .filter(|_| leak_words.is_some() || output_safety.is_some())
                {
                    // The answer is checked against this request's system prompt
                    // and judged together with its prompt.
                    let system = std::mem::take(&mut outcome.trusted_text);
                    parts.extensions.insert(Arc::new(output::OutputCheck {
                        route: route.name.clone(),
                        rules: rules.clone(),
                        shadow: route.shadow,
                        fail_closed: route.fail_mode == FailMode::Closed,
                        system: leak_words.map(|words| SystemPromptIndex::new(&system, words)),
                        tools: route.tools.clone(),
                        safety: output_safety.zip(models.safety.clone()),
                        pii: rules.pii.clone().zip(models.pii.clone()),
                        prompt: last_chars(&outcome.untrusted_text, PROMPT_CONTEXT).to_owned(),
                        decision: decision::current(),
                    }));
                }
                outcome
            }
            Err(inspect::Unscannable) => {
                tracing::warn!(route = %route.name, bytes = body.len(), compressed, fail_mode = ?route.fail_mode, "request body could not be inspected");
                return Ok(self.uninspected(route, parts, body).await);
            }
        };

        // Names and addresses are redacted before anything is forwarded.
        if let Some((rule, model)) = route.pii.clone().zip(models.pii.clone()) {
            if outcome.action != Some(Action::Block) {
                let current = outcome
                    .redacted_body
                    .clone()
                    .unwrap_or_else(|| body.clone());
                let tagging = Instant::now();
                let task = tokio::task::spawn_blocking(move || tag_body(&model, &rule, &current));
                let tagged = task.await;
                metrics::observe(
                    "promptwall_check_duration_seconds",
                    &[("route", &route.name), ("stage", "models")],
                    tagging.elapsed(),
                );
                decision::check_time("models", tagging.elapsed());
                match tagged {
                    Ok(Ok((tagged, new_body))) => add_tagged(&mut outcome, tagged, new_body),
                    Ok(Err(err)) => {
                        tracing::warn!(route = %route.name, error = %format!("{err:#}"), "PII model failed");
                        return Ok(self.uninspected(route, parts, body).await);
                    }
                    Err(err) => {
                        tracing::warn!(route = %route.name, error = %err, "PII model panicked");
                        return Ok(self.uninspected(route, parts, body).await);
                    }
                }
            }
        }

        // Tier 2 runs only when Tier 1 has not already blocked the request.
        let task = (!jobs.is_empty()
            && outcome.action != Some(Action::Block)
            && !outcome.untrusted_text.is_empty())
        .then(|| {
            let text = std::mem::take(&mut outcome.untrusted_text);
            tokio::task::spawn_blocking(move || jobs.run(&text))
        });
        let Some(task) = task else {
            return Ok(self.decide(route, parts, body, outcome).await);
        };

        if !route.classifier_parallel {
            return Ok(match tier2_verdict(route, task).await {
                Some(found) => {
                    add_model_findings(&mut outcome, &found);
                    self.decide(route, parts, body, outcome).await
                }
                None => self.uninspected(route, parts, body).await,
            });
        }

        // Forward what Tier 1 allows while the models run, and hold the
        // response until they have decided. Their latency then hides behind
        // the provider's time to first token instead of adding to it.
        let tier1 = if route.shadow { None } else { outcome.action };
        let body_out = match tier1 {
            Some(Action::Redact) => outcome.redacted_body.take().unwrap_or(body),
            _ => body,
        };
        let proxy = self.clone();
        let upstream =
            tokio::spawn(async move { proxy.forward(with_body(parts, body_out), tier1).await });
        let found = match tier2_verdict(route, task).await {
            Some(found) => found,
            None if route.fail_mode == FailMode::Closed && !route.shadow => {
                upstream.abort();
                return Ok(uninspectable());
            }
            None => Vec::new(),
        };
        add_model_findings(&mut outcome, &found);
        if let Some(action) = outcome.action {
            log_findings(route, action, &outcome);
        }
        let model_action = found.iter().map(|(_, a)| *a).max();
        if !route.shadow && model_action == Some(Action::Block) {
            upstream.abort();
            return Ok(policy_violation(&outcome));
        }
        let mut resp = match upstream.await {
            Ok(resp) => resp,
            Err(_) => text(StatusCode::BAD_GATEWAY, "upstream unavailable\n"),
        };
        if let Some(action) = model_action.filter(|_| !route.shadow) {
            if !resp.headers().contains_key(ACTION_HEADER) {
                resp.headers_mut()
                    .insert(ACTION_HEADER, HeaderValue::from_static(action.as_str()));
            }
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
        metrics::count(
            "promptwall_uninspected_total",
            &[("route", &route.name), ("direction", "request")],
            1,
        );
        decision::note(|e| e.request.uninspected = true);
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
        let ticket = req.extensions().get::<Arc<limits::Ticket>>().cloned();
        let resp = self.send(req, action, check).await;
        match ticket {
            Some(ticket) => resp.map(|body| limits::meter(body, ticket)),
            None => resp,
        }
    }

    async fn send(
        &self,
        req: Request<ProxyBody>,
        action: Option<Action>,
        check: Option<Arc<output::OutputCheck>>,
    ) -> Response<ProxyBody> {
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
                metrics::count("promptwall_upstream_errors_total", &[], 1);
                text(StatusCode::BAD_GATEWAY, "upstream unavailable\n")
            }
        }
    }

    /// Runs a route's checks on one prompt or answer without sending
    /// anything, for policy tests and `promptwall scan`. A prompt is checked
    /// as the user message of a chat request. Blocking: the models run inline.
    pub fn check(&self, route: &str, sample: Sample) -> anyhow::Result<Verdict> {
        let policy = self.policy();
        let route = policy
            .routes
            .iter()
            .find(|r| r.name == route)
            .with_context(|| format!("no route named {route:?}"))?;
        let models = &self.inner.models;
        let text = match sample {
            Sample::Input(text) => text,
            Sample::Output(text) => {
                let Some(rules) = &route.output else {
                    return Ok(Verdict {
                        text: text.to_owned(),
                        ..Verdict::default()
                    });
                };
                let check = output::OutputCheck {
                    route: route.name.clone(),
                    rules: rules.clone(),
                    shadow: false,
                    fail_closed: route.fail_mode == FailMode::Closed,
                    system: None,
                    tools: None,
                    safety: rules.safety.clone().zip(models.safety.clone()),
                    pii: rules.pii.clone().zip(models.pii.clone()),
                    prompt: String::new(),
                    decision: None,
                };
                return output::check_text(&check, text);
            }
        };
        let (mut outcome, body) = text::inspect_input(route, text, true)?;
        if outcome.action != Some(Action::Block) {
            if let Some((rule, model)) = route.pii.as_ref().zip(models.pii.as_ref()) {
                let current = outcome
                    .redacted_body
                    .clone()
                    .unwrap_or_else(|| body.clone());
                let (tagged, new_body) = tag_body(model, rule, &current)?;
                add_tagged(&mut outcome, tagged, new_body);
            }
        }
        let jobs = Tier2 {
            injection: route.classifier().zip(models.injection.clone()),
            safety: route.safety.clone().zip(models.safety.clone()),
            topics: route.topics.clone().zip(models.topics.clone()),
        };
        if !jobs.is_empty() && outcome.action != Some(Action::Block) {
            let (found, _) = jobs.run(&outcome.untrusted_text)?;
            add_model_findings(&mut outcome, &found);
        }
        text::input_verdict(outcome, text)
    }

    /// Runs the test cases of the policy (its `tests` section). Blocking,
    /// like [`Proxy::check`].
    pub fn run_tests(&self) -> Vec<TestResult> {
        self.policy()
            .tests
            .iter()
            .map(|test| {
                let sample = if test.output {
                    Sample::Output(&test.text)
                } else {
                    Sample::Input(&test.text)
                };
                let failure = match self.check(&test.route, sample) {
                    Err(err) => Some(format!("{err:#}")),
                    Ok(verdict) => {
                        let name = |a: Option<Action>| a.map_or("allow", Action::as_str);
                        let mut problems = Vec::new();
                        if verdict.action != test.action {
                            problems.push(format!(
                                "expected {}, got {}",
                                name(test.action),
                                name(verdict.action)
                            ));
                        }
                        let missing: Vec<&str> = test
                            .findings
                            .iter()
                            .filter(|f| !verdict.findings.contains_key(*f))
                            .map(String::as_str)
                            .collect();
                        if !missing.is_empty() {
                            problems.push(format!("missing findings {}", missing.join(", ")));
                        }
                        if let Some(text) =
                            test.expect_text.as_ref().filter(|t| **t != verdict.text)
                        {
                            problems
                                .push(format!("expected text {text:?}, got {:?}", verdict.text));
                        }
                        if !problems.is_empty() && !verdict.findings.is_empty() {
                            let found: Vec<&str> =
                                verdict.findings.keys().map(String::as_str).collect();
                            problems.push(format!("found {}", found.join(", ")));
                        }
                        (!problems.is_empty()).then(|| problems.join("; "))
                    }
                };
                TestResult {
                    name: test.name.clone(),
                    failure,
                }
            })
            .collect()
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
/// Finding labels from Tier 2 models, with the action each calls for.
type ModelFindings = Vec<(String, Action)>;

/// The Tier 2 models a request is checked with, and their rules.
struct Tier2 {
    injection: Option<((f32, Action), Arc<Classifier>)>,
    safety: Option<(policy::SafetyRule, Arc<moderation::Safety>)>,
    topics: Option<(policy::TopicRule, Arc<moderation::Topics>)>,
}

impl Tier2 {
    fn is_empty(&self) -> bool {
        self.injection.is_none() && self.safety.is_none() && self.topics.is_none()
    }

    /// Runs the models on the prompt text; returns the findings and their
    /// actions, and how long it took. Blocking and CPU-bound.
    fn run(&self, text: &str) -> anyhow::Result<(ModelFindings, Duration)> {
        let started = Instant::now();
        let mut found = Vec::new();
        if let Some(((threshold, action), model)) = &self.injection {
            if model.score(text)? >= *threshold {
                found.push((Kind::InjectionClassifier.id(), *action));
            }
        }
        if let Some((rule, model)) = &self.safety {
            let labels = model.check(text, None, rule)?;
            found.extend(labels.into_iter().map(|l| (l, rule.action)));
        }
        if let Some((rule, model)) = &self.topics {
            let labels = model.check(text, rule)?;
            found.extend(labels.into_iter().map(|l| (l, rule.action)));
        }
        Ok((found, started.elapsed()))
    }
}

/// Tier 2 models loaded at startup. Each is optional; routes that need a
/// missing one are rejected by [`Proxy::with_models`].
#[derive(Clone, Default)]
pub struct Models {
    /// Prompt-injection classifier.
    pub injection: Option<Arc<Classifier>>,
    /// Moderation model for `content_safety`.
    pub safety: Option<Arc<moderation::Safety>>,
    /// Zero-shot model for `topics`.
    pub topics: Option<Arc<moderation::Topics>>,
    /// Token-classification model for `pii` entities that are not built in,
    /// such as names and addresses.
    pub pii: Option<Arc<ner::PiiModel>>,
}

/// The outcome of one policy test.
#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    /// Why it failed; `None` if it passed.
    pub failure: Option<String>,
}

pub use promptwall_engine::{Sample, Verdict};

/// Compares two secrets in time that does not depend on where they differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Adds what the PII model found to the outcome of Tier 1.
fn add_tagged(outcome: &mut inspect::Outcome, tagged: ner::Tagged, new_body: Option<Bytes>) {
    for (label, n) in tagged.findings {
        *outcome.findings.entry(label).or_default() += n;
    }
    outcome.action = outcome.action.max(tagged.action);
    if new_body.is_some() {
        outcome.redacted_body = new_body;
    }
}

/// Tags the prompt text of a request body with the PII model; returns what it
/// found and the body with redactions, if any. Blocking and CPU-bound.
fn tag_body(
    model: &ner::PiiModel,
    rule: &policy::PiiRule,
    body: &[u8],
) -> anyhow::Result<(ner::Tagged, Option<Bytes>)> {
    // Not UTF-8: read as U+FFFD, as the rules do.
    let text = String::from_utf8_lossy(body);
    if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&text) {
        let tagged = model.tag_json(rule, &mut json, &inspect::PROMPT_KEYS)?;
        let new_body = tagged
            .changed
            .then(|| Bytes::from(serde_json::to_vec(&json).unwrap_or_default()));
        return Ok((tagged, new_body));
    }
    let mut text = text.into_owned();
    let tagged = model.tag_text(rule, &mut text)?;
    let new_body = tagged.changed.then(|| Bytes::from(text));
    Ok((tagged, new_body))
}

/// Characters of the prompt kept to judge the answer in context.
const PROMPT_CONTEXT: usize = 2000;

/// The last `n` bytes of `s` or fewer, cut at a character boundary.
fn last_chars(s: &str, n: usize) -> &str {
    let mut start = s.len().saturating_sub(n);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// The findings of the Tier 2 models, or `None` if they failed.
async fn tier2_verdict(
    route: &policy::Route,
    task: tokio::task::JoinHandle<anyhow::Result<(ModelFindings, Duration)>>,
) -> Option<ModelFindings> {
    match task.await {
        Ok(Ok((found, elapsed))) => {
            metrics::observe(
                "promptwall_check_duration_seconds",
                &[("route", &route.name), ("stage", "models")],
                elapsed,
            );
            decision::check_time("models", elapsed);
            tracing::debug!(route = %route.name, ?found, elapsed_us = elapsed.as_micros() as u64, "tier 2 models");
            Some(found)
        }
        Ok(Err(err)) => {
            tracing::warn!(route = %route.name, error = %format!("{err:#}"), "tier 2 model failed");
            None
        }
        Err(err) => {
            tracing::warn!(route = %route.name, error = %err, "tier 2 model panicked");
            None
        }
    }
}

fn add_model_findings(outcome: &mut inspect::Outcome, found: &[(String, Action)]) {
    for (label, action) in found {
        *outcome.findings.entry(label.clone()).or_default() += 1;
        outcome.action = outcome.action.max(Some(*action));
    }
}

fn log_findings(route: &policy::Route, action: Action, outcome: &inspect::Outcome) {
    metrics::findings(&route.name, "request", &outcome.findings);
    decision::note(|e| e.request.record(action, &outcome.findings));
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

fn rate_limited(over: &limits::Exceeded) -> Response<ProxyBody> {
    let mut resp = json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "promptwall_rate_limited",
        &format!(
            "Rate limit reached: {} {}. Try again in {} seconds.",
            over.limit, over.what, over.retry_after
        ),
        &[],
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(over.retry_after));
    resp
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

/// Fails when a route of `policy` needs a model that is not loaded.
fn check_models(policy: &Policy, models: &Models) -> anyhow::Result<()> {
    for route in &policy.routes {
        let name = &route.name;
        if models.injection.is_none() && route.threshold.is_some() {
            anyhow::bail!(
                "route {name:?} sets a prompt_injection threshold, but no injection model is loaded (--injection-model)"
            );
        }
        let output_safety = route.output.as_ref().and_then(|o| o.safety.as_ref());
        for rule in route.safety.iter().chain(output_safety) {
            let Some(model) = &models.safety else {
                anyhow::bail!(
                    "route {name:?} uses content_safety, but no safety model is loaded (--safety-model)"
                );
            };
            let known: Vec<&str> = model.categories().collect();
            if let Some(unknown) = rule
                .categories
                .iter()
                .find(|c| !known.contains(&c.as_str()))
            {
                anyhow::bail!(
                    "route {name:?}: the safety model has no category {unknown:?}; it has {}",
                    known.join(", ")
                );
            }
        }
        if route.topics.is_some() && models.topics.is_none() {
            anyhow::bail!(
                "route {name:?} uses topics, but no topic model is loaded (--topic-model)"
            );
        }
        let output_pii = route.output.as_ref().and_then(|o| o.pii.as_ref());
        for rule in route.pii.iter().chain(output_pii) {
            let builtin = || {
                Kind::ALL
                    .iter()
                    .filter(|k| k.category() == promptwall_detect::Category::Pii)
                    .map(|k| k.entity())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let Some(model) = &models.pii else {
                let entity = rule.entities.keys().next().map_or("", String::as_str);
                anyhow::bail!(
                    "route {name:?}: unknown pii entity {entity:?}. Built in: {}. Names, addresses and other entities need a PII model (--pii-model)",
                    builtin()
                );
            };
            if let Some(unknown) = rule.entities.keys().find(|e| !model.entities().contains(e)) {
                anyhow::bail!(
                    "route {name:?}: unknown pii entity {unknown:?}. Built in: {}. The PII model has: {}",
                    builtin(),
                    model.entities().join(", ")
                );
            }
        }
    }
    Ok(())
}
