//! Promptwall data plane.
//!
//! The proxy routes each request by its [`Policy`]. Routes without detectors
//! stream the body straight through; routes with detectors read the request
//! body once, run the Tier 1 detectors and then forward, redact or block.
//! Responses are always streamed back without buffering.

pub mod inspect;
pub mod policy;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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
    client: Client<HttpsConnector<HttpConnector>, ProxyBody>,
}

impl Proxy {
    /// Creates a proxy that forwards everything to `upstream`, for example
    /// `https://api.openai.com`, without inspection.
    pub fn new(upstream: &str) -> anyhow::Result<Self> {
        Self::with_policy(Policy::passthrough(upstream)?)
    }

    pub fn with_policy(policy: Policy) -> anyhow::Result<Self> {
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
            inner: Arc::new(Inner { policy, client }),
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

        if !route.inspects_input() {
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

        let outcome = if compressed || body.len() > MAX_SCAN_BYTES {
            Err(inspect::Unscannable)
        } else {
            inspect::inspect(&route.detector, &route.input, &body)
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(inspect::Unscannable) => {
                tracing::warn!(route = %route.name, bytes = body.len(), compressed, fail_mode = ?route.fail_mode, "request body could not be inspected");
                if route.fail_mode == FailMode::Closed && !route.shadow {
                    return Ok(json_error(
                        StatusCode::FORBIDDEN,
                        "promptwall_uninspectable",
                        "Request blocked by Promptwall: the body could not be inspected",
                        &[],
                    ));
                }
                return Ok(self.forward(with_body(parts, body), None).await);
            }
        };

        let Some(action) = outcome.action else {
            return Ok(self.forward(with_body(parts, body), None).await);
        };
        let kinds: Vec<String> = outcome.findings.keys().cloned().collect();
        tracing::info!(
            route = %route.name,
            action = action.as_str(),
            shadow = route.shadow,
            findings = ?outcome.findings.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>(),
            "sensitive data in request"
        );
        if route.shadow {
            return Ok(self.forward(with_body(parts, body), None).await);
        }
        match action {
            Action::Block => Ok(json_error(
                StatusCode::FORBIDDEN,
                "promptwall_policy_violation",
                &format!("Request blocked by Promptwall policy: {}", kinds.join(", ")),
                &kinds,
            )),
            Action::Redact => {
                let body = outcome.redacted_body.unwrap_or(body);
                Ok(self.forward(with_body(parts, body), Some(action)).await)
            }
            Action::Flag => Ok(self.forward(with_body(parts, body), Some(action)).await),
        }
    }

    async fn forward(
        &self,
        req: Request<ProxyBody>,
        action: Option<Action>,
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
                Response::from_parts(parts, body.boxed())
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
