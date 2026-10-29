//! Promptwall data plane.
//!
//! This first version is a transparent pass-through proxy: it forwards every
//! request to one upstream and streams the response back without buffering.
//! Detectors plug into [`Proxy::handle`] in later phases; keeping the
//! pass-through path lean is what the latency benchmark measures.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

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
    scheme: Scheme,
    authority: Authority,
    host: HeaderValue,
    client: Client<HttpsConnector<HttpConnector>, Incoming>,
}

impl Proxy {
    /// Creates a proxy that forwards to `upstream`, for example
    /// `https://api.openai.com`. Only the scheme and authority are used.
    pub fn new(upstream: &str) -> anyhow::Result<Self> {
        let uri: Uri = upstream.parse().context("invalid upstream URL")?;
        let (Some(scheme), Some(authority)) = (uri.scheme().cloned(), uri.authority().cloned())
        else {
            bail!("upstream URL must include a scheme and host, e.g. https://api.openai.com");
        };
        if uri.path() != "/" && !uri.path().is_empty() {
            bail!("upstream URL must not include a path");
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
                host: HeaderValue::from_str(authority.as_str())?,
                scheme,
                authority,
                client,
            }),
        })
    }

    /// Handles one request. Never fails: upstream errors become a 502.
    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<ProxyBody>, Infallible> {
        if req.uri().path() == "/healthz" {
            return Ok(text(StatusCode::OK, "ok\n"));
        }

        let (mut parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/"));
        parts.uri = match Uri::builder()
            .scheme(self.inner.scheme.clone())
            .authority(self.inner.authority.clone())
            .path_and_query(path)
            .build()
        {
            Ok(uri) => uri,
            Err(_) => return Ok(text(StatusCode::BAD_REQUEST, "invalid request URI\n")),
        };
        // The client picks the upstream HTTP version; the inbound one may differ.
        parts.version = http::Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.insert(header::HOST, self.inner.host.clone());

        match self
            .inner
            .client
            .request(Request::from_parts(parts, body))
            .await
        {
            Ok(resp) => {
                let (mut parts, body) = resp.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                Ok(Response::from_parts(parts, body.boxed()))
            }
            Err(err) => {
                tracing::warn!(error = %err, "upstream request failed");
                Ok(text(StatusCode::BAD_GATEWAY, "upstream unavailable\n"))
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

fn text(status: StatusCode, body: &'static str) -> Response<ProxyBody> {
    let mut resp = Response::new(
        Full::new(Bytes::from_static(body.as_bytes()))
            .map_err(|e| match e {})
            .boxed(),
    );
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
