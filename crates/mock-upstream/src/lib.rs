//! A mock OpenAI-compatible chat completions endpoint.
//!
//! It reads the whole request, waits a fixed delay, then answers either with
//! one JSON body or, when the request contains `"stream": true`, with a
//! server-sent event stream of fixed-size chunks. Fixed timings make the
//! difference between a direct call and a proxied call measurable.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Clone, Debug)]
pub struct Config {
    /// Time before the response (or the first stream chunk) is sent.
    pub delay: Duration,
    /// Number of chunks in a streamed response.
    pub chunks: usize,
    /// Time between streamed chunks.
    pub chunk_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            delay: Duration::from_millis(50),
            chunks: 20,
            chunk_interval: Duration::from_millis(20),
        }
    }
}

const COMPLETION: &str = r#"{"id":"chatcmpl-mock","object":"chat.completion","model":"mock","choices":[{"index":0,"message":{"role":"assistant","content":"Hello from the mock upstream."},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":6,"total_tokens":7}}"#;
const CHUNK: &str = "data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\",\"model\":\"mock\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token \"}}]}\n\n";
const DONE: &str = "data: [DONE]\n\n";

/// Binds `addr` and serves the mock in a background task. Returns the bound address.
pub async fn spawn(addr: SocketAddr, config: Config) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(serve(listener, config));
    Ok(local)
}

/// Serves the mock on `listener` forever.
pub async fn serve(listener: TcpListener, config: Config) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let _ = stream.set_nodelay(true);
        let config = config.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, config.clone()));
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    config: Config,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let echo = req.headers().get("x-echo").cloned();
    // Lets tests check that hop-by-hop headers were not forwarded.
    let saw_hop = req.headers().contains_key("x-hop");
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };
    let stream = is_stream_request(&body);

    tokio::time::sleep(config.delay).await;

    let mut resp = if stream {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
        tokio::spawn(async move {
            for i in 0..config.chunks {
                if i > 0 {
                    tokio::time::sleep(config.chunk_interval).await;
                }
                if tx
                    .send(Ok(Frame::data(Bytes::from_static(CHUNK.as_bytes()))))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = tx
                .send(Ok(Frame::data(Bytes::from_static(DONE.as_bytes()))))
                .await;
        });
        let body = StreamBody::new(ReceiverStream::new(rx));
        let mut resp = Response::new(BodyExt::boxed(body));
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        resp
    } else {
        let mut resp = Response::new(Full::new(Bytes::from_static(COMPLETION.as_bytes())).boxed());
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    };
    *resp.status_mut() = StatusCode::OK;
    if let Some(v) = echo {
        resp.headers_mut().insert("x-echo", v);
    }
    if saw_hop {
        resp.headers_mut()
            .insert("x-saw-hop", HeaderValue::from_static("1"));
    }
    resp.headers_mut()
        .insert("x-request-bytes", HeaderValue::from(body.len()));
    Ok(resp)
}

fn is_stream_request(body: &[u8]) -> bool {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    compact.windows(13).any(|w| w == b"\"stream\":true")
}
