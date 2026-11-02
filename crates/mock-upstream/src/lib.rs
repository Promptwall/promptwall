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
    // Lets tests see the path and query the upstream was asked for.
    let uri = HeaderValue::from_str(&req.uri().to_string()).ok();
    // And the API key header Azure OpenAI uses.
    let api_key = req.headers().get("api-key").cloned();
    // Lets tests check that hop-by-hop headers were not forwarded.
    let saw_hop = req.headers().contains_key("x-hop");
    // Lets tests see exactly what the upstream received.
    let echo_body = req.headers().contains_key("x-echo-body");
    // Lets tests choose the answer, streamed in pieces of `x-reply-chunk` bytes.
    let reply = req
        .headers()
        .get("x-reply")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // And a tool call after the answer text: `x-tool-call: <name> <arguments JSON>`.
    let tool_call = req
        .headers()
        .get("x-tool-call")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .map(|(name, args)| (name.to_owned(), args.to_owned()));
    // Or exact bytes (hex), for fuzzing the proxy's stream parser: sent as
    // they are, in pieces of `x-reply-chunk` bytes, as `x-raw-type`.
    let raw = req
        .headers()
        .get("x-raw-hex")
        .and_then(|v| v.to_str().ok())
        .and_then(unhex);
    let raw_type = req
        .headers()
        .get("x-raw-type")
        .cloned()
        .unwrap_or(HeaderValue::from_static("text/event-stream"));
    let reply_chunk = req
        .headers()
        .get("x-reply-chunk")
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
        .unwrap_or(5)
        .max(1);
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };
    let stream = is_stream_request(&body);

    tokio::time::sleep(config.delay).await;

    let mut resp = if let Some(raw) = raw {
        let frames: Vec<Result<Frame<Bytes>, Infallible>> = raw
            .chunks(reply_chunk)
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        let body = StreamBody::new(tokio_stream::iter(frames));
        let mut resp = Response::new(BodyExt::boxed(body));
        resp.headers_mut().insert(header::CONTENT_TYPE, raw_type);
        resp
    } else if echo_body {
        Response::new(Full::new(body.clone()).boxed())
    } else if reply.is_some() || tool_call.is_some() {
        reply_response(&reply.unwrap_or_default(), tool_call, stream, reply_chunk)
    } else if stream {
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
    if let Some(uri) = uri {
        resp.headers_mut().insert("x-request-uri", uri);
    }
    if let Some(key) = api_key {
        resp.headers_mut().insert("x-saw-api-key", key);
    }
    Ok(resp)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// An OpenAI-style answer with the given text, whole or as a stream of deltas.
/// Each streamed event is sent as two frames, split mid-event, the way TCP
/// may deliver it.
fn reply_response(
    text: &str,
    tool_call: Option<(String, String)>,
    stream: bool,
    chunk: usize,
) -> Response<BoxBody<Bytes, Infallible>> {
    if !stream {
        let mut message = serde_json::json!({"role": "assistant", "content": text});
        if let Some((name, args)) = &tool_call {
            message["tool_calls"] = serde_json::json!([{
                "id": "call_mock", "type": "function",
                "function": {"name": name, "arguments": args},
            }]);
        }
        let completion = serde_json::json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        });
        let mut resp = Response::new(Full::new(Bytes::from(completion.to_string())).boxed());
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return resp;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut deltas: Vec<serde_json::Value> = chars
        .chunks(chunk)
        .map(|piece| serde_json::json!({"content": piece.iter().collect::<String>()}))
        .collect();
    if let Some((name, args)) = tool_call {
        deltas.push(serde_json::json!({"tool_calls": [{
            "index": 0, "id": "call_mock", "type": "function",
            "function": {"name": name, "arguments": ""},
        }]}));
        let args: Vec<char> = args.chars().collect();
        deltas.extend(args.chunks(chunk).map(|piece| {
            serde_json::json!({"tool_calls": [{
                "index": 0, "function": {"arguments": piece.iter().collect::<String>()},
            }]})
        }));
    }
    let mut frames: Vec<Bytes> = Vec::new();
    for delta in deltas {
        let event = serde_json::json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": delta}],
        });
        let event = format!("data: {event}\n\n");
        let (a, b) = event.split_at(event.len() / 2);
        frames.push(Bytes::from(a.to_owned()));
        frames.push(Bytes::from(b.to_owned()));
    }
    frames.push(Bytes::from_static(DONE.as_bytes()));
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
    tokio::spawn(async move {
        for frame in frames {
            if tx.send(Ok(Frame::data(frame))).await.is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut resp = Response::new(BodyExt::boxed(StreamBody::new(ReceiverStream::new(rx))));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    resp
}

fn is_stream_request(body: &[u8]) -> bool {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    compact.windows(13).any(|w| w == b"\"stream\":true")
}
