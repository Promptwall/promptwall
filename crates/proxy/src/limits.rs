//! Rate and token limits per route, optionally per API key or per user.
//!
//! Counters are kept in memory in fixed windows (the current UTC minute and
//! day), so each instance of the proxy counts on its own. Requests are
//! counted when they arrive; tokens when the answer has been sent, from the
//! usage the provider reports in it.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{HeaderMap, HeaderName, AUTHORIZATION};
use http_body_util::BodyExt;

use crate::ProxyBody;

/// Keys tracked before old ones are dropped.
const MAX_KEYS: usize = 100_000;

/// The `limits` of a route.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Limits {
    pub key: LimitKey,
    pub requests_per_minute: Option<u64>,
    pub requests_per_day: Option<u64>,
    pub tokens_per_minute: Option<u64>,
    pub tokens_per_day: Option<u64>,
}

/// Who a limit applies to.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum LimitKey {
    /// All requests on the route together.
    #[default]
    Route,
    /// Each API key (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`).
    ApiKey,
    /// Each value of a header, such as a user ID the app sets.
    Header(HeaderName),
}

/// A route's limits and their counters.
#[derive(Debug)]
pub struct Limiter {
    pub limits: Limits,
    counters: Mutex<HashMap<u64, Counter>>,
}

#[derive(Debug, Default)]
struct Counter {
    minute: u64,
    day: u64,
    requests_minute: u64,
    requests_day: u64,
    tokens_minute: u64,
    tokens_day: u64,
}

impl Counter {
    /// Starts new windows when the minute or day has changed.
    fn roll(&mut self, now: u64) {
        let (minute, day) = (now / 60, now / 86_400);
        if self.minute != minute {
            self.minute = minute;
            self.requests_minute = 0;
            self.tokens_minute = 0;
        }
        if self.day != day {
            self.day = day;
            self.requests_day = 0;
            self.tokens_day = 0;
        }
    }
}

/// A request over a limit.
#[derive(Debug, PartialEq)]
pub struct Exceeded {
    /// Which limit, such as `requests per minute`.
    pub what: &'static str,
    pub limit: u64,
    /// Seconds until the window ends.
    pub retry_after: u64,
}

/// An admitted request; the tokens of its answer are added through it.
#[derive(Debug)]
pub struct Ticket {
    limiter: Arc<Limiter>,
    key: u64,
    /// Size of the request body, for an estimate when the answer reports no usage.
    request_bytes: u64,
}

impl Limiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            counters: Mutex::new(HashMap::new()),
        }
    }

    /// Counts a request, or says which limit it is over. `now` is in Unix seconds.
    pub fn admit(self: &Arc<Self>, headers: &HeaderMap, now: u64) -> Result<Ticket, Exceeded> {
        let key = self.key(headers);
        let mut counters = self.counters.lock().unwrap_or_else(|p| p.into_inner());
        if counters.len() >= MAX_KEYS && !counters.contains_key(&key) {
            let day = now / 86_400;
            counters.retain(|_, c| c.day == day);
        }
        let counter = counters.entry(key).or_default();
        counter.roll(now);
        let l = &self.limits;
        let to_minute = 60 - now % 60;
        let to_day = 86_400 - now % 86_400;
        let checks = [
            (
                l.tokens_per_minute,
                counter.tokens_minute,
                "tokens per minute",
                to_minute,
            ),
            (
                l.tokens_per_day,
                counter.tokens_day,
                "tokens per day",
                to_day,
            ),
            (
                l.requests_per_minute,
                counter.requests_minute,
                "requests per minute",
                to_minute,
            ),
            (
                l.requests_per_day,
                counter.requests_day,
                "requests per day",
                to_day,
            ),
        ];
        for (limit, used, what, retry_after) in checks {
            if let Some(limit) = limit.filter(|&limit| used >= limit) {
                return Err(Exceeded {
                    what,
                    limit,
                    retry_after,
                });
            }
        }
        counter.requests_minute += 1;
        counter.requests_day += 1;
        let request_bytes = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse().ok())
            .unwrap_or(0);
        Ok(Ticket {
            limiter: self.clone(),
            key,
            request_bytes,
        })
    }

    /// Whether answers must be metered.
    pub fn counts_tokens(&self) -> bool {
        self.limits.tokens_per_minute.is_some() || self.limits.tokens_per_day.is_some()
    }

    /// A hash of who the request is from. API keys are never kept.
    fn key(&self, headers: &HeaderMap) -> u64 {
        let value = match &self.limits.key {
            LimitKey::Route => None,
            LimitKey::ApiKey => headers
                .get(AUTHORIZATION)
                .or_else(|| headers.get("x-api-key"))
                .or_else(|| headers.get("x-goog-api-key")),
            LimitKey::Header(name) => headers.get(name),
        };
        let mut hasher = DefaultHasher::new();
        value.map(|v| v.as_bytes()).hash(&mut hasher);
        hasher.finish()
    }
}

impl Ticket {
    fn add_tokens(&self, tokens: u64) {
        let mut counters = self
            .limiter
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let counter = counters.entry(self.key).or_default();
        counter.roll(now());
        counter.tokens_minute += tokens;
        counter.tokens_day += tokens;
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Passes `body` through and, once it is done or dropped, adds the tokens it
/// used to the ticket's counters.
pub fn meter(body: ProxyBody, ticket: Arc<Ticket>) -> ProxyBody {
    let mut meter = Meter {
        ticket,
        usage: Usage::default(),
        bytes: 0,
    };
    body.map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            meter.bytes += data.len() as u64;
            meter.usage.feed(data);
        }
        frame
    })
    .boxed()
}

struct Meter {
    ticket: Arc<Ticket>,
    usage: Usage,
    bytes: u64,
}

impl Drop for Meter {
    fn drop(&mut self) {
        let reported = self.usage.input + self.usage.output;
        // Without usage in the answer, about four bytes per token, counting
        // the JSON around the text too.
        let tokens = if reported > 0 {
            reported
        } else {
            (self.ticket.request_bytes + self.bytes) / 4
        };
        self.ticket.add_tokens(tokens);
    }
}

/// Token counts reported in an answer, read as it streams past. Providers
/// report counts so far (Anthropic, Gemini streams) or once at the end, so the
/// largest value of each is kept.
#[derive(Debug, Default)]
struct Usage {
    input: u64,
    output: u64,
    /// The end of the previous chunk, for a field split across chunks.
    carry: Vec<u8>,
}

/// JSON fields with input and output token counts: OpenAI chat, OpenAI
/// Responses and Anthropic, Gemini.
const INPUT_FIELDS: [&[u8]; 3] = [
    b"\"prompt_tokens\"",
    b"\"input_tokens\"",
    b"\"promptTokenCount\"",
];
const OUTPUT_FIELDS: [&[u8]; 3] = [
    b"\"completion_tokens\"",
    b"\"output_tokens\"",
    b"\"candidatesTokenCount\"",
];
const CARRY: usize = 64;

impl Usage {
    fn feed(&mut self, data: &[u8]) {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(data);
        for (fields, total) in [
            (INPUT_FIELDS, &mut self.input),
            (OUTPUT_FIELDS, &mut self.output),
        ] {
            for field in fields {
                let mut at = 0;
                while let Some(i) = find(&buf[at..], field) {
                    let start = at + i + field.len();
                    if let Some(n) = number_after(&buf[start..]) {
                        *total = (*total).max(n);
                    }
                    at = start;
                }
            }
        }
        self.carry = buf[buf.len().saturating_sub(CARRY)..].to_vec();
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The number in `: 123` at the start of `rest`, if complete.
fn number_after(rest: &[u8]) -> Option<u64> {
    let rest = rest
        .trim_ascii_start()
        .strip_prefix(b":")?
        .trim_ascii_start();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    // A number at the very end may continue in the next chunk.
    if digits == 0 || digits == rest.len() {
        return None;
    }
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(limits: Limits) -> Arc<Limiter> {
        Arc::new(Limiter::new(limits))
    }

    #[test]
    fn counts_requests_per_key_in_fixed_windows() {
        let l = limiter(Limits {
            key: LimitKey::ApiKey,
            requests_per_minute: Some(2),
            ..Limits::default()
        });
        let mut alice = HeaderMap::new();
        alice.insert(AUTHORIZATION, "Bearer a".parse().unwrap());
        let mut bob = HeaderMap::new();
        bob.insert("x-api-key", "b".parse().unwrap());
        let t = 1_000_000; // 40 s into a minute
        assert!(l.admit(&alice, t).is_ok());
        assert!(l.admit(&alice, t).is_ok());
        let over = l.admit(&alice, t + 1).unwrap_err();
        assert_eq!(
            over,
            Exceeded {
                what: "requests per minute",
                limit: 2,
                retry_after: 19
            }
        );
        assert!(l.admit(&bob, t).is_ok(), "another key has its own count");
        assert!(l.admit(&alice, t + 20).is_ok(), "a new minute starts over");
    }

    #[test]
    fn token_limits_apply_once_used_up() {
        let l = limiter(Limits {
            tokens_per_day: Some(100),
            ..Limits::default()
        });
        let headers = HeaderMap::new();
        let ticket = l.admit(&headers, now()).unwrap();
        ticket.add_tokens(60);
        assert!(l.admit(&headers, now()).is_ok());
        ticket.add_tokens(60);
        assert_eq!(l.admit(&headers, now()).unwrap_err().what, "tokens per day");
    }

    #[test]
    fn reads_usage_split_across_chunks() {
        let mut u = Usage::default();
        // Anthropic stream: input in message_start, output counts growing.
        u.feed(br#"data: {"message":{"usage":{"input_tokens":25,"output_tokens":1}}}"#);
        u.feed(br#"data: {"usage":{"output_to"#);
        u.feed(br#"kens": 4"#);
        u.feed(br#"2}}"#);
        assert_eq!((u.input, u.output), (25, 42));
        // Text that merely mentions a field is escaped inside JSON strings.
        let mut u = Usage::default();
        u.feed(br#"{"content":"say \"prompt_tokens\": 999","usage":{"prompt_tokens":7,"completion_tokens":3,"prompt_tokens_details":{"cached_tokens":5}}}"#);
        assert_eq!((u.input, u.output), (7, 3));
    }
}
