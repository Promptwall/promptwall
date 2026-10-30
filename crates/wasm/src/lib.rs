//! The Promptwall policy engine as a WebAssembly module, for the npm package
//! (packages/sdk). It runs the pattern checks (Tier 1) of a policy; the Tier 2
//! models need a Promptwall server.
//!
//! The interface is plain C ABI with JSON in and out, so the module needs no
//! generated bindings and loads with `WebAssembly.instantiate` in Node, edge
//! runtimes and browsers:
//!
//! 1. `pw_alloc(len)` reserves `len` bytes; the caller writes a JSON request
//!    there and passes it to `pw_call(ptr, len)`, which frees it.
//! 2. `pw_call` returns 0 when it worked and 1 when it failed; either way the
//!    answer, a JSON value or an error message, is at `pw_out_ptr()` and is
//!    `pw_out_len()` bytes long, until the next call.
//!
//! Requests have an `op`:
//!
//! - `load`: `{policy}` (YAML text) compiles a policy; answers `{handle,
//!   digest, routes}`.
//! - `check`: `{handle, route?, direction, text}` checks one prompt (`input`)
//!   or answer (`output`); answers the verdict `{action, findings, text}` and
//!   `models`, the Tier 2 checks the route asks for that did not run here.
//! - `inspect`: `{handle, route?, body}` checks a whole request body (JSON
//!   text) the way the proxy does; answers `{action, findings, body}`, where
//!   `body` is the redacted body, if anything was redacted.
//! - `test`: `{handle}` runs the policy's `tests` that need no model.
//! - `drop`: `{handle}` frees a policy.
//!
//! Without `route`, the route named `default` is used, or else the first.

use std::cell::RefCell;

use promptwall_engine::inspect::{self, Collect};
use promptwall_engine::policy::{FailMode, Policy, Route};
use promptwall_engine::text::{self, Sample};
use promptwall_engine::Action;
use serde::Deserialize;
use serde_json::{json, Value};

thread_local! {
    static POLICIES: RefCell<Vec<Option<Policy>>> = const { RefCell::new(Vec::new()) };
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Load {
        policy: String,
    },
    Check {
        handle: usize,
        route: Option<String>,
        direction: Direction,
        text: String,
    },
    Inspect {
        handle: usize,
        route: Option<String>,
        body: String,
    },
    Test {
        handle: usize,
    },
    Drop {
        handle: usize,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Input,
    Output,
}

/// Handles one JSON request; the JSON answer or an error message.
pub fn call(request: &[u8]) -> Result<Value, String> {
    let request: Request =
        serde_json::from_slice(request).map_err(|e| format!("invalid request: {e}"))?;
    match request {
        Request::Load { policy } => {
            let policy = Policy::from_yaml(&policy).map_err(|e| format!("{e:#}"))?;
            let answer = json!({
                "digest": policy.digest,
                "routes": policy.routes.iter().map(describe).collect::<Vec<_>>(),
            });
            let handle = POLICIES.with_borrow_mut(|all| {
                all.push(Some(policy));
                all.len()
            });
            let mut answer = answer;
            answer["handle"] = handle.into();
            Ok(answer)
        }
        Request::Check {
            handle,
            route,
            direction,
            text,
        } => with_route(handle, route.as_deref(), |route| {
            let sample = match direction {
                Direction::Input => Sample::Input(&text),
                Direction::Output => Sample::Output(&text),
            };
            let verdict = text::check(route, sample).map_err(|e| format!("{e:#}"))?;
            let mut answer = serde_json::to_value(verdict).map_err(|e| e.to_string())?;
            answer["models"] = models(route, direction).into();
            Ok(answer)
        }),
        Request::Inspect {
            handle,
            route,
            body,
        } => with_route(handle, route.as_deref(), |route| {
            let outcome = inspect::inspect(
                &route.detector,
                &route.input,
                body.as_bytes(),
                Collect::default(),
                &route.except,
            )
            .map_err(|_| "the body could not be inspected".to_owned())?;
            let body = outcome
                .redacted_body
                .filter(|_| outcome.action == Some(Action::Redact))
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            Ok(json!({
                "action": outcome.action,
                "findings": outcome.findings,
                "body": body,
                "models": models(route, Direction::Input),
            }))
        }),
        Request::Test { handle } => POLICIES.with_borrow(|all| {
            let policy = get(all, handle)?;
            Ok(Value::Array(
                policy.tests.iter().map(|t| run_test(policy, t)).collect(),
            ))
        }),
        Request::Drop { handle } => POLICIES.with_borrow_mut(|all| {
            if let Some(slot) = all.get_mut(handle.wrapping_sub(1)) {
                *slot = None;
            }
            Ok(Value::Null)
        }),
    }
}

fn get(all: &[Option<Policy>], handle: usize) -> Result<&Policy, String> {
    all.get(handle.wrapping_sub(1))
        .and_then(Option::as_ref)
        .ok_or_else(|| "no such policy; was it dropped?".to_owned())
}

fn with_route(
    handle: usize,
    name: Option<&str>,
    f: impl FnOnce(&Route) -> Result<Value, String>,
) -> Result<Value, String> {
    POLICIES.with_borrow(|all| {
        let policy = get(all, handle)?;
        let route = match name {
            Some(name) => policy.routes.iter().find(|r| r.name == name),
            None => policy
                .routes
                .iter()
                .find(|r| r.name == "default")
                .or(policy.routes.first()),
        }
        .ok_or_else(|| format!("no route named {:?}", name.unwrap_or("default")))?;
        f(route)
    })
}

/// What the SDK needs to know about a route.
fn describe(route: &Route) -> Value {
    json!({
        "name": route.name,
        "fail_mode": if route.fail_mode == FailMode::Closed { "closed" } else { "open" },
        "shadow": route.shadow,
        "input": route.inspects_input(),
        "output": route.output.is_some(),
        "models": {
            "input": models(route, Direction::Input),
            "output": models(route, Direction::Output),
        },
    })
}

/// The Tier 2 checks the route asks for in one direction, by detector name.
fn models(route: &Route, direction: Direction) -> Vec<&'static str> {
    let mut out = Vec::new();
    match direction {
        Direction::Input => {
            if route.classifier().is_some() {
                out.push("prompt_injection");
            }
            if route.safety.is_some() {
                out.push("content_safety");
            }
            if route.topics.is_some() {
                out.push("topics");
            }
            if route.pii.is_some() {
                out.push("pii");
            }
        }
        Direction::Output => {
            if let Some(rules) = &route.output {
                if rules.safety.is_some() {
                    out.push("content_safety");
                }
                if rules.pii.is_some() {
                    out.push("pii");
                }
            }
        }
    }
    out
}

/// Runs one policy test case; tests on routes that need a model are skipped,
/// since their outcome depends on it.
fn run_test(policy: &Policy, test: &promptwall_engine::policy::PolicyTest) -> Value {
    let name = |a: Option<Action>| a.map_or("allow", Action::as_str);
    let Some(route) = policy.routes.iter().find(|r| r.name == test.route) else {
        return json!({"name": test.name, "failure": format!("no route named {:?}", test.route)});
    };
    let direction = if test.output {
        Direction::Output
    } else {
        Direction::Input
    };
    // The injection classifier only adds findings, so the patterns decide
    // alone whether its tests pass; the other models can change the outcome.
    if models(route, direction)
        .iter()
        .any(|m| *m != "prompt_injection")
    {
        return json!({"name": test.name, "skipped": "needs a Tier 2 model"});
    }
    let sample = if test.output {
        Sample::Output(&test.text)
    } else {
        Sample::Input(&test.text)
    };
    let failure = match text::check(route, sample) {
        Err(err) => Some(format!("{err:#}")),
        Ok(verdict) => {
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
            if let Some(text) = test.expect_text.as_ref().filter(|t| **t != verdict.text) {
                problems.push(format!("expected text {text:?}, got {:?}", verdict.text));
            }
            (!problems.is_empty()).then(|| problems.join("; "))
        }
    };
    json!({"name": test.name, "failure": failure})
}

/// Reserves `len` bytes for a request.
#[no_mangle]
pub extern "C" fn pw_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Handles the request of `len` bytes at `ptr`, which must come from
/// [`pw_alloc`] with the same length, and frees it.
///
/// # Safety
///
/// `ptr` and `len` must be a buffer from `pw_alloc` that `len` bytes were
/// written to, used once.
#[no_mangle]
pub unsafe extern "C" fn pw_call(ptr: *mut u8, len: usize) -> u32 {
    let request = Vec::from_raw_parts(ptr, len, len);
    let (status, out) = match call(&request) {
        Ok(value) => (0, value.to_string().into_bytes()),
        Err(message) => (1, message.into_bytes()),
    };
    OUT.with_borrow_mut(|o| *o = out);
    status
}

/// Where the answer of the last call starts.
#[no_mangle]
pub extern "C" fn pw_out_ptr() -> *const u8 {
    OUT.with_borrow(|o| o.as_ptr())
}

/// How long the answer of the last call is.
#[no_mangle]
pub extern "C" fn pw_out_len() -> usize {
    OUT.with_borrow(|o| o.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version: 1
upstreams:
  openai: {url: "https://api.openai.com"}
routes:
  - name: default
    upstream: openai
    input:
      - {detector: secrets, action: block}
      - {detector: pii, entities: [email], action: redact}
    output:
      - {detector: pii, entities: [email], action: redact}
tests:
  - name: email redacted
    route: default
    input: "mail jane@corp.io"
    expect: {action: redact, text: "mail [REDACTED:EMAIL]"}
"#;

    fn ask(request: Value) -> Value {
        call(request.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn checks_text_and_bodies_like_the_proxy() {
        let handle = ask(json!({"op": "load", "policy": POLICY}))["handle"].clone();
        let v = ask(
            json!({"op": "check", "handle": handle, "direction": "input", "text": "mail jane@corp.io"}),
        );
        assert_eq!(v["action"], "redact");
        assert_eq!(v["text"], "mail [REDACTED:EMAIL]");
        assert_eq!(v["findings"]["pii.email"], 1);

        let v = ask(
            json!({"op": "check", "handle": handle, "direction": "output", "text": "it is jane@corp.io"}),
        );
        assert_eq!(v["text"], "it is [REDACTED:EMAIL]");

        let body = json!({"model": "m", "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]});
        let v = ask(json!({"op": "inspect", "handle": handle, "body": body.to_string()}));
        assert_eq!(v["action"], "block");
        assert_eq!(v["body"], Value::Null);

        let tests = ask(json!({"op": "test", "handle": handle}));
        assert_eq!(tests[0]["failure"], Value::Null, "{tests}");

        ask(json!({"op": "drop", "handle": handle}));
        assert!(call(
            json!({"op": "test", "handle": handle})
                .to_string()
                .as_bytes()
        )
        .is_err());
    }

    #[test]
    fn reports_policy_errors() {
        let err = call(
            json!({"op": "load", "policy": "version: 2"})
                .to_string()
                .as_bytes(),
        );
        assert!(err.is_err());
    }
}
