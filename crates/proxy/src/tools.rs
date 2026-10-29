//! Tool-call firewall: which tools a model may be offered and may call, and
//! which argument values it may pass to them.
//!
//! Tools offered in a request are checked before it is forwarded, which also
//! covers tools the provider runs itself (web search, code execution). Tool
//! calls in an answer are checked before the app sees them: a JSON answer as
//! a whole, a streamed answer by holding back the tool-call events until the
//! stream ends and the arguments are complete.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::policy::Action;

/// Finding labels, as they appear in logs and error bodies.
pub const NOT_ALLOWED: &str = "tool.not_allowed";
pub const ARGUMENT: &str = "tool.argument";
pub const MALFORMED: &str = "tool.malformed_arguments";

/// The `tools` section of a route.
#[derive(Debug)]
pub struct ToolRules {
    /// Tool names that may be used; `None` allows every name not denied.
    pub allow: Option<Vec<String>>,
    pub deny: Vec<String>,
    pub arguments: Vec<ArgumentRule>,
    pub action: Action,
}

/// Limits on the values one argument of a tool may take.
#[derive(Debug)]
pub struct ArgumentRule {
    /// Tool name pattern.
    pub tool: String,
    /// Path to the argument, keys separated by dots; arrays are searched
    /// element by element.
    pub field: Vec<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub allow_domains: Vec<String>,
}

/// A tool call from the model. `arguments` is `None` when they are not valid JSON.
#[derive(Debug)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Option<Value>,
}

impl ToolRules {
    /// Whether the tool `name` may be offered and called.
    pub fn allows(&self, name: &str) -> bool {
        self.allow
            .as_ref()
            .is_none_or(|allow| allow.iter().any(|p| glob(p, name)))
            && !self.deny.iter().any(|p| glob(p, name))
    }

    /// Labels of the rules `call` breaks, empty if none.
    pub fn check(&self, call: &ToolCall) -> Vec<&'static str> {
        if !self.allows(&call.name) {
            return vec![NOT_ALLOWED];
        }
        let rules: Vec<&ArgumentRule> = self
            .arguments
            .iter()
            .filter(|r| glob(&r.tool, &call.name))
            .collect();
        if rules.is_empty() {
            return Vec::new();
        }
        let Some(args) = &call.arguments else {
            return vec![MALFORMED];
        };
        let broken = rules.iter().any(|rule| {
            let mut values = Vec::new();
            values_at(args, &rule.field, &mut values);
            values.iter().any(|v| !rule.accepts(v))
        });
        if broken {
            vec![ARGUMENT]
        } else {
            Vec::new()
        }
    }
}

impl ArgumentRule {
    fn accepts(&self, value: &str) -> bool {
        (self.allow.is_empty() || self.allow.iter().any(|p| glob(p, value)))
            && !self.deny.iter().any(|p| glob(p, value))
            && (self.allow_domains.is_empty() || {
                let host = host_of(value);
                self.allow_domains
                    .iter()
                    .any(|d| host == *d || host.ends_with(&format!(".{d}")))
            })
    }
}

/// Case-insensitive match where `*` stands for any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.to_lowercase(), text.to_lowercase());
    let mut parts = p.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = t.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty();
    };
    for part in middle {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

/// The host of a URL (`https://host/...`), an email address, or a bare host.
fn host_of(value: &str) -> String {
    let value = value.trim();
    let rest = match value.split_once("://") {
        Some((_, rest)) => rest,
        None => value.rsplit('@').next().unwrap_or_default(),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host.strip_prefix('[').map_or_else(
        || host.split(':').next().unwrap_or_default(),
        |h| h.split(']').next().unwrap_or_default(),
    );
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// String forms of the values at `path` in `value`.
fn values_at(value: &Value, path: &[String], out: &mut Vec<String>) {
    match (value, path.split_first()) {
        (Value::Array(items), _) => items.iter().for_each(|v| values_at(v, path, out)),
        (Value::Object(map), Some((key, rest))) => {
            if let Some(v) = map.get(key) {
                values_at(v, rest, out);
            }
        }
        (Value::String(s), None) => out.push(s.clone()),
        (Value::Number(_) | Value::Bool(_), None) => out.push(value.to_string()),
        _ => {}
    }
}

/// Names of the tools a request offers the model: functions it defines and
/// tools the provider runs itself, named by their type (`web_search_preview`,
/// `code_interpreter`, `googleSearch`).
pub fn offered(body: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for tool in body["tools"].as_array().into_iter().flatten() {
        if let Some(name) = tool["function"]["name"].as_str().or(tool["name"].as_str()) {
            names.push(name.to_owned());
        } else if let Some(declared) = tool["functionDeclarations"]
            .as_array()
            .or(tool["function_declarations"].as_array())
        {
            names.extend(
                declared
                    .iter()
                    .filter_map(|d| d["name"].as_str().map(str::to_owned)),
            );
        } else if let Some(kind) = tool["type"].as_str() {
            names.push(kind.to_owned());
        } else if let Some(key) = tool.as_object().and_then(|m| m.keys().next()) {
            names.push(key.clone());
        }
    }
    for function in body["functions"].as_array().into_iter().flatten() {
        if let Some(name) = function["name"].as_str() {
            names.push(name.to_owned());
        }
    }
    names
}

/// Tool calls in a whole (not streamed) answer: OpenAI Chat Completions and
/// Responses, Anthropic Messages and Gemini.
pub fn calls(answer: &Value) -> Vec<ToolCall> {
    let mut out = Vec::new();
    collect_calls(answer, &mut out);
    out
}

fn collect_calls(value: &Value, out: &mut Vec<ToolCall>) {
    match value {
        Value::Array(items) => items.iter().for_each(|v| collect_calls(v, out)),
        Value::Object(map) => {
            let name = map.get("name").and_then(Value::as_str);
            let kind = map.get("type").and_then(Value::as_str);
            let call = match (kind, name) {
                // Anthropic `tool_use` blocks and Responses `function_call` items.
                (Some("tool_use"), Some(name)) => Some((name, map.get("input"))),
                (Some("function_call"), Some(name)) => Some((name, map.get("arguments"))),
                _ => None,
            };
            if let Some((name, args)) = call {
                out.push(call_of(name, args));
                return;
            }
            for (key, v) in map {
                match key.as_str() {
                    // Chat Completions `tool_calls[].function`, legacy
                    // `function_call`, Gemini `functionCall`.
                    "function" | "function_call" | "functionCall" => {
                        if let Some(name) = v["name"].as_str() {
                            let args = v.get("arguments").or(v.get("args"));
                            out.push(call_of(name, args));
                            continue;
                        }
                        collect_calls(v, out);
                    }
                    _ => collect_calls(v, out),
                }
            }
        }
        _ => {}
    }
}

/// A call from its name and arguments, which are either a JSON object or a
/// string holding one.
fn call_of(name: &str, args: Option<&Value>) -> ToolCall {
    let arguments = match args {
        None | Some(Value::Null) => Some(Value::Object(Default::default())),
        Some(Value::String(s)) if s.trim().is_empty() => Some(Value::Object(Default::default())),
        Some(Value::String(s)) => serde_json::from_str(s).ok(),
        Some(v) => Some(v.clone()),
    };
    ToolCall {
        name: name.to_owned(),
        arguments,
    }
}

/// Tool calls assembled from the events of a streamed answer.
#[derive(Debug, Default)]
pub struct StreamCalls {
    /// Name and argument text per call, keyed by where the call sits.
    calls: BTreeMap<String, (String, String)>,
    gemini: usize,
}

impl StreamCalls {
    /// Adds what one event says about tool calls. Returns whether it had any.
    pub fn feed(&mut self, event: &Value) -> bool {
        let mut seen = false;
        // Chat Completions: `choices[].delta.tool_calls[]` with the name in the
        // first piece and the arguments spread over the following ones.
        for choice in event["choices"].as_array().into_iter().flatten() {
            let delta = &choice["delta"];
            for call in delta["tool_calls"].as_array().into_iter().flatten() {
                let key = format!("c{}:{}", choice["index"], call["index"]);
                self.append(
                    key,
                    call["function"]["name"].as_str(),
                    call["function"]["arguments"].as_str(),
                );
                seen = true;
            }
            if let Some(f) = delta.get("function_call") {
                let key = format!("c{}:f", choice["index"]);
                self.append(key, f["name"].as_str(), f["arguments"].as_str());
                seen = true;
            }
        }
        match event["type"].as_str() {
            // Anthropic Messages.
            Some("content_block_start") if event["content_block"]["type"] == "tool_use" => {
                let key = format!("a{}", event["index"]);
                self.append(key, event["content_block"]["name"].as_str(), None);
                seen = true;
            }
            Some("content_block_delta") if event["delta"]["type"] == "input_json_delta" => {
                let key = format!("a{}", event["index"]);
                self.append(key, None, event["delta"]["partial_json"].as_str());
                seen = true;
            }
            // OpenAI Responses.
            Some("response.output_item.added" | "response.output_item.done")
                if event["item"]["type"] == "function_call" =>
            {
                let key = format!("r{}", event["output_index"]);
                let entry = self.calls.entry(key).or_default();
                if let Some(name) = event["item"]["name"].as_str() {
                    entry.0 = name.to_owned();
                }
                if let Some(args) = event["item"]["arguments"]
                    .as_str()
                    .filter(|a| !a.is_empty())
                {
                    entry.1 = args.to_owned();
                }
                seen = true;
            }
            Some("response.function_call_arguments.delta") => {
                let key = format!("r{}", event["output_index"]);
                self.append(key, None, event["delta"].as_str());
                seen = true;
            }
            Some("response.function_call_arguments.done") => {
                let key = format!("r{}", event["output_index"]);
                if let Some(args) = event["arguments"].as_str() {
                    self.calls.entry(key).or_default().1 = args.to_owned();
                }
                seen = true;
            }
            _ => {}
        }
        // Gemini sends each call whole.
        for candidate in event["candidates"].as_array().into_iter().flatten() {
            for part in candidate["content"]["parts"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let Some(f) = part.get("functionCall") {
                    self.gemini += 1;
                    let args = serde_json::to_string(&f["args"]).unwrap_or_default();
                    self.append(format!("g{}", self.gemini), f["name"].as_str(), Some(&args));
                    seen = true;
                }
            }
        }
        seen
    }

    fn append(&mut self, key: String, name: Option<&str>, args: Option<&str>) {
        let entry = self.calls.entry(key).or_default();
        if let Some(name) = name {
            entry.0.push_str(name);
        }
        if let Some(args) = args {
            entry.1.push_str(args);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// The calls with their complete arguments.
    pub fn finish(&self) -> Vec<ToolCall> {
        self.calls
            .values()
            .map(|(name, args)| call_of(name, Some(&Value::String(args.clone()))))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules() -> ToolRules {
        ToolRules {
            allow: Some(vec![
                "get_weather".into(),
                "send_email".into(),
                "fetch_*".into(),
            ]),
            deny: vec!["fetch_internal".into()],
            arguments: vec![
                ArgumentRule {
                    tool: "send_email".into(),
                    field: vec!["to".into()],
                    allow: vec!["*@acme.example".into()],
                    deny: Vec::new(),
                    allow_domains: Vec::new(),
                },
                ArgumentRule {
                    tool: "fetch_*".into(),
                    field: vec!["request".into(), "url".into()],
                    allow: Vec::new(),
                    deny: Vec::new(),
                    allow_domains: vec!["acme.example".into()],
                },
            ],
            action: Action::Block,
        }
    }

    fn call(name: &str, args: Value) -> ToolCall {
        ToolCall {
            name: name.into(),
            arguments: Some(args),
        }
    }

    #[test]
    fn checks_names_and_arguments() {
        let r = rules();
        assert!(r
            .check(&call("get_weather", json!({"city": "Berlin"})))
            .is_empty());
        assert_eq!(r.check(&call("delete_user", json!({}))), [NOT_ALLOWED]);
        assert_eq!(r.check(&call("fetch_internal", json!({}))), [NOT_ALLOWED]);
        assert!(r
            .check(&call("send_email", json!({"to": "Bob@ACME.example"})))
            .is_empty());
        assert_eq!(
            r.check(&call("send_email", json!({"to": "x@evil.example"}))),
            [ARGUMENT]
        );
        // Every element of an array must pass.
        assert_eq!(
            r.check(&call(
                "send_email",
                json!({"to": ["a@acme.example", "b@evil.example"]})
            )),
            [ARGUMENT]
        );
        assert!(r
            .check(&call(
                "fetch_page",
                json!({"request": {"url": "https://docs.acme.example/a"}})
            ))
            .is_empty());
        assert_eq!(
            r.check(&call(
                "fetch_page",
                json!({"request": {"url": "https://acme.example.evil.io/"}})
            )),
            [ARGUMENT]
        );
        let broken = ToolCall {
            name: "send_email".into(),
            arguments: None,
        };
        assert_eq!(r.check(&broken), [MALFORMED]);
    }

    #[test]
    fn globs() {
        assert!(glob("*@acme.example", "a@acme.example"));
        assert!(glob("fetch_*", "fetch_page"));
        assert!(glob("*drop table*", "x; DROP TABLE users"));
        assert!(!glob("fetch_*", "prefetch_page"));
        assert!(glob("a*b*c", "aXbYc") && !glob("a*b*c", "aXbY"));
    }

    #[test]
    fn finds_offered_tools() {
        let body = json!({"tools": [
            {"type": "function", "function": {"name": "get_weather"}},
            {"type": "function", "name": "lookup"},
            {"name": "search", "input_schema": {}},
            {"type": "web_search_preview"},
            {"functionDeclarations": [{"name": "a"}, {"name": "b"}]},
            {"googleSearch": {}},
        ]});
        assert_eq!(
            offered(&body),
            [
                "get_weather",
                "lookup",
                "search",
                "web_search_preview",
                "a",
                "b",
                "googleSearch"
            ]
        );
    }

    #[test]
    fn finds_calls_in_whole_answers() {
        let names = |v: Value| {
            calls(&v)
                .into_iter()
                .map(|c| (c.name, c.arguments))
                .collect::<Vec<_>>()
        };
        let openai = json!({"choices": [{"message": {"tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "send_email", "arguments": "{\"to\":\"a@b.c\"}"}}
        ]}}]});
        assert_eq!(
            names(openai),
            [("send_email".into(), Some(json!({"to": "a@b.c"})))]
        );
        let anthropic = json!({"content": [{"type": "text", "text": "ok"}, {"type": "tool_use", "id": "t", "name": "get_weather", "input": {"city": "Rome"}}]});
        assert_eq!(
            names(anthropic),
            [("get_weather".into(), Some(json!({"city": "Rome"})))]
        );
        let responses =
            json!({"output": [{"type": "function_call", "name": "lookup", "arguments": "{}"}]});
        assert_eq!(names(responses), [("lookup".into(), Some(json!({})))]);
        let gemini = json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "f", "args": {"x": 1}}}]}}]});
        assert_eq!(names(gemini), [("f".into(), Some(json!({"x": 1})))]);
        let broken = json!({"choices": [{"message": {"tool_calls": [{"function": {"name": "f", "arguments": "{\"x\": "}}]}}]});
        assert_eq!(names(broken), [("f".into(), None)]);
    }

    #[test]
    fn assembles_streamed_calls() {
        let mut s = StreamCalls::default();
        assert!(!s.feed(&json!({"choices": [{"index": 0, "delta": {"content": "hi"}}]})));
        for event in [
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"name": "send_email", "arguments": ""}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"to\":"}}]}}]}),
            json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": "\"x@evil.example\"}"}}]}}]}),
            json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "name": "get_weather", "input": {}}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"city\": \"Rome\"}"}}),
        ] {
            assert!(s.feed(&event));
        }
        let calls: Vec<_> = s
            .finish()
            .into_iter()
            .map(|c| (c.name, c.arguments))
            .collect();
        assert_eq!(
            calls,
            [
                ("get_weather".into(), Some(json!({"city": "Rome"}))),
                ("send_email".into(), Some(json!({"to": "x@evil.example"}))),
            ]
        );
    }
}
