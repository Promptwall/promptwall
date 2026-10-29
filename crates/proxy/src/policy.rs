//! Policy files: which traffic goes where, and what happens to sensitive data.
//!
//! The file format is specified in `docs/specs/policy-format.md`. Unknown
//! fields are rejected rather than ignored, so a rule that this version does
//! not support yet can never silently turn into no rule at all.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, ensure, Context};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::uri::{Authority, Scheme};
use http::Uri;
use promptwall_detect::{Category, Kind};
use serde::Deserialize;

/// What happens when a detector finds something. Ordered by severity.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Forward unchanged, but log the finding.
    Flag,
    /// Replace the sensitive value with a marker before forwarding.
    Redact,
    /// Reject the request with 403; nothing reaches the upstream.
    Block,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Flag => "flag",
            Action::Redact => "redact",
            Action::Block => "block",
        }
    }
}

/// What happens when a request cannot be inspected (too large, compressed, not text).
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Forward it uninspected and log a warning.
    #[default]
    Open,
    /// Reject it.
    Closed,
}

/// A validated policy, ready to route requests.
#[derive(Debug)]
pub struct Policy {
    pub routes: Vec<Route>,
}

#[derive(Debug)]
pub struct Upstream {
    pub scheme: Scheme,
    pub authority: Authority,
    pub host: HeaderValue,
}

#[derive(Debug)]
pub struct Route {
    pub name: String,
    path_prefix: Option<String>,
    headers: Vec<(HeaderName, String)>,
    pub upstream: Arc<Upstream>,
    pub fail_mode: FailMode,
    pub shadow: bool,
    /// Action per finding kind on the request. Empty means the request body is
    /// streamed through without inspection.
    pub input: HashMap<Kind, Action>,
}

impl Route {
    pub fn matches(&self, path: &str, headers: &HeaderMap) -> bool {
        self.path_prefix
            .as_deref()
            .is_none_or(|p| path.starts_with(p))
            && self
                .headers
                .iter()
                .all(|(name, value)| headers.get(name).is_some_and(|v| v == value.as_str()))
    }

    pub fn inspects_input(&self) -> bool {
        !self.input.is_empty()
    }
}

impl Upstream {
    /// Parses a base URL such as `https://api.openai.com`. Paths are not allowed:
    /// the request path is forwarded as is.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let uri: Uri = url
            .parse()
            .with_context(|| format!("invalid upstream URL {url:?}"))?;
        let (Some(scheme), Some(authority)) = (uri.scheme().cloned(), uri.authority().cloned())
        else {
            bail!(
                "upstream URL {url:?} must include a scheme and host, e.g. https://api.openai.com"
            );
        };
        ensure!(
            uri.path().is_empty() || uri.path() == "/",
            "upstream URL {url:?} must not include a path"
        );
        Ok(Self {
            host: HeaderValue::from_str(authority.as_str())?,
            scheme,
            authority,
        })
    }
}

impl Policy {
    /// One route that forwards everything to `upstream` without inspection.
    pub fn passthrough(upstream: &str) -> anyhow::Result<Self> {
        Ok(Self {
            routes: vec![Route {
                name: "default".into(),
                path_prefix: None,
                headers: Vec::new(),
                upstream: Arc::new(Upstream::parse(upstream)?),
                fail_mode: FailMode::Open,
                shadow: false,
                input: HashMap::new(),
            }],
        })
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        Self::from_yaml(&text).with_context(|| format!("invalid policy file {}", path.display()))
    }

    pub fn from_yaml(text: &str) -> anyhow::Result<Self> {
        let file: PolicyFile = serde_yaml_ng::from_str(text)?;
        ensure!(
            file.version == 1,
            "unsupported policy version {}, expected 1",
            file.version
        );
        ensure!(!file.routes.is_empty(), "policy has no routes");

        let mut upstreams = BTreeMap::new();
        for (name, spec) in file.upstreams {
            let upstream =
                Upstream::parse(&spec.url).with_context(|| format!("upstream {name:?}"))?;
            upstreams.insert(name, Arc::new(upstream));
        }

        let mut routes = Vec::with_capacity(file.routes.len());
        for spec in file.routes {
            let name = spec.name;
            let upstream = upstreams
                .get(&spec.upstream)
                .with_context(|| {
                    format!("route {name:?} uses unknown upstream {:?}", spec.upstream)
                })?
                .clone();
            let headers = spec
                .matcher
                .header
                .into_iter()
                .map(|(k, v)| {
                    let k = HeaderName::try_from(k.to_ascii_lowercase())
                        .with_context(|| format!("route {name:?} has an invalid header name"))?;
                    Ok((k, v))
                })
                .collect::<anyhow::Result<_>>()?;
            let input =
                compile_detectors(&spec.input).with_context(|| format!("route {name:?}"))?;
            routes.push(Route {
                path_prefix: spec.matcher.path,
                headers,
                upstream,
                fail_mode: spec
                    .fail_mode
                    .or(file.defaults.fail_mode)
                    .unwrap_or_default(),
                shadow: spec.shadow.or(file.defaults.shadow).unwrap_or(false),
                input,
                name,
            });
        }
        Ok(Self { routes })
    }

    pub fn route(&self, path: &str, headers: &HeaderMap) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(path, headers))
    }
}

/// Maps each finding kind to the action of the first detector entry that covers it.
fn compile_detectors(specs: &[DetectorFile]) -> anyhow::Result<HashMap<Kind, Action>> {
    let mut actions = HashMap::new();
    for spec in specs {
        let category = match spec.detector {
            DetectorName::Pii => Category::Pii,
            DetectorName::Secrets => Category::Secret,
        };
        let kinds: Vec<Kind> = if spec.entities.is_empty() {
            Kind::ALL
                .into_iter()
                .filter(|k| k.category() == category)
                .collect()
        } else {
            spec.entities
                .iter()
                .map(|e| {
                    Kind::from_entity(category, e).with_context(|| {
                        let known: Vec<_> = Kind::ALL
                            .iter()
                            .filter(|k| k.category() == category)
                            .map(|k| k.entity())
                            .collect();
                        format!("unknown entity {e:?}; known: {}", known.join(", "))
                    })
                })
                .collect::<anyhow::Result<_>>()?
        };
        for kind in kinds {
            actions.entry(kind).or_insert(spec.action);
        }
    }
    Ok(actions)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    defaults: DefaultsFile,
    upstreams: BTreeMap<String, UpstreamFile>,
    routes: Vec<RouteFile>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsFile {
    fail_mode: Option<FailMode>,
    shadow: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamFile {
    url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    name: String,
    #[serde(rename = "match", default)]
    matcher: MatchFile,
    upstream: String,
    fail_mode: Option<FailMode>,
    shadow: Option<bool>,
    #[serde(default)]
    input: Vec<DetectorFile>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatchFile {
    path: Option<String>,
    #[serde(default)]
    header: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorFile {
    detector: DetectorName,
    #[serde(default)]
    entities: Vec<String>,
    action: Action,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DetectorName {
    Pii,
    Secrets,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
version: 1
defaults:
  fail_mode: closed
upstreams:
  openai: { url: "https://api.openai.com" }
  local: { url: "http://127.0.0.1:9000" }
routes:
  - name: support-bot
    match:
      path: /v1/chat
      header: { X-Promptwall-App: support-bot }
    upstream: openai
    input:
      - detector: secrets
        action: block
      - detector: pii
        entities: [email, iban]
        action: redact
      - detector: pii
        action: flag
  - name: everything-else
    upstream: local
    shadow: true
"#;

    #[test]
    fn parses_and_compiles_example() {
        let policy = Policy::from_yaml(EXAMPLE).unwrap();
        let bot = &policy.routes[0];
        assert_eq!(bot.fail_mode, FailMode::Closed);
        assert!(!bot.shadow);
        assert_eq!(bot.input[&Kind::OpenAiKey], Action::Block);
        assert_eq!(bot.input[&Kind::Email], Action::Redact);
        // Not listed in the redact entry, so the later catch-all flag applies.
        assert_eq!(bot.input[&Kind::Phone], Action::Flag);
        let rest = &policy.routes[1];
        assert!(rest.shadow && !rest.inspects_input());
    }

    #[test]
    fn routes_by_path_and_header() {
        let policy = Policy::from_yaml(EXAMPLE).unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(
            policy.route("/v1/chat/completions", &headers).unwrap().name,
            "everything-else"
        );
        headers.insert("x-promptwall-app", HeaderValue::from_static("support-bot"));
        assert_eq!(
            policy.route("/v1/chat/completions", &headers).unwrap().name,
            "support-bot"
        );
        assert_eq!(
            policy.route("/v1/embeddings", &headers).unwrap().name,
            "everything-else"
        );
    }

    #[test]
    fn rejects_mistakes_with_clear_errors() {
        let err = |yaml: &str| format!("{:#}", Policy::from_yaml(yaml).unwrap_err());
        let base = "version: 1\nupstreams: { a: { url: 'http://x' } }\n";

        assert!(err(&format!("{base}routes: [{{ name: r, upstream: b }}]"))
            .contains("unknown upstream"));
        assert!(err(&format!(
            "{base}routes: [{{ name: r, upstream: a, input: [{{ detector: pii, entities: [ssn], action: block }}] }}]"
        ))
        .contains("unknown entity \"ssn\""));
        // A field from the spec that this version does not support yet.
        assert!(err(&format!(
            "{base}routes: [{{ name: r, upstream: a, output: [] }}]"
        ))
        .contains("unknown field"));
        assert!(err("version: 2\nupstreams: {}\nroutes: []").contains("unsupported policy version"));
        assert!(err("version: 1\nupstreams: { a: { url: 'http://x/v1' } }\nroutes: [{ name: r, upstream: a }]")
            .contains("must not include a path"));
    }
}
