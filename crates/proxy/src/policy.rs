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
use promptwall_detect::{Category, Detector, Kind};
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
    /// Built-in detectors plus this route's custom patterns and keyword lists.
    pub detector: Arc<Detector>,
    /// Classifier score at or above which a prompt counts as an injection, if
    /// the policy sets one.
    pub threshold: Option<f32>,
    /// Whether the classifier runs while the request is already on its way to
    /// the provider (only the response waits for it), or before forwarding.
    pub classifier_parallel: bool,
}

/// Classifier threshold when the policy does not set one.
pub const DEFAULT_THRESHOLD: f32 = 0.5;

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

    /// Threshold and action for the injection classifier, if this route uses it.
    /// The classifier cannot point at a span to redact, so redact blocks.
    pub fn classifier(&self) -> Option<(f32, Action)> {
        let action = match self.input.get(&Kind::InjectionClassifier)? {
            Action::Redact => Action::Block,
            action => *action,
        };
        Some((self.threshold.unwrap_or(DEFAULT_THRESHOLD), action))
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
                detector: Arc::new(Detector::new()),
                threshold: None,
                classifier_parallel: true,
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
            let Compiled {
                actions: input,
                detector,
                threshold,
                parallel,
            } = compile_detectors(&spec.input).with_context(|| format!("route {name:?}"))?;
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
                detector: Arc::new(detector),
                threshold,
                classifier_parallel: parallel.unwrap_or(true),
                name,
            });
        }
        Ok(Self { routes })
    }

    pub fn route(&self, path: &str, headers: &HeaderMap) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(path, headers))
    }
}

struct Compiled {
    actions: HashMap<Kind, Action>,
    detector: Detector,
    threshold: Option<f32>,
    parallel: Option<bool>,
}

/// Maps each finding kind to the action of the first detector entry that covers
/// it, and builds the detector with the route's custom patterns and keyword lists.
/// Also returns the classifier settings, if any are set.
fn compile_detectors(specs: &[DetectorFile]) -> anyhow::Result<Compiled> {
    let mut actions = HashMap::new();
    let mut builder = Detector::builder();
    let mut threshold = None;
    let mut parallel = None;
    for spec in specs {
        if let Some(p) = spec.parallel {
            ensure!(
                matches!(spec.detector, DetectorName::PromptInjection),
                "parallel is only allowed on the prompt_injection detector"
            );
            parallel.get_or_insert(p);
        }
        if let Some(t) = spec.threshold {
            ensure!(
                matches!(spec.detector, DetectorName::PromptInjection),
                "threshold is only allowed on the prompt_injection detector"
            );
            ensure!(
                (0.0..=1.0).contains(&t),
                "threshold must be between 0 and 1"
            );
            threshold.get_or_insert(t);
        }
        let category = match spec.detector {
            DetectorName::Pii => Category::Pii,
            DetectorName::Secrets => Category::Secret,
            DetectorName::PromptInjection => Category::Injection,
            DetectorName::Custom => {
                let name = spec
                    .name
                    .as_deref()
                    .context("a custom detector needs a name")?;
                ensure!(
                    spec.entities.is_empty(),
                    "custom detector {name:?} cannot list entities"
                );
                let kind = match (&spec.pattern, &spec.keywords) {
                    (Some(pattern), None) => builder.pattern(name, pattern)?,
                    (None, Some(words)) => builder.keywords(name, words)?,
                    _ => bail!("custom detector {name:?} needs either pattern or keywords"),
                };
                actions.entry(kind).or_insert(spec.action);
                continue;
            }
        };
        ensure!(
            spec.name.is_none() && spec.pattern.is_none() && spec.keywords.is_none(),
            "name, pattern and keywords are only allowed on custom detectors"
        );
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
    Ok(Compiled {
        actions,
        detector: builder.build(),
        threshold,
        parallel,
    })
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
    /// Custom detectors only: the name used in logs and redaction markers.
    name: Option<String>,
    /// Custom detectors only: a regular expression.
    pattern: Option<String>,
    /// Custom detectors only: case-insensitive words or phrases.
    keywords: Option<Vec<String>>,
    /// prompt_injection only: classifier score from 0 to 1 at which it fires.
    threshold: Option<f32>,
    /// prompt_injection only: run the classifier while the request is forwarded
    /// (default) or before.
    parallel: Option<bool>,
    action: Action,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DetectorName {
    Pii,
    Secrets,
    PromptInjection,
    Custom,
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
      - detector: custom
        name: employee_id
        pattern: 'EMP-[0-9]{6}'
        action: redact
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
        let custom = bot.detector.scan("ticket EMP-123456");
        assert_eq!(bot.detector.label(custom[0].kind), "custom.employee_id");
        assert_eq!(bot.input[&custom[0].kind], Action::Redact);
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
        let custom = |detector: &str| {
            err(&format!(
                "{base}routes: [{{ name: r, upstream: a, input: [{detector}] }}]"
            ))
        };
        assert!(custom("{ detector: custom, name: x, action: block }")
            .contains("either pattern or keywords"));
        assert!(
            custom("{ detector: custom, name: x, pattern: '(', action: block }")
                .contains("invalid pattern")
        );
        assert!(
            custom("{ detector: custom, name: X, keywords: [a], action: block }")
                .contains("invalid custom detector name")
        );
        assert!(custom("{ detector: pii, pattern: 'x', action: block }")
            .contains("only allowed on custom"));
        assert!(custom("{ detector: pii, threshold: 0.9, action: block }")
            .contains("only allowed on the prompt_injection"));
        assert!(
            custom("{ detector: prompt_injection, threshold: 2, action: block }")
                .contains("between 0 and 1")
        );
        assert!(err("version: 1\nupstreams: { a: { url: 'http://x/v1' } }\nroutes: [{ name: r, upstream: a }]")
            .contains("must not include a path"));
    }
}
