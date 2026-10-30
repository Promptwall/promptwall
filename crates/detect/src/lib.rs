//! Tier 1 detectors: pattern-based PII, secret and prompt-injection detection,
//! and checks on model output (exfiltration links, system prompt leaks).
//! [`Detector::scan_evasions`] finds injections hidden by encoding, look-alike
//! characters or spacing.
//!
//! Every detector is a regular expression plus a validator (a checksum, a
//! valid range) that removes false positives, and for generic formats a
//! context keyword that must appear just before the value. A [`RegexSet`]
//! first finds which patterns occur at all, so text without sensitive data is
//! scanned in a single pass.
//!
//! Policies can add their own patterns and keyword lists with [`Builder`].
//!
//! The crate does no I/O and has no async code so that it can be compiled to
//! WebAssembly and run inside the npm package as well as the proxy.

mod evasion;
mod leak;
mod rules;

use std::fmt;

use regex::{Regex, RegexSet};

pub use leak::SystemPromptIndex;
use rules::{Validator, RULES};

/// What a finding is. Built-in kinds have stable IDs from [`Kind::id`], which
/// policies and logs refer to. Custom kinds are numbered per [`Detector`]; use
/// [`Detector::label`] to name them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Email,
    Phone,
    Iban,
    CreditCard,
    Bic,
    VatId,
    DeTaxId,
    NlBsn,
    EsDni,
    ItFiscalCode,
    FrNir,
    PlPesel,
    UkNino,
    UsSsn,
    IpAddress,
    AnthropicKey,
    OpenAiKey,
    AwsAccessKey,
    GitHubToken,
    SlackToken,
    StripeKey,
    GoogleApiKey,
    AzureStorageKey,
    GcpServiceAccount,
    HuggingFaceToken,
    NpmToken,
    TwilioKey,
    SendGridKey,
    PrivateKey,
    Jwt,
    UrlCredentials,
    Password,
    IgnorePrevious,
    RoleOverride,
    PromptExtraction,
    ChatTemplate,
    HiddenText,
    /// Instructions aimed at an AI inside content it reads: a web page, an
    /// email or tool output ("if you are an AI reading this", "do not tell the
    /// user").
    IndirectInstruction,
    /// An injection hidden by encoding, look-alike characters or spacing; see
    /// [`Detector::scan_evasions`].
    Obfuscated,
    /// A long written-out dialogue in one message that primes the model to
    /// answer anything (many-shot jailbreak).
    ManyShot,
    /// Verdict of the Tier 2 injection classifier. This crate never reports it;
    /// it exists so policies can name it next to the pattern-based kinds.
    InjectionClassifier,
    /// A markdown image pointing at another site: rendering it sends a request
    /// there, with whatever the model put into the URL.
    MarkdownImage,
    HtmlImage,
    /// A link whose query string carries a long encoded value.
    UrlWithData,
    /// The answer repeats the app's system prompt; see [`SystemPromptIndex`].
    SystemPromptLeak,
    /// A pattern or keyword list defined in a policy.
    Custom(u16),
}

/// Broad family a [`Kind`] belongs to; each maps to one policy detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Pii,
    Secret,
    Injection,
    /// Model output that would send data to another site when rendered.
    Exfiltration,
    /// Model output that repeats the app's own instructions.
    Leak,
    Custom,
}

impl Kind {
    /// All built-in kinds.
    pub const ALL: [Kind; 45] = [
        Kind::Email,
        Kind::Phone,
        Kind::Iban,
        Kind::CreditCard,
        Kind::Bic,
        Kind::VatId,
        Kind::DeTaxId,
        Kind::NlBsn,
        Kind::EsDni,
        Kind::ItFiscalCode,
        Kind::FrNir,
        Kind::PlPesel,
        Kind::UkNino,
        Kind::UsSsn,
        Kind::IpAddress,
        Kind::AnthropicKey,
        Kind::OpenAiKey,
        Kind::AwsAccessKey,
        Kind::GitHubToken,
        Kind::SlackToken,
        Kind::StripeKey,
        Kind::GoogleApiKey,
        Kind::AzureStorageKey,
        Kind::GcpServiceAccount,
        Kind::HuggingFaceToken,
        Kind::NpmToken,
        Kind::TwilioKey,
        Kind::SendGridKey,
        Kind::PrivateKey,
        Kind::Jwt,
        Kind::UrlCredentials,
        Kind::Password,
        Kind::IgnorePrevious,
        Kind::RoleOverride,
        Kind::PromptExtraction,
        Kind::ChatTemplate,
        Kind::HiddenText,
        Kind::IndirectInstruction,
        Kind::Obfuscated,
        Kind::ManyShot,
        Kind::InjectionClassifier,
        Kind::MarkdownImage,
        Kind::HtmlImage,
        Kind::UrlWithData,
        Kind::SystemPromptLeak,
    ];

    pub fn category(self) -> Category {
        match self {
            Kind::Email
            | Kind::Phone
            | Kind::Iban
            | Kind::CreditCard
            | Kind::Bic
            | Kind::VatId
            | Kind::DeTaxId
            | Kind::NlBsn
            | Kind::EsDni
            | Kind::ItFiscalCode
            | Kind::FrNir
            | Kind::PlPesel
            | Kind::UkNino
            | Kind::UsSsn
            | Kind::IpAddress => Category::Pii,
            Kind::IgnorePrevious
            | Kind::RoleOverride
            | Kind::PromptExtraction
            | Kind::ChatTemplate
            | Kind::HiddenText
            | Kind::IndirectInstruction
            | Kind::Obfuscated
            | Kind::ManyShot
            | Kind::InjectionClassifier => Category::Injection,
            Kind::MarkdownImage | Kind::HtmlImage | Kind::UrlWithData => Category::Exfiltration,
            Kind::SystemPromptLeak => Category::Leak,
            Kind::Custom(_) => Category::Custom,
            _ => Category::Secret,
        }
    }

    /// Entity name used in policies, e.g. `email` or `openai_key`.
    /// Custom kinds have no fixed name; see [`Detector::label`].
    pub fn entity(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Phone => "phone",
            Kind::Iban => "iban",
            Kind::CreditCard => "credit_card",
            Kind::Bic => "bic",
            Kind::VatId => "vat_id",
            Kind::DeTaxId => "de_tax_id",
            Kind::NlBsn => "nl_bsn",
            Kind::EsDni => "es_dni",
            Kind::ItFiscalCode => "it_fiscal_code",
            Kind::FrNir => "fr_nir",
            Kind::PlPesel => "pl_pesel",
            Kind::UkNino => "uk_nino",
            Kind::UsSsn => "us_ssn",
            Kind::IpAddress => "ip_address",
            Kind::AnthropicKey => "anthropic_key",
            Kind::OpenAiKey => "openai_key",
            Kind::AwsAccessKey => "aws_access_key",
            Kind::GitHubToken => "github_token",
            Kind::SlackToken => "slack_token",
            Kind::StripeKey => "stripe_key",
            Kind::GoogleApiKey => "google_api_key",
            Kind::AzureStorageKey => "azure_storage_key",
            Kind::GcpServiceAccount => "gcp_service_account",
            Kind::HuggingFaceToken => "huggingface_token",
            Kind::NpmToken => "npm_token",
            Kind::TwilioKey => "twilio_key",
            Kind::SendGridKey => "sendgrid_key",
            Kind::PrivateKey => "private_key",
            Kind::Jwt => "jwt",
            Kind::UrlCredentials => "url_credentials",
            Kind::Password => "password",
            Kind::IgnorePrevious => "ignore_previous",
            Kind::RoleOverride => "role_override",
            Kind::PromptExtraction => "prompt_extraction",
            Kind::ChatTemplate => "chat_template",
            Kind::HiddenText => "hidden_text",
            Kind::IndirectInstruction => "indirect",
            Kind::Obfuscated => "obfuscated",
            Kind::ManyShot => "many_shot",
            Kind::InjectionClassifier => "classifier",
            Kind::MarkdownImage => "markdown_image",
            Kind::HtmlImage => "html_image",
            Kind::UrlWithData => "url_with_data",
            Kind::SystemPromptLeak => "system_prompt",
            Kind::Custom(_) => "custom",
        }
    }

    /// Stable rule ID, e.g. `pii.email` or `secret.openai_key`.
    pub fn id(self) -> String {
        let prefix = match self.category() {
            Category::Pii => "pii",
            Category::Secret => "secret",
            Category::Injection => "injection",
            Category::Exfiltration => "exfiltration",
            Category::Leak => "leak",
            Category::Custom => "custom",
        };
        format!("{prefix}.{}", self.entity())
    }

    /// Looks up a built-in kind by its policy entity name within a category.
    pub fn from_entity(category: Category, name: &str) -> Option<Kind> {
        Kind::ALL
            .into_iter()
            .find(|k| k.category() == category && k.entity() == name)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id())
    }
}

/// One match: `text[start..end]` is the sensitive value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

/// A custom detector could not be added.
#[derive(Debug)]
pub enum BuildError {
    InvalidName(String),
    InvalidPattern(String, regex::Error),
    EmptyKeywords(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::InvalidName(n) => write!(
                f,
                "invalid custom detector name {n:?}: use lowercase letters, digits and _"
            ),
            BuildError::InvalidPattern(n, e) => write!(f, "invalid pattern for {n:?}: {e}"),
            BuildError::EmptyKeywords(n) => write!(f, "keyword list {n:?} is empty"),
        }
    }
}

impl std::error::Error for BuildError {}

struct Rule {
    kind: Kind,
    regex: Regex,
    validate: Validator,
    context: Option<Regex>,
    /// Whether capture group 1 holds the value (otherwise the whole match).
    grouped: bool,
}

/// How far before a value its context keyword may appear, in bytes.
const CONTEXT_WINDOW: usize = 48;

/// Adds custom patterns and keyword lists to the built-in detectors.
#[derive(Default)]
pub struct Builder {
    custom: Vec<(String, String)>,
}

impl Builder {
    /// Adds a regular expression. Returns the kind its findings will have.
    pub fn pattern(&mut self, name: &str, pattern: &str) -> Result<Kind, BuildError> {
        check_name(name)?;
        Regex::new(pattern).map_err(|e| BuildError::InvalidPattern(name.into(), e))?;
        self.custom.push((name.into(), pattern.into()));
        Ok(Kind::Custom(self.custom.len() as u16 - 1))
    }

    /// Adds a case-insensitive list of words or phrases, matched as whole words.
    pub fn keywords(&mut self, name: &str, words: &[String]) -> Result<Kind, BuildError> {
        check_name(name)?;
        let words: Vec<String> = words
            .iter()
            .map(|w| w.trim())
            .filter(|w| !w.is_empty())
            .map(|w| {
                let edge =
                    |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                let start = if edge(w.chars().next()) {
                    r"(?-u:\b)"
                } else {
                    ""
                };
                let end = if edge(w.chars().last()) {
                    r"(?-u:\b)"
                } else {
                    ""
                };
                format!("{start}{}{end}", regex::escape(w))
            })
            .collect();
        if words.is_empty() {
            return Err(BuildError::EmptyKeywords(name.into()));
        }
        self.pattern(name, &format!("(?i)(?:{})", words.join("|")))
    }

    pub fn build(self) -> Detector {
        let mut sources: Vec<String> = RULES
            .iter()
            .map(|r| r.pattern.replace(r"\b", r"(?-u:\b)"))
            .collect();
        sources.extend(self.custom.iter().map(|(_, p)| p.clone()));
        let set = RegexSet::new(&sources).expect("patterns were validated");

        let mut rules: Vec<Rule> = RULES
            .iter()
            .zip(&sources)
            .map(|(spec, src)| {
                let regex = Regex::new(src).expect("built-in pattern compiles");
                Rule {
                    kind: spec.kind,
                    grouped: regex.captures_len() > 1,
                    regex,
                    validate: spec.validate,
                    context: spec
                        .context
                        .map(|c| Regex::new(&format!("(?i){c}")).expect("context compiles")),
                }
            })
            .collect();
        for (i, (_, src)) in self.custom.iter().enumerate() {
            rules.push(Rule {
                kind: Kind::Custom(i as u16),
                regex: Regex::new(src).expect("pattern was validated"),
                validate: |s| Some(s.len()),
                context: None,
                grouped: false,
            });
        }
        let injection_rules: Vec<usize> = (0..RULES.len())
            .filter(|&i| RULES[i].kind.category() == Category::Injection)
            .collect();
        let injection_set = RegexSet::new(injection_rules.iter().map(|&i| &sources[i]))
            .expect("patterns were validated");
        Detector {
            set,
            rules,
            injection_set,
            injection_rules,
            custom_names: self.custom.into_iter().map(|(n, _)| n).collect(),
        }
    }
}

fn check_name(name: &str) -> Result<(), BuildError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(BuildError::InvalidName(name.into()))
    }
}

/// Compiled set of detectors. Build once and share; scanning is `&self`.
pub struct Detector {
    set: RegexSet,
    rules: Vec<Rule>,
    /// The injection rules alone, for the evasion checks; indices into `rules`.
    injection_set: RegexSet,
    injection_rules: Vec<usize>,
    custom_names: Vec<String>,
}

impl fmt::Debug for Detector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Detector")
            .field("rules", &self.rules.len())
            .field("custom", &self.custom_names)
            .finish()
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    /// The built-in detectors only.
    pub fn new() -> Self {
        Builder::default().build()
    }

    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Finds all sensitive values in `text`, sorted by position, without overlaps.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let found = self.find(&self.set, None, text);
        let hidden = self.scan_hidden(text);
        if hidden.is_empty() {
            return found;
        }
        // A hidden value overlapping one found as written is the same value.
        let mut all: Vec<Finding> = found;
        all.extend(hidden);
        all.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
        let mut out: Vec<Finding> = Vec::with_capacity(all.len());
        for f in all {
            if out.last().is_none_or(|last| f.start >= last.end) {
                out.push(f);
            }
        }
        out
    }

    /// Like [`Detector::scan`] with the injection rules only.
    fn scan_injection(&self, text: &str) -> Vec<Finding> {
        self.find(&self.injection_set, Some(&self.injection_rules), text)
    }

    /// Runs the rules that `set` matches; `rules` maps set indices to rules.
    fn find(&self, set: &RegexSet, rules: Option<&[usize]>, text: &str) -> Vec<Finding> {
        let mut found = Vec::new();
        for idx in set.matches(text).iter() {
            let idx = rules.map_or(idx, |r| r[idx]);
            let rule = &self.rules[idx];
            let mut consider = |start: usize, value: &str| {
                let Some(len) = (rule.validate)(value) else {
                    return;
                };
                if let Some(context) = &rule.context {
                    if !context.is_match(&text[window_start(text, start)..start]) {
                        return;
                    }
                }
                found.push((
                    idx,
                    Finding {
                        kind: rule.kind,
                        start,
                        end: start + len,
                    },
                ));
            };
            if rule.grouped {
                for caps in rule.regex.captures_iter(text) {
                    if let Some(m) = caps.get(1) {
                        consider(m.start(), m.as_str());
                    }
                }
            } else {
                for m in rule.regex.find_iter(text) {
                    consider(m.start(), m.as_str());
                }
            }
        }
        // At each position: secrets before other kinds (a password can look like the
        // start of an email address), then the longest match, then rule order.
        found.sort_by_key(|(idx, f)| {
            let secret_first = f.kind.category() != Category::Secret;
            (f.start, secret_first, std::cmp::Reverse(f.end), *idx)
        });
        let mut out: Vec<Finding> = Vec::with_capacity(found.len());
        for (_, f) in found {
            if out.last().is_none_or(|last| f.start >= last.end) {
                out.push(f);
            }
        }
        out
    }

    /// ID for logs and policies: `pii.email`, `secret.openai_key` or `custom.<name>`.
    pub fn label(&self, kind: Kind) -> String {
        match kind {
            Kind::Custom(i) => format!("custom.{}", self.custom_name(i)),
            _ => kind.id(),
        }
    }

    /// Replaces each finding with a `[REDACTED:<ENTITY>]` marker.
    /// `findings` must be sorted and non-overlapping, as returned by [`Detector::scan`].
    pub fn redact(&self, text: &str, findings: &[Finding]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for f in findings {
            let name = match f.kind {
                Kind::Custom(i) => self.custom_name(i),
                kind => kind.entity(),
            };
            out.push_str(&text[pos..f.start]);
            out.push_str("[REDACTED:");
            out.push_str(&name.to_ascii_uppercase());
            out.push(']');
            pos = f.end;
        }
        out.push_str(&text[pos..]);
        out
    }

    fn custom_name(&self, i: u16) -> &str {
        self.custom_names
            .get(usize::from(i))
            .map_or("unknown", String::as_str)
    }
}

/// Start of the context window before `pos`, moved forward to a character boundary.
fn window_start(text: &str, pos: usize) -> usize {
    let mut start = pos.saturating_sub(CONTEXT_WINDOW);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    start
}

#[cfg(test)]
mod tests;
