//! Tier 1 detectors: pattern-based PII and secret detection.
//!
//! Every detector is a regular expression plus an optional validator (a
//! checksum, a digit count) that removes false positives. A [`RegexSet`]
//! first finds which patterns occur at all, so text without sensitive data is
//! scanned in a single pass.
//!
//! The crate does no I/O and has no async code so that it can be compiled to
//! WebAssembly and run inside the npm package as well as the proxy.

use std::fmt;

use regex::{Regex, RegexSet};

/// What a finding is. The string IDs from [`Kind::id`] are stable and are what
/// policies and logs refer to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Email,
    Phone,
    Iban,
    CreditCard,
    AnthropicKey,
    OpenAiKey,
    AwsAccessKey,
    GitHubToken,
    SlackToken,
    StripeKey,
    GoogleApiKey,
    PrivateKey,
    Jwt,
}

/// Broad family a [`Kind`] belongs to; each maps to one policy detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Pii,
    Secret,
}

impl Kind {
    pub const ALL: [Kind; 13] = [
        Kind::Email,
        Kind::Phone,
        Kind::Iban,
        Kind::CreditCard,
        Kind::AnthropicKey,
        Kind::OpenAiKey,
        Kind::AwsAccessKey,
        Kind::GitHubToken,
        Kind::SlackToken,
        Kind::StripeKey,
        Kind::GoogleApiKey,
        Kind::PrivateKey,
        Kind::Jwt,
    ];

    pub fn category(self) -> Category {
        match self {
            Kind::Email | Kind::Phone | Kind::Iban | Kind::CreditCard => Category::Pii,
            _ => Category::Secret,
        }
    }

    /// Entity name used in policies, e.g. `email` or `openai_key`.
    pub fn entity(self) -> &'static str {
        match self {
            Kind::Email => "email",
            Kind::Phone => "phone",
            Kind::Iban => "iban",
            Kind::CreditCard => "credit_card",
            Kind::AnthropicKey => "anthropic_key",
            Kind::OpenAiKey => "openai_key",
            Kind::AwsAccessKey => "aws_access_key",
            Kind::GitHubToken => "github_token",
            Kind::SlackToken => "slack_token",
            Kind::StripeKey => "stripe_key",
            Kind::GoogleApiKey => "google_api_key",
            Kind::PrivateKey => "private_key",
            Kind::Jwt => "jwt",
        }
    }

    /// Stable rule ID, e.g. `pii.email` or `secret.openai_key`.
    pub fn id(self) -> String {
        let prefix = match self.category() {
            Category::Pii => "pii",
            Category::Secret => "secret",
        };
        format!("{prefix}.{}", self.entity())
    }

    /// Looks up a kind by its policy entity name within a category.
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

/// Returns how many bytes of the candidate are a valid match, or `None` to reject it.
type Validator = fn(&str) -> Option<usize>;

struct Rule {
    kind: Kind,
    regex: Regex,
    validate: Validator,
}

/// Compiled set of all Tier 1 detectors. Build once and share; scanning is `&self`.
pub struct Detector {
    set: RegexSet,
    rules: Vec<Rule>,
}

// Patterns use `\b`, which is replaced by an ASCII word boundary before
// compiling: Unicode word boundaries force the slower regex engine on
// non-ASCII text. Order matters for identical spans: earlier wins, so the
// Anthropic pattern precedes the more general OpenAI one.
const PATTERNS: [(Kind, &str, Validator); 13] = [
    (
        Kind::Email,
        r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b",
        accept,
    ),
    // Only the `+` international form: `00`-prefixed and national formats look too
    // much like other digit runs (IBAN groups, order numbers) to match on pattern alone.
    (Kind::Phone, r"\+[1-9][0-9 ().-]{6,20}[0-9]\b", valid_phone),
    (
        Kind::Iban,
        r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,32}\b",
        valid_iban,
    ),
    (
        Kind::CreditCard,
        r"\b[2-6][0-9](?:[ -]?[0-9]){11,17}\b",
        valid_card,
    ),
    (Kind::AnthropicKey, r"\bsk-ant-[A-Za-z0-9_-]{20,}", accept),
    (Kind::OpenAiKey, r"\bsk-[A-Za-z0-9_-]{20,}", accept),
    (Kind::AwsAccessKey, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", accept),
    (
        Kind::GitHubToken,
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
        accept,
    ),
    (Kind::SlackToken, r"\bxox[abprs]-[A-Za-z0-9-]{10,}", accept),
    (
        Kind::StripeKey,
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b",
        accept,
    ),
    (Kind::GoogleApiKey, r"\bAIza[A-Za-z0-9_-]{35}", accept),
    (
        Kind::PrivateKey,
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----)?",
        accept,
    ),
    (
        Kind::Jwt,
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
        accept,
    ),
];

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    pub fn new() -> Self {
        let sources: Vec<String> = PATTERNS
            .iter()
            .map(|(_, p, _)| p.replace(r"\b", r"(?-u:\b)"))
            .collect();
        let set = RegexSet::new(&sources).expect("built-in patterns compile");
        let rules = PATTERNS
            .iter()
            .zip(&sources)
            .map(|((kind, _, validate), src)| Rule {
                kind: *kind,
                regex: Regex::new(src).expect("built-in pattern compiles"),
                validate: *validate,
            })
            .collect();
        Self { set, rules }
    }

    /// Finds all sensitive values in `text`, sorted by position, without overlaps.
    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut found = Vec::new();
        for idx in self.set.matches(text).iter() {
            let rule = &self.rules[idx];
            for m in rule.regex.find_iter(text) {
                if let Some(len) = (rule.validate)(m.as_str()) {
                    found.push((
                        idx,
                        Finding {
                            kind: rule.kind,
                            start: m.start(),
                            end: m.start() + len,
                        },
                    ));
                }
            }
        }
        // Longest match first at each position; rule order breaks ties.
        found.sort_by_key(|(idx, f)| (f.start, std::cmp::Reverse(f.end), *idx));
        let mut out: Vec<Finding> = Vec::with_capacity(found.len());
        for (_, f) in found {
            if out.last().is_none_or(|last| f.start >= last.end) {
                out.push(f);
            }
        }
        out
    }
}

/// Replaces each finding with a `[REDACTED:<ENTITY>]` marker.
/// `findings` must be sorted and non-overlapping, as returned by [`Detector::scan`].
pub fn redact(text: &str, findings: &[Finding]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    for f in findings {
        out.push_str(&text[pos..f.start]);
        out.push_str("[REDACTED:");
        out.push_str(&f.kind.entity().to_ascii_uppercase());
        out.push(']');
        pos = f.end;
    }
    out.push_str(&text[pos..]);
    out
}

fn accept(s: &str) -> Option<usize> {
    Some(s.len())
}

/// E.164 allows at most 15 digits; fewer than 8 is rarely a full international number.
fn valid_phone(s: &str) -> Option<usize> {
    let digits = s.bytes().filter(u8::is_ascii_digit).count();
    (8..=15).contains(&digits).then_some(s.len())
}

/// ISO 13616 check: the longest prefix of 15 to 34 characters whose mod-97 remainder is 1.
/// Trying shorter prefixes handles an IBAN followed by another uppercase word.
fn valid_iban(s: &str) -> Option<usize> {
    let chars: Vec<(usize, char)> = s
        .char_indices()
        .filter(|(_, c)| c.is_ascii_alphanumeric())
        .collect();
    for n in (15..=chars.len().min(34)).rev() {
        let compact: String = chars[..n].iter().map(|(_, c)| *c).collect();
        if iban_mod97(&compact) == 1 {
            let (last, c) = chars[n - 1];
            return Some(last + c.len_utf8());
        }
    }
    None
}

fn iban_mod97(compact: &str) -> u32 {
    let (head, tail) = compact.split_at(4);
    let mut rem = 0u32;
    for c in tail.chars().chain(head.chars()) {
        let v = c.to_digit(36).unwrap_or(0);
        rem = if v >= 10 {
            (rem * 100 + v) % 97
        } else {
            (rem * 10 + v) % 97
        };
    }
    rem
}

/// A known card network prefix and length (so random digit runs rarely qualify),
/// passing the Luhn checksum, and not a run of one digit.
fn valid_card(s: &str) -> Option<usize> {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if !card_network_matches(&digits) || digits.iter().all(|d| *d == digits[0]) {
        return None;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                if d * 2 > 9 {
                    d * 2 - 9
                } else {
                    d * 2
                }
            } else {
                d
            }
        })
        .sum();
    (sum % 10 == 0).then_some(s.len())
}

fn card_network_matches(digits: &[u32]) -> bool {
    let prefix = |n: usize| digits.iter().take(n).fold(0, |acc, d| acc * 10 + d);
    let len = digits.len();
    let (p2, p3, p4) = (prefix(2), prefix(3), prefix(4));
    match digits.first() {
        // Visa
        Some(4) => matches!(len, 13 | 16 | 19),
        // Mastercard
        Some(5) => (51..=55).contains(&p2) && len == 16,
        Some(2) => (2221..=2720).contains(&p4) && len == 16,
        // Amex, Diners, JCB
        Some(3) => match p2 {
            34 | 37 => len == 15,
            36 | 38 | 39 => (14..=19).contains(&len),
            30 => (300..=305).contains(&p3) && (14..=19).contains(&len),
            35 => (3528..=3589).contains(&p4) && (16..=19).contains(&len),
            _ => false,
        },
        // Discover, UnionPay
        Some(6) => {
            (p4 == 6011 || (644..=649).contains(&p3) || p2 == 65 || p2 == 62)
                && (16..=19).contains(&len)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<Kind> {
        Detector::new()
            .scan(text)
            .into_iter()
            .map(|f| f.kind)
            .collect()
    }

    fn values(text: &str) -> Vec<&str> {
        Detector::new()
            .scan(text)
            .into_iter()
            .map(|f| &text[f.start..f.end])
            .collect()
    }

    #[test]
    fn finds_emails() {
        assert_eq!(
            values("Write to jane.doe+news@example.co.uk today."),
            ["jane.doe+news@example.co.uk"]
        );
        assert!(kinds("no at sign here, just text").is_empty());
    }

    #[test]
    fn finds_international_phone_numbers() {
        assert_eq!(values("Call +49 151 23456789 now"), ["+49 151 23456789"]);
        assert_eq!(values("or +44 (20) 7946-0958."), ["+44 (20) 7946-0958"]);
        assert!(kinds("version +1.2 released").is_empty());
    }

    #[test]
    fn finds_ibans_and_checks_the_checksum() {
        assert_eq!(
            values("IBAN: DE89 3704 0044 0532 0130 00 thanks"),
            ["DE89 3704 0044 0532 0130 00"]
        );
        assert_eq!(values("GB82WEST12345698765432"), ["GB82WEST12345698765432"]);
        // An uppercase word after the IBAN is not swallowed.
        assert_eq!(
            values("DE89370400440532013000 OK"),
            ["DE89370400440532013000"]
        );
        // One digit changed: checksum fails.
        assert!(kinds("DE89 3704 0044 0532 0130 01").is_empty());
    }

    #[test]
    fn finds_card_numbers_that_pass_luhn() {
        assert_eq!(
            values("card 4111 1111 1111 1111 exp 12/29"),
            ["4111 1111 1111 1111"]
        );
        assert_eq!(values("5500-0000-0000-0004"), ["5500-0000-0000-0004"]);
        assert!(kinds("4111 1111 1111 1112").is_empty());
        assert_eq!(kinds("amex 3782 822463 10005"), [Kind::CreditCard]);
        assert!(kinds("order 2024000000000000").is_empty());
        // Passes Luhn but no card network uses this prefix and length.
        assert!(kinds("3704 0044 0532 0130 01").is_empty());
    }

    #[test]
    fn finds_secrets() {
        let cases = [
            ("key=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345", Kind::OpenAiKey),
            ("sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123", Kind::AnthropicKey),
            ("AKIAIOSFODNN7EXAMPLE", Kind::AwsAccessKey),
            ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", Kind::GitHubToken),
            ("xoxb-1234567890-abcdefghij", Kind::SlackToken),
            ("sk_live_abcdefghijklmnopqrstuvwx", Kind::StripeKey),
            ("AIzaSyA-abcdefghijklmnopqrstuvwxyz01234", Kind::GoogleApiKey),
            (
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                Kind::Jwt,
            ),
        ];
        for (text, kind) in cases {
            assert_eq!(kinds(text), [kind], "{text}");
        }
    }

    #[test]
    fn finds_whole_private_key_block() {
        let text = "here:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nIBAAK\n-----END RSA PRIVATE KEY-----\nbye";
        let found = values(text);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("-----BEGIN") && found[0].ends_with("KEY-----"));
        // A truncated key still counts.
        assert_eq!(
            kinds("-----BEGIN PRIVATE KEY-----\nMIIEv"),
            [Kind::PrivateKey]
        );
    }

    #[test]
    fn plain_text_has_no_findings() {
        let text = "Please summarise the attached quarterly report in three bullet points. \
                    Revenue grew 12% to 4.5 million, orders reached 120000 and the skill \
                    matrix lists sk-level staff. Ünïcödé text is fine too.";
        assert!(kinds(text).is_empty());
    }

    #[test]
    fn redacts_findings_and_keeps_the_rest() {
        let text = "Mail jane@example.com or call +49 151 23456789, café ✓";
        let findings = Detector::new().scan(text);
        assert_eq!(
            redact(text, &findings),
            "Mail [REDACTED:EMAIL] or call [REDACTED:PHONE], café ✓"
        );
    }

    #[test]
    fn entity_names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(
                Kind::from_entity(kind.category(), kind.entity()),
                Some(kind)
            );
        }
        assert_eq!(Kind::Iban.id(), "pii.iban");
        assert_eq!(Kind::OpenAiKey.id(), "secret.openai_key");
    }
}
