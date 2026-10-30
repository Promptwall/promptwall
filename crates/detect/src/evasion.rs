//! Prompt-injection evasions: attacks written so that the plain patterns miss
//! them. Each variant of the text below is scanned with the injection rules,
//! and a hit is reported as [`Kind::Obfuscated`] on the span of the original
//! text it came from:
//!
//! - look-alike characters: Cyrillic and Greek homoglyphs, fullwidth,
//!   mathematical and circled letters, leetspeak (`1gn0r3`), combining marks
//!   and invisible characters between letters;
//! - escapes: percent (`%69`), HTML (`&#105;`), `\x69` and `i`, and
//!   Unicode tag characters (decoded rather than only flagged as hidden text);
//! - spacing: `i g n o r e`, `i.g.n.o.r.e`, and words run together;
//! - encodings: base64 and hex runs, and ROT13 or reversed text when the
//!   prompt mentions them.
//!
//! A long fake dialogue inside one message (many-shot jailbreak) is reported
//! as [`Kind::ManyShot`].

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use crate::{Category, Detector, Finding, Kind};

/// Fake turns of each side that make a many-shot jailbreak.
const MANY_SHOT_TURNS: usize = 8;
/// Shortest base64 or hex run that is decoded, in characters.
const MIN_ENCODED: usize = 16;
/// Longest run that is decoded; longer ones are files or images.
const MAX_ENCODED: usize = 16 * 1024;
/// How deep encodings inside encodings are followed.
const DEPTH: u8 = 2;

/// Words that announce ROT13 or reversed text.
const HINT: &str = r"(?i:rot.?13|caesar|revers|backward|umgekehrt|l'envers|al rev)|[Rr]ückwärts";
static HINT_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(HINT).expect("valid"));
/// Attack phrases with the words run together or joined by `-`, `_`, `*` and
/// the like (`IgnoreAllPreviousInstructions`, `reveal-your-system-prompt`).
/// Letter-spaced words are joined up by [`normalize`] first.
static JOINED: LazyLock<String> = LazyLock::new(|| {
    let phrases = [
        "(?:ignore|disregard|forget|override|bypass) (?:(?:all|any|every|the|your|of) )*\
         (?:previous|prior|preceding|above|earlier|former|initial|original|system|safety) \
         (?:instructions?|prompts?|rules|directions|guidelines|commands|restrictions)",
        "(?:reveal|show|print|display|repeat|output|leak|tell|dump) (?:(?:me|us) )?(?:your|the) \
         (?:(?:full|entire|exact|complete|original|initial|hidden|secret) )*\
         (?:system|initial|hidden|original|developer|secret) (?:prompt|instructions)",
        "(?:developer|jailbreak|god) mode (?:is )?(?:enabled|activated|on)",
        "do any thing now|you are now (?:(?:a|an) )?(?:dan|jailbroken|unrestricted|unfiltered|uncensored)",
        "ignorier(?:e|en)? (?:sie )?(?:alle )?(?:vorherigen|bisherigen|deine|ihre) anweisungen",
        "(?:ignorez?|oubliez?) (?:toutes )?(?:les|vos|tes) instructions",
        "(?:ignora|olvida) (?:todas )?(?:las|tus|sus) instrucciones",
    ];
    // Between words: nothing, a single dot, or up to three spaces and joiners.
    // A dot followed by a space ends a sentence and does not join.
    format!("(?i){}", phrases.join("|")).replace(' ', r"(?:[\s_*/|~+-]{0,3}|\.)")
});
static JOINED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&JOINED).expect("valid"));
/// Whether [`JOINED`] or [`HINT`] occur at all, in one pass over the text.
static GATE: LazyLock<RegexSet> =
    LazyLock::new(|| RegexSet::new([JOINED.as_str(), HINT]).expect("valid"));
/// A line that opens a turn of a written-out dialogue: `User:`, `**AI:**`.
static TURN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?mi)^[ \t>*_#-]*(user|human|q|question|me|assistant|ai|a|answer|bot|model|gpt|claude)[ \t*_]*:",
    )
    .expect("valid")
});
/// Context kept on each side of a changed character when normalizing, in bytes.
const WINDOW: usize = 256;

impl Detector {
    /// Injection attacks hidden from [`Detector::scan`] by encoding, look-alike
    /// characters or spacing, and many-shot jailbreaks. `found` is what
    /// `scan` returned for the same text: hits that overlap one of its
    /// injection findings are not reported twice.
    pub fn scan_evasions(&self, text: &str, found: &[Finding]) -> Vec<Finding> {
        let mut out = Vec::new();
        self.evasions(text, DEPTH, &mut out);
        if let Some(f) = many_shot(text) {
            out.push(f);
        }
        out.retain(|f| {
            !found.iter().any(|t| {
                t.kind.category() == Category::Injection && t.start < f.end && f.start < t.end
            })
        });
        out.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
        let mut merged: Vec<Finding> = Vec::with_capacity(out.len());
        for f in out {
            if merged.last().is_none_or(|last| f.start >= last.end) {
                merged.push(f);
            }
        }
        merged
    }

    fn evasions(&self, text: &str, depth: u8, out: &mut Vec<Finding>) {
        let obfuscated = |(start, end)| Finding {
            kind: Kind::Obfuscated,
            start,
            end,
        };
        let gate = GATE.matches(text);
        if gate.matched(0) {
            for m in JOINED_RE.find_iter(text) {
                out.push(obfuscated((m.start(), m.end())));
            }
        }
        for n in normalize(text) {
            let spans = self.injection_spans(&n.text).into_iter();
            let joined = JOINED_RE.find_iter(&n.text).map(|m| (m.start(), m.end()));
            for (s, e) in spans.chain(joined) {
                out.push(obfuscated(n.span(s, e)));
            }
        }
        // Hint words are rare, so ROT13 and reversed text are only tried then.
        let (mut rot, mut rev) = (false, false);
        for m in HINT_RE.find_iter(text).take_while(|_| gate.matched(1)) {
            let word = m.as_str().to_lowercase();
            if word.starts_with("rot") || word == "caesar" {
                rot = true;
            } else {
                rev = true;
            }
        }
        if rot {
            let rotated: String = text.chars().map(rot13).collect();
            // ROT13 keeps every character's length, so spans carry over.
            for span in self.injection_spans(&rotated) {
                out.push(obfuscated(span));
            }
        }
        if rev {
            let reversed: String = text.chars().rev().collect();
            if !self.injection_spans(&reversed).is_empty() {
                out.push(obfuscated((0, text.len())));
            }
        }
        if depth == 0 {
            return;
        }
        for (start, end) in encoded_runs(text) {
            let run = &text[start..end];
            let decoded = if run.len() % 2 == 0 && run.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex(run)
            } else {
                base64(run)
            };
            let Some(decoded) = decoded.and_then(readable) else {
                continue;
            };
            if self.has_attack(&decoded, depth - 1) {
                out.push(obfuscated((start, end)));
            }
        }
    }

    fn has_attack(&self, text: &str, depth: u8) -> bool {
        if !self.injection_spans(text).is_empty() {
            return true;
        }
        let mut found = Vec::new();
        self.evasions(text, depth, &mut found);
        !found.is_empty()
    }

    /// Spans of pattern-based injection findings in `text`.
    fn injection_spans(&self, text: &str) -> Vec<(usize, usize)> {
        self.scan_injection(text)
            .into_iter()
            .map(|f| (f.start, f.end))
            .collect()
    }
}

impl Detector {
    /// Data findings (PII, secrets, custom patterns) that [`Detector::scan`]
    /// misses because the value is hidden: split by invisible characters,
    /// written in fullwidth letters, or base64- or hex-encoded. Spans are in
    /// `text`; an encoded value is reported on the whole encoded run.
    pub(crate) fn scan_hidden(&self, text: &str) -> Vec<Finding> {
        let data = |f: &Finding| f.kind.category() != Category::Injection;
        let mut out = Vec::new();
        if !text.is_ascii() {
            if let Some((clean, from)) = unhide(text) {
                for f in self
                    .find(&self.set, None, &clean)
                    .iter()
                    .filter(|f| data(f))
                {
                    out.push(Finding {
                        kind: f.kind,
                        start: from[f.start].0,
                        end: from[f.end - 1].1,
                    });
                }
            }
        }
        for (start, end) in encoded_runs(text) {
            let run = &text[start..end];
            let decoded = if run.len() % 2 == 0 && run.bytes().all(|b| b.is_ascii_hexdigit()) {
                hex(run)
            } else {
                base64(run)
            };
            let Some(decoded) = decoded.and_then(readable) else {
                continue;
            };
            if let Some(f) = self.find(&self.set, None, &decoded).into_iter().find(data) {
                out.push(Finding {
                    kind: f.kind,
                    start,
                    end,
                });
            }
        }
        out
    }
}

/// `text` without invisible characters and with fullwidth ASCII folded to
/// ASCII, and for each byte of it the span of the character in `text` it
/// came from; `None` when nothing changes.
fn unhide(text: &str) -> Option<(String, Vec<(usize, usize)>)> {
    let mut clean = String::with_capacity(text.len());
    let mut from = Vec::with_capacity(text.len());
    let mut changed = false;
    for (i, c) in text.char_indices() {
        let span = (i, i + c.len_utf8());
        let out = match c {
            c if invisible(c) => None,
            '\u{FF01}'..='\u{FF5E}' => char::from_u32(c as u32 - 0xFEE0),
            '\u{3000}' => Some(' '),
            c => Some(c),
        };
        changed |= out != Some(c);
        if let Some(o) = out {
            clean.push(o);
            from.extend(std::iter::repeat_n(span, o.len_utf8()));
        }
    }
    changed.then_some((clean, from))
}

/// Characters that take no space: zero-width, soft hyphens, direction marks,
/// byte-order marks and Unicode tags.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// A many-shot jailbreak: one message holding a long dialogue between a user
/// and an assistant, written out to make the model continue the pattern.
fn many_shot(text: &str) -> Option<Finding> {
    let (mut user, mut bot, mut first) = (0, 0, None);
    for caps in TURN.captures_iter(text) {
        let role = caps[1].to_ascii_lowercase();
        match role.as_str() {
            "user" | "human" | "q" | "question" | "me" => user += 1,
            _ => bot += 1,
        }
        first.get_or_insert(caps.get(0).expect("whole match").start());
    }
    (user >= MANY_SHOT_TURNS && bot >= MANY_SHOT_TURNS).then(|| Finding {
        kind: Kind::ManyShot,
        start: first.unwrap_or(0),
        end: text.len(),
    })
}

/// Text rewritten from another text, with each byte's source span.
struct Mapped {
    text: String,
    src: Vec<(usize, usize)>,
}

impl Mapped {
    fn push(&mut self, c: char, from: (usize, usize)) {
        self.text.push(c);
        self.src.extend(std::iter::repeat_n(from, c.len_utf8()));
    }

    /// The span of the original text that `text[start..end]` came from.
    fn span(&self, start: usize, end: usize) -> (usize, usize) {
        (self.src[start].0, self.src[end - 1].1)
    }
}

/// The parts of `text` around characters that stand for others (look-alikes,
/// escapes, invisible characters, letter spacing), each with those undone.
/// Empty when there is nothing to undo, which is the common case.
fn normalize(text: &str) -> Vec<Mapped> {
    let separators = spacing(text);
    let mut hot = changed_chars(text);
    if hot.is_empty() && separators.is_empty() {
        return Vec::new();
    }
    hot.extend_from_slice(&separators);
    hot.sort_unstable();
    let floor = |mut i: usize| {
        while !text.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for at in hot {
        let (start, end) = (
            floor(at.saturating_sub(WINDOW)),
            floor((at + WINDOW).min(text.len())),
        );
        match windows.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => windows.push((start, end)),
        }
    }
    windows
        .into_iter()
        .map(|(start, end)| normalize_window(text, start, end, &separators))
        .collect()
}

/// Byte offsets of characters that [`normalize_window`] would change, apart
/// from letter spacing.
fn changed_chars(text: &str) -> Vec<usize> {
    let b = text.as_bytes();
    let letter = |i: Option<usize>| {
        i.and_then(|i| b.get(i))
            .is_some_and(|x| x.is_ascii_alphabetic() || *x >= 0x80)
    };
    let mut out = Vec::new();
    for (i, &x) in b.iter().enumerate() {
        let changed = match x {
            b'%' | b'\\' | b'&' => escape(&text[i..]).is_some(),
            0x80..=0xBF => false, // inside a multi-byte character
            0xC0.. => text[i..]
                .chars()
                .next()
                .is_some_and(|c| look_alike(c) != Some(c)),
            _ => leet(char::from(x)).is_some() && (letter(i.checked_sub(1)) || letter(Some(i + 1))),
        };
        if changed {
            out.push(i);
        }
    }
    out
}

/// `text[start..end]` with look-alikes, escapes, invisible characters and the
/// letter-spacing `separators` undone.
fn normalize_window(text: &str, start: usize, end: usize, separators: &[usize]) -> Mapped {
    let chars: Vec<(usize, char)> = text[start..end]
        .char_indices()
        .map(|(i, c)| (start + i, c))
        .collect();
    let mut drop = vec![false; chars.len()];
    for &at in separators.iter().filter(|&&at| (start..end).contains(&at)) {
        drop[chars.partition_point(|(i, _)| *i < at)] = true;
    }
    let end_of = |k: usize| chars.get(k).map_or(end, |(i, _)| *i);
    // Whether the nearest kept character before or after `k` is a letter.
    let letter_beside = |k: usize| {
        let letter = |j: usize| chars[j].1.is_alphabetic();
        (0..k).rev().find(|j| !drop[*j]).is_some_and(letter)
            || (k + 1..chars.len()).find(|j| !drop[*j]).is_some_and(letter)
    };

    let mut out = Mapped {
        text: String::with_capacity(end - start),
        src: Vec::with_capacity(end - start),
    };
    let mut k = 0;
    while k < chars.len() {
        let (at, c) = chars[k];
        if drop[k] {
            k += 1;
            continue;
        }
        if let Some((decoded, used)) = escape(&text[at..end]) {
            if let Some(c) = look_alike(decoded) {
                out.push(c, (at, at + used));
            }
            k = chars.partition_point(|(i, _)| *i < at + used);
            continue;
        }
        let mapped = match look_alike(c) {
            None => {
                k += 1;
                continue;
            }
            Some(m) if m != c => m,
            Some(_) => leet(c).filter(|_| letter_beside(k)).unwrap_or(c),
        };
        out.push(mapped, (at, end_of(k + 1)));
        k += 1;
    }
    out
}

/// Byte offsets of the separators in letter-spaced words: three or more single
/// letters (or digits) with one separator between each, like `i g n o r e` or
/// `i.g.n.o.r.e`.
pub(crate) fn spacing(text: &str) -> Vec<usize> {
    let b = text.as_bytes();
    // Any non-ASCII character counts as a letter here.
    let token = |x: u8| x.is_ascii_alphanumeric() || matches!(x, b'@' | b'$') || x >= 0x80;
    let separator = |x: u8| matches!(x, b' ' | b'.' | b'_' | b'*' | b'/' | b'|' | b'-');
    // End of the character at `at` if it is a word on its own.
    let single = |at: usize| {
        let len = match b[at] {
            0xF0.. => 4,
            0xE0.. => 3,
            0xC0.. => 2,
            _ => 1,
        };
        let end = at + len;
        (end <= b.len() && b.get(end).is_none_or(|x| !token(*x))).then_some(end)
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !token(b[i]) {
            i += 1;
            continue;
        }
        let mut seps = Vec::new();
        let mut at = i;
        while let Some(end) = single(at) {
            let next = end + 1;
            if end < b.len()
                && separator(b[end])
                && next < b.len()
                && token(b[next])
                && single(next).is_some()
            {
                seps.push(end);
                at = next;
            } else {
                break;
            }
        }
        if seps.len() >= 2 {
            out.extend(seps);
        }
        // Skip to the end of the word the run stopped at.
        i = at;
        while i < b.len() && token(b[i]) {
            i += 1;
        }
    }
    out
}

/// An escape sequence at the start of `s`: the character and its length.
fn escape(s: &str) -> Option<(char, usize)> {
    let b = s.as_bytes();
    let hex_at = |from: usize, n: usize| {
        let digits = s.get(from..from + n)?;
        digits
            .bytes()
            .all(|d| d.is_ascii_hexdigit())
            .then(|| u32::from_str_radix(digits, 16).ok())?
    };
    let ascii = |v: u32| (v < 0x80).then(|| char::from(v as u8));
    match b.first()? {
        b'%' => Some((ascii(hex_at(1, 2)?)?, 3)),
        b'\\' => match b.get(1)? {
            b'x' => Some((ascii(hex_at(2, 2)?)?, 4)),
            b'u' => Some((char::from_u32(hex_at(2, 4)?)?, 6)),
            _ => None,
        },
        b'&' => {
            let end = b.iter().take(12).position(|&c| c == b';')?;
            let name = &s[1..end];
            let c = if let Some(num) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                char::from_u32(u32::from_str_radix(num, 16).ok()?)?
            } else if let Some(num) = name.strip_prefix('#') {
                char::from_u32(num.parse().ok()?)?
            } else {
                match name {
                    "lt" => '<',
                    "gt" => '>',
                    "amp" => '&',
                    "quot" => '"',
                    "apos" => '\'',
                    "nbsp" => ' ',
                    _ => return None,
                }
            };
            Some((c, end + 1))
        }
        _ => None,
    }
}

/// The plain character `c` stands for, `Some(c)` if none, or `None` for an
/// invisible character to drop.
fn look_alike(c: char) -> Option<char> {
    let u = c as u32;
    let from = |base: u32, first: char| char::from_u32(first as u32 + (u - base));
    Some(match u {
        // Zero-width and formatting characters, combining marks, soft hyphen.
        0x00AD | 0x034F | 0x180E | 0x200B..=0x200F | 0x2060..=0x2064 | 0xFEFF => return None,
        0x0300..=0x036F | 0xFE00..=0xFE0F | 0xE0100..=0xE01EF => return None,
        // Unicode tag characters mirror ASCII.
        0xE0020..=0xE007E => from(0xE0000, '\0')?,
        0xE0000..=0xE007F => return None,
        // Fullwidth ASCII.
        0xFF01..=0xFF5E => from(0xFF01, '!')?,
        // Mathematical alphanumerics: 13 alphabets of 52 letters, then digits.
        0x1D400..=0x1D6A3 => {
            let i = (u - 0x1D400) % 52;
            char::from_u32(if i < 26 {
                'A' as u32 + i
            } else {
                'a' as u32 + i - 26
            })?
        }
        0x1D7CE..=0x1D7FF => char::from_u32('0' as u32 + (u - 0x1D7CE) % 10)?,
        // Circled and parenthesized letters.
        0x24B6..=0x24CF => from(0x24B6, 'A')?,
        0x24D0..=0x24E9 => from(0x24D0, 'a')?,
        0x249C..=0x24B5 => from(0x249C, 'a')?,
        _ => homoglyph(c).unwrap_or(c),
    })
}

/// Cyrillic, Greek and Latin letters that look like basic Latin ones.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        'а' | 'α' | 'ɑ' => 'a',
        'е' | 'ε' => 'e',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'с' | 'ϲ' => 'c',
        'у' => 'y',
        'х' | 'χ' => 'x',
        'ѕ' => 's',
        'і' | 'ι' | 'ı' => 'i',
        'ј' => 'j',
        'ԁ' => 'd',
        'һ' => 'h',
        'ӏ' => 'l',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'ɡ' => 'g',
        'κ' => 'k',
        'ν' => 'v',
        'τ' => 't',
        'υ' => 'u',
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'Е' | 'Ε' => 'E',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'Н' | 'Η' => 'H',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'С' => 'C',
        'Т' | 'Τ' => 'T',
        'Х' | 'Χ' => 'X',
        'У' | 'Υ' => 'Y',
        'І' | 'Ι' => 'I',
        'Ј' => 'J',
        'Ѕ' => 'S',
        'Ζ' => 'Z',
        'Ν' => 'N',
        _ => return None,
    })
}

/// The letter a digit or symbol stands for in leetspeak.
fn leet(c: char) -> Option<char> {
    Some(match c {
        '0' => 'o',
        '1' => 'i',
        '3' => 'e',
        '4' | '@' => 'a',
        '5' | '$' => 's',
        '7' => 't',
        _ => return None,
    })
}

fn rot13(c: char) -> char {
    match c {
        'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
        'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
        _ => c,
    }
}

/// Standard or URL-safe base64, padding optional.
fn base64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() < MIN_ENCODED || s.len() % 4 == 1 {
        return None;
    }
    let value = |b: u8| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for b in s.bytes() {
        acc = (acc << 6) | u32::from(value(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Hex digits, two per byte.
fn hex(s: &str) -> Option<Vec<u8>> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

/// Runs of base64 or hex characters long enough to hold a sentence, and not so
/// long that they are a file or an image.
fn encoded_runs(text: &str) -> Vec<(usize, usize)> {
    let class = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-');
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !class(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && class(bytes[i]) {
            i += 1;
        }
        while i < bytes.len() && bytes[i] == b'=' {
            i += 1;
        }
        if (MIN_ENCODED..=MAX_ENCODED).contains(&(i - start)) {
            runs.push((start, i));
        }
    }
    runs
}

/// Decoded bytes that are text a model would read, not binary data.
fn readable(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let printable = text
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    let letters = text.chars().filter(|c| c.is_alphabetic()).count();
    let total = text.chars().count();
    (printable * 20 >= total * 19 && letters * 2 >= total).then_some(text)
}
