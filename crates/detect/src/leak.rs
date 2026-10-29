//! System prompt leak detection: does the answer repeat a run of words from the
//! app's own instructions?

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::{Finding, Kind};

/// The word runs of one system prompt, ready to be looked up in model output.
/// Words are compared case-insensitively and ignore punctuation, so a leak
/// survives reformatting.
#[derive(Debug, Default)]
pub struct SystemPromptIndex {
    runs: HashSet<u64>,
    words: usize,
}

impl SystemPromptIndex {
    /// Indexes every run of `words` consecutive words in `system_prompt`.
    pub fn new(system_prompt: &str, words: usize) -> Self {
        let words = words.max(1);
        let tokens: Vec<String> = word_spans(system_prompt)
            .map(|(s, e)| system_prompt[s..e].to_lowercase())
            .collect();
        let runs = tokens.windows(words).map(hash_run).collect();
        Self { runs, words }
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Spans of `text` that repeat a run of the system prompt. Overlapping runs
    /// merge into one finding.
    pub fn find(&self, text: &str) -> Vec<Finding> {
        if self.runs.is_empty() {
            return Vec::new();
        }
        let spans: Vec<(usize, usize)> = word_spans(text).collect();
        let tokens: Vec<String> = spans
            .iter()
            .map(|&(s, e)| text[s..e].to_lowercase())
            .collect();
        let mut out: Vec<Finding> = Vec::new();
        for (i, run) in tokens.windows(self.words).enumerate() {
            if !self.runs.contains(&hash_run(run)) {
                continue;
            }
            let (start, end) = (spans[i].0, spans[i + self.words - 1].1);
            match out.last_mut() {
                Some(last) if start <= last.end => last.end = last.end.max(end),
                _ => out.push(Finding {
                    kind: Kind::SystemPromptLeak,
                    start,
                    end,
                }),
            }
        }
        out
    }
}

fn hash_run(words: &[String]) -> u64 {
    let mut h = DefaultHasher::new();
    words.hash(&mut h);
    h.finish()
}

/// Byte spans of the words (letters and digits) in `text`.
fn word_spans(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut chars = text.char_indices().peekable();
    std::iter::from_fn(move || {
        while chars.peek().is_some_and(|(_, c)| !c.is_alphanumeric()) {
            chars.next();
        }
        let (start, _) = *chars.peek()?;
        let mut end = start;
        while let Some(&(i, c)) = chars.peek() {
            if !c.is_alphanumeric() {
                break;
            }
            end = i + c.len_utf8();
            chars.next();
        }
        Some((start, end))
    })
}
