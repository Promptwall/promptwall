//! Attachments in request bodies: files, images and audio that a request
//! carries inline (base64) or by reference, in the formats of the OpenAI Chat
//! Completions and Responses APIs, Anthropic Messages and Gemini.
//!
//! [`open`] replaces each attachment whose text can be read (plain text, CSV,
//! JSON, Markdown and other text files, and PDFs with a text layer) with a
//! text part holding that text, so the checks treat it like any other prompt
//! text: the patterns redact or block it and the models see it. [`close`]
//! then puts the attachments back. One whose text was not changed is restored
//! byte for byte. A text file whose text was redacted is sent as the same file
//! with the redacted text. A PDF cannot be rewritten, so a PDF with redactions
//! is sent as a text part with its redacted text instead.
//!
//! Images, audio, scanned PDFs and attachments sent as a link or file ID
//! cannot be read; they are reported with an attachment [`Kind`], which a
//! policy can flag, block or redact (remove from the request).

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use promptwall_detect::Kind;
use serde_json::{json, Map, Value};

/// Most text read from one attachment. A longer one counts as unreadable,
/// since the part after the limit would go unchecked.
pub const MAX_TEXT: usize = 2 << 20;

/// The API format an attachment is written in, which decides the shape of
/// the text part that replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Api {
    /// OpenAI Chat Completions.
    Chat,
    /// OpenAI Responses.
    Responses,
    Anthropic,
    Gemini,
}

/// What an attachment is, for metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Pdf,
    Image,
    Audio,
    /// A file of another format, or one that could not be decoded.
    File,
    /// A link or file ID that the provider fetches itself.
    Remote,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Pdf => "pdf",
            Format::Image => "image",
            Format::Audio => "audio",
            Format::File => "file",
            Format::Remote => "remote",
        }
    }
}

/// One attachment found by [`open`].
#[derive(Debug)]
pub struct Attachment {
    /// JSON pointer to the attachment's node in the body.
    pointer: String,
    /// The node as the client sent it, if [`open`] replaced it.
    original: Option<Value>,
    api: Api,
    pub format: Format,
    /// File name, if the request gives one.
    name: Option<String>,
    /// The text read from it, which the text part holds while it is checked.
    text: Option<String>,
    /// Where the text goes back into the original when it was changed: the
    /// path of the field and the prefix before the base64 data (such as
    /// `data:text/plain;base64,`), or `None` for a field that holds plain text.
    /// `None` for PDFs, which are replaced with their text instead.
    write_back: Option<(Vec<&'static str>, Option<String>)>,
    /// The kind to report, for attachments whose content is not checked.
    pub unreadable: Option<Kind>,
    /// Set by the caller to remove the attachment from the request, leaving a
    /// redaction marker in its place.
    pub remove: bool,
}

/// Finds the attachments in a request body and replaces those with readable
/// text by text parts holding that text. [`close`] must be called before the
/// body is sent on.
pub fn open(body: &mut Value) -> Vec<Attachment> {
    let mut found = Vec::new();
    walk(body, &mut String::new(), &mut found);
    found
}

/// Puts the attachments back after the checks: unchanged ones as they were,
/// changed text in the original file where possible, removed ones as a
/// redaction marker. Returns whether the body differs from what the client
/// sent.
pub fn close(body: &mut Value, attachments: Vec<Attachment>) -> bool {
    let mut changed = false;
    for a in attachments {
        let Some(node) = body.pointer_mut(&a.pointer) else {
            continue;
        };
        if a.remove {
            let entity = a.unreadable.map_or("attachment", Kind::entity);
            *node = text_part(a.api, format!("[REDACTED:{}]", entity.to_ascii_uppercase()));
            changed = true;
            continue;
        }
        let Some(mut original) = a.original else {
            continue;
        };
        // Unreadable ones were left out as empty text.
        let before = a.text.as_deref().unwrap_or("");
        let Some(now) = node
            .get("text")
            .and_then(Value::as_str)
            .filter(|now| *now != before)
            .map(str::to_owned)
        else {
            *node = original;
            continue;
        };
        changed = true;
        match a.write_back {
            Some((field, prefix)) => {
                let value = match prefix {
                    Some(prefix) => prefix + &STANDARD.encode(&now),
                    None => now,
                };
                if let Some(slot) = field_mut(&mut original, &field) {
                    *slot = Value::String(value);
                }
                *node = original;
            }
            None => {
                let name = a.name.as_deref().unwrap_or("file");
                *node = text_part(a.api, format!("[Attachment {name}, text only]\n{now}"));
            }
        }
    }
    changed
}

fn walk(value: &mut Value, pointer: &mut String, found: &mut Vec<Attachment>) {
    match value {
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                walk(item, pointer, found);
                pointer.truncate(len);
            }
        }
        Value::Object(map) => {
            if let Some(attachment) = attachment(map, pointer) {
                if let Some(text) = &attachment.text {
                    *value = json!({"type": "text", "text": text});
                } else if attachment.original.is_some() {
                    // Inline data that cannot be read is left out while the
                    // body is checked; the patterns would only find noise in it.
                    *value = json!({"type": "text", "text": ""});
                }
                found.push(attachment);
                return;
            }
            for (key, item) in map.iter_mut() {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(&key.replace('~', "~0").replace('/', "~1"));
                walk(item, pointer, found);
                pointer.truncate(len);
            }
        }
        _ => {}
    }
}

/// Where an attachment's content is.
enum Payload<'a> {
    /// Base64 data in the field at this path, after `prefix`.
    Base64 {
        field: Vec<&'static str>,
        mime: Option<String>,
        prefix: Option<String>,
        data: &'a str,
    },
    /// Plain text in the field at this path.
    Text {
        field: Vec<&'static str>,
        text: &'a str,
    },
    /// Inline image or audio data.
    Media(Format),
    /// A link or file ID.
    Remote,
}

/// The attachment this object is, if it is one.
fn attachment(map: &mut Map<String, Value>, pointer: &str) -> Option<Attachment> {
    let (api, payload, name) = recognize(map)?;
    let name = name.map(str::to_owned);
    let mut a = Attachment {
        pointer: pointer.to_owned(),
        original: None,
        api,
        format: Format::Remote,
        name,
        text: None,
        write_back: None,
        unreadable: None,
        remove: false,
    };
    match payload {
        Payload::Remote => a.unreadable = Some(Kind::AttachedRemote),
        Payload::Media(format) => {
            a.format = format;
            a.unreadable = Some(unreadable_kind(format));
        }
        Payload::Text { field, text } => {
            if text.len() <= MAX_TEXT {
                a.format = Format::Text;
                a.text = Some(text.to_owned());
                a.write_back = Some((field, None));
            } else {
                a.format = Format::File;
                a.unreadable = Some(Kind::AttachedFile);
            }
        }
        Payload::Base64 {
            field,
            mime,
            prefix,
            data,
        } => match read(data, mime.as_deref(), a.name.as_deref()) {
            Read::Text(text) => {
                a.format = Format::Text;
                a.text = Some(text);
                // Keep the original's prefix, or none if it had none.
                a.write_back = Some((field, Some(prefix.unwrap_or_default())));
            }
            Read::Pdf(text) => {
                a.format = Format::Pdf;
                a.text = Some(text);
            }
            Read::Unreadable(format) => {
                a.format = format;
                a.unreadable = Some(unreadable_kind(format));
            }
        },
    }
    if a.format != Format::Remote {
        a.original = Some(Value::Object(std::mem::take(map)));
    }
    Some(a)
}

fn unreadable_kind(format: Format) -> Kind {
    match format {
        Format::Image => Kind::AttachedImage,
        Format::Audio => Kind::AttachedAudio,
        Format::Remote => Kind::AttachedRemote,
        Format::Text | Format::Pdf | Format::File => Kind::AttachedFile,
    }
}

/// Recognizes the attachment shapes of the supported APIs.
fn recognize(map: &Map<String, Value>) -> Option<(Api, Payload<'_>, Option<&str>)> {
    let str_at = |path: &[&str]| -> Option<&str> {
        let mut v = map.get(path[0])?;
        for key in &path[1..] {
            v = v.get(key)?;
        }
        v.as_str()
    };
    // Gemini parts: {"inlineData": {"mimeType", "data"}}, {"fileData": {...}},
    // in camelCase or snake_case.
    for (key, mime_key) in [("inlineData", "mimeType"), ("inline_data", "mime_type")] {
        if let Some(inline) = map.get(key).and_then(Value::as_object) {
            let mime = inline.get(mime_key).and_then(Value::as_str);
            let data = inline.get("data").and_then(Value::as_str)?;
            let field = vec![key_static(key), "data"];
            let payload = match media(mime) {
                Some(format) => Payload::Media(format),
                None => Payload::Base64 {
                    field,
                    mime: mime.map(str::to_owned),
                    prefix: None,
                    data,
                },
            };
            return Some((Api::Gemini, payload, None));
        }
    }
    if map.contains_key("fileData") || (map.contains_key("file_data") && !map.contains_key("type"))
    {
        return Some((Api::Gemini, Payload::Remote, None));
    }

    let kind = map.get("type").and_then(Value::as_str)?;
    match kind {
        // OpenAI Chat: {"type": "image_url", "image_url": {"url": ...}}.
        "image_url" => {
            let url = str_at(&["image_url", "url"]).or_else(|| str_at(&["image_url"]))?;
            Some((Api::Chat, inline_or_remote(url, Format::Image), None))
        }
        // OpenAI Chat: {"type": "input_audio", "input_audio": {"data", "format"}}.
        "input_audio" => Some((Api::Chat, Payload::Media(Format::Audio), None)),
        // OpenAI Chat: {"type": "file", "file": {"file_data" | "file_id", "filename"}}.
        "file" if map.get("file").is_some_and(Value::is_object) => {
            let name = str_at(&["file", "filename"]);
            let payload = match str_at(&["file", "file_data"]) {
                Some(data) => base64_payload(vec!["file", "file_data"], data),
                None => Payload::Remote,
            };
            Some((Api::Chat, payload, name))
        }
        // OpenAI Responses: {"type": "input_image", "image_url" | "file_id"}.
        "input_image" => {
            let payload = match str_at(&["image_url"]) {
                Some(url) => inline_or_remote(url, Format::Image),
                None => Payload::Remote,
            };
            Some((Api::Responses, payload, None))
        }
        // OpenAI Responses: {"type": "input_file", "file_data" | "file_id" | "file_url", "filename"}.
        "input_file" => {
            let name = str_at(&["filename"]);
            let payload = match str_at(&["file_data"]) {
                Some(data) => base64_payload(vec!["file_data"], data),
                None => Payload::Remote,
            };
            Some((Api::Responses, payload, name))
        }
        // Anthropic: {"type": "image", "source": {"type": "base64" | "url" | "file", ...}}.
        "image" if map.get("source").is_some_and(Value::is_object) => {
            let payload = match str_at(&["source", "type"]) {
                Some("base64") => Payload::Media(Format::Image),
                _ => Payload::Remote,
            };
            Some((Api::Anthropic, payload, None))
        }
        // Anthropic: {"type": "document", "source": {...}, "title"}.
        "document" if map.get("source").is_some_and(Value::is_object) => {
            let name = str_at(&["title"]);
            let payload = match str_at(&["source", "type"]) {
                Some("base64") => Payload::Base64 {
                    field: vec!["source", "data"],
                    mime: str_at(&["source", "media_type"]).map(str::to_owned),
                    prefix: None,
                    data: str_at(&["source", "data"])?,
                },
                Some("text") => Payload::Text {
                    field: vec!["source", "data"],
                    text: str_at(&["source", "data"])?,
                },
                // Content blocks are ordinary text blocks, checked as they are.
                Some("content") => return None,
                _ => Payload::Remote,
            };
            Some((Api::Anthropic, payload, name))
        }
        _ => None,
    }
}

fn key_static(key: &str) -> &'static str {
    if key == "inlineData" {
        "inlineData"
    } else {
        "inline_data"
    }
}

/// A `data:` URL is inline media; anything else is a link the provider fetches.
fn inline_or_remote(url: &str, format: Format) -> Payload<'_> {
    if url.trim_start().starts_with("data:") {
        Payload::Media(format)
    } else {
        Payload::Remote
    }
}

/// A base64 file, as a `data:` URL or bare.
fn base64_payload<'a>(field: Vec<&'static str>, value: &'a str) -> Payload<'a> {
    match value.strip_prefix("data:") {
        Some(rest) => {
            let Some((header, data)) = rest.split_once(',') else {
                return Payload::Media(Format::File);
            };
            if !header.ends_with(";base64") {
                return Payload::Media(Format::File);
            }
            let mime = header.split(';').next().unwrap_or("").to_owned();
            if let Some(format) = media(Some(&mime)) {
                return Payload::Media(format);
            }
            Payload::Base64 {
                field,
                mime: (!mime.is_empty()).then_some(mime),
                prefix: Some(format!("data:{header},")),
                data,
            }
        }
        None => Payload::Base64 {
            field,
            mime: None,
            prefix: None,
            data: value,
        },
    }
}

/// Images, audio and video, by MIME type.
fn media(mime: Option<&str>) -> Option<Format> {
    let mime = mime?.trim().to_ascii_lowercase();
    if mime.starts_with("image/") {
        Some(Format::Image)
    } else if mime.starts_with("audio/") || mime.starts_with("video/") {
        Some(Format::Audio)
    } else {
        None
    }
}

enum Read {
    Text(String),
    Pdf(String),
    Unreadable(Format),
}

/// Decodes a base64 file and reads its text.
fn read(data: &str, mime: Option<&str>, name: Option<&str>) -> Read {
    let compact: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let Ok(bytes) = STANDARD.decode(compact.trim_end_matches('=').to_owned() + pad(&compact))
    else {
        return Read::Unreadable(Format::File);
    };
    let mime = mime.map(|m| m.trim().to_ascii_lowercase());
    if bytes.starts_with(b"%PDF-") || mime.as_deref() == Some("application/pdf") {
        return match pdf_text(&bytes) {
            Some(text) if !text.trim().is_empty() && text.len() <= MAX_TEXT => Read::Pdf(text),
            _ => Read::Unreadable(Format::File),
        };
    }
    if !is_text(mime.as_deref(), name) && !looks_like_text(&bytes) {
        return Read::Unreadable(Format::File);
    }
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) if text.len() <= MAX_TEXT => Read::Text(text.to_owned()),
        _ => Read::Unreadable(Format::File),
    }
}

/// Padding that makes base64 without it decodable.
fn pad(data: &str) -> &'static str {
    match data.trim_end_matches('=').len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    }
}

/// Text formats by MIME type or file name.
fn is_text(mime: Option<&str>, name: Option<&str>) -> bool {
    const TYPES: [&str; 9] = [
        "application/json",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
        "application/csv",
        "application/javascript",
        "application/x-ndjson",
        "application/sql",
        "application/rtf",
    ];
    const EXTENSIONS: [&str; 16] = [
        "txt", "md", "markdown", "csv", "tsv", "json", "jsonl", "xml", "yaml", "yml", "html",
        "htm", "log", "ini", "toml", "sql",
    ];
    let by_type = mime.is_some_and(|m| {
        m.starts_with("text/") || TYPES.contains(&m) || m.ends_with("+json") || m.ends_with("+xml")
    });
    let by_name = name
        .and_then(|n| n.rsplit_once('.'))
        .is_some_and(|(_, ext)| EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()));
    by_type || by_name
}

/// UTF-8 without control characters other than tabs and line breaks.
fn looks_like_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| {
        !s.is_empty()
            && !s
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{c}'))
    })
}

/// Most bytes the compressed streams of one PDF may inflate to. A small PDF
/// can hold a stream that inflates a thousandfold (a "zip bomb"), which would
/// cost seconds and gigabytes to read; such a PDF counts as unreadable.
#[cfg(feature = "pdf")]
const MAX_PDF_INFLATED: usize = 64 << 20;
/// Most `stream` keywords looked at in one PDF.
#[cfg(feature = "pdf")]
const MAX_PDF_STREAMS: usize = 20_000;

#[cfg(feature = "pdf")]
fn pdf_text(bytes: &[u8]) -> Option<String> {
    if !inflates_within(bytes, MAX_PDF_INFLATED) {
        return None;
    }
    // The PDF reader can panic on damaged files; that must not take the
    // request, let alone the proxy, down with it.
    std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes).ok())
        .ok()
        .flatten()
}

/// Whether every zlib stream in the PDF together inflates to at most
/// `budget` bytes. Checked on the raw bytes, before the PDF reader inflates
/// anything, and without keeping what is inflated. LZW, the other filter that
/// can inflate a lot, is rare today and not allowed.
#[cfg(feature = "pdf")]
fn inflates_within(bytes: &[u8], budget: usize) -> bool {
    use std::io::Read as _;

    if find(bytes, b"LZWDecode").is_some() {
        return false;
    }
    let mut total = 0;
    let mut buf = vec![0; 64 * 1024];
    let mut at = 0;
    let mut streams = 0;
    while let Some(p) = find(&bytes[at..], b"stream") {
        // Real PDFs of a few megabytes have hundreds of streams, not tens of
        // thousands; each try costs a decoder.
        streams += 1;
        if streams > MAX_PDF_STREAMS {
            return false;
        }
        let mut start = at + p + b"stream".len();
        at = start;
        if bytes[..start].ends_with(b"endstream") {
            continue;
        }
        if bytes.get(start) == Some(&b'\r') {
            start += 1;
        }
        if bytes.get(start) == Some(&b'\n') {
            start += 1;
        }
        // Data that is not zlib fails on its first bytes.
        let mut stream = flate2::read::ZlibDecoder::new(&bytes[start..]);
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
            if total > budget {
                return false;
            }
        }
    }
    true
}

#[cfg(feature = "pdf")]
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(not(feature = "pdf"))]
fn pdf_text(_: &[u8]) -> Option<String> {
    None
}

fn field_mut<'a>(value: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    let mut v = value;
    for key in path {
        v = v.get_mut(*key)?;
    }
    Some(v)
}

/// A text part in the given API's format.
fn text_part(api: Api, text: String) -> Value {
    match api {
        Api::Chat | Api::Anthropic => json!({"type": "text", "text": text}),
        Api::Responses => json!({"type": "input_text", "text": text}),
        Api::Gemini => json!({"text": text}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        STANDARD.encode(s)
    }

    #[test]
    fn unchanged_attachments_are_restored_exactly() {
        let body = json!({"messages": [{"role": "user", "content": [
            {"type": "text", "text": "Summarise this"},
            {"type": "file", "file": {"filename": "notes.txt", "file_data": format!("data:text/plain;base64,{}", b64("hello"))}},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}},
            {"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}},
        ]}]});
        let mut json = body.clone();
        let found = open(&mut json);
        let formats: Vec<_> = found.iter().map(|a| a.format).collect();
        assert_eq!(formats, [Format::Text, Format::Image, Format::Remote]);
        assert_eq!(json["messages"][0]["content"][1]["text"], "hello");
        assert!(!close(&mut json, found));
        assert_eq!(json, body);
    }

    #[test]
    fn changed_text_files_keep_their_shape() {
        let cases = [
            json!({"type": "file", "file": {"filename": "a.csv", "file_data": format!("data:text/csv;base64,{}", b64("jane@corp.io"))}}),
            json!({"type": "input_file", "filename": "a.txt", "file_data": format!("data:text/plain;base64,{}", b64("jane@corp.io"))}),
            json!({"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": b64("jane@corp.io")}}),
            json!({"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "jane@corp.io"}}),
            json!({"inlineData": {"mimeType": "text/plain", "data": b64("jane@corp.io")}}),
        ];
        for part in cases {
            let mut json = json!({"content": [part.clone()]});
            let found = open(&mut json);
            assert_eq!(found.len(), 1, "{part}");
            assert_eq!(json["content"][0]["text"], "jane@corp.io");
            json["content"][0]["text"] = "[REDACTED:EMAIL]".into();
            assert!(close(&mut json, found));
            let sent = json["content"][0].to_string();
            assert!(!sent.contains(&b64("jane@corp.io")), "{sent}");
            assert!(
                sent.contains(&b64("[REDACTED:EMAIL]")) || sent.contains("[REDACTED:EMAIL]"),
                "{sent}"
            );
            // Same keys as before: still a file.
            let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
            assert_eq!(keys(&json["content"][0]), keys(&part));
        }
    }

    #[test]
    fn removed_attachments_leave_a_marker_in_the_api_format() {
        let mut json = json!({"input": [{"role": "user", "content": [
            {"type": "input_image", "image_url": "data:image/png;base64,iVBORw0KGgo="},
        ]}], "contents": [{"parts": [{"fileData": {"fileUri": "gs://b/x.pdf"}}]}]});
        let mut found = open(&mut json);
        assert_eq!(found[0].unreadable, Some(Kind::AttachedImage));
        assert_eq!(found[1].unreadable, Some(Kind::AttachedRemote));
        found.iter_mut().for_each(|a| a.remove = true);
        assert!(close(&mut json, found));
        assert_eq!(
            json["input"][0]["content"][0],
            json!({"type": "input_text", "text": "[REDACTED:IMAGE]"})
        );
        assert_eq!(
            json["contents"][0]["parts"][0],
            json!({"text": "[REDACTED:REMOTE]"})
        );
    }

    #[test]
    fn binary_files_cannot_be_read() {
        let zip = STANDARD.encode(b"PK\x03\x04\x00\x00binary");
        let mut json = json!({"content": [{"type": "input_file", "filename": "a.docx", "file_data": format!("data:application/octet-stream;base64,{zip}")}]});
        let found = open(&mut json);
        assert_eq!(found[0].unreadable, Some(Kind::AttachedFile));
        // Left out while checking, restored afterwards.
        assert_eq!(json["content"][0]["text"], "");
        let before = json!({"content": [{"type": "input_file", "filename": "a.docx", "file_data": format!("data:application/octet-stream;base64,{zip}")}]});
        assert!(!close(&mut json, found));
        assert_eq!(json, before);
    }

    #[test]
    fn audio_and_anthropic_media() {
        let mut json = json!({"messages": [{"content": [
            {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
            {"type": "image", "source": {"type": "url", "url": "https://example.com/a.png"}},
            {"type": "document", "source": {"type": "file", "file_id": "file_1"}},
        ]}]});
        let kinds: Vec<_> = open(&mut json).iter().map(|a| a.unreadable).collect();
        assert_eq!(
            kinds,
            [
                Some(Kind::AttachedAudio),
                Some(Kind::AttachedImage),
                Some(Kind::AttachedRemote),
                Some(Kind::AttachedRemote),
            ]
        );
    }

    #[test]
    fn plain_text_blocks_are_not_attachments() {
        let mut json = json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            "contents": [{"parts": [{"text": "hi"}]}]});
        assert!(open(&mut json).is_empty());
    }

    #[cfg(feature = "pdf")]
    #[test]
    fn pdfs_are_read_and_replaced_by_their_text_when_changed() {
        let pdf = STANDARD.encode(minimal_pdf("Contact jane@corp.io today"));
        let part = json!({"type": "file", "file": {"filename": "r.pdf", "file_data": format!("data:application/pdf;base64,{pdf}")}});
        let mut json = json!({"content": [part.clone()]});
        let found = open(&mut json);
        assert_eq!(found[0].format, Format::Pdf);
        let text = json["content"][0]["text"].as_str().unwrap().to_owned();
        assert!(text.contains("jane@corp.io"), "{text:?}");
        // Unchanged: the PDF goes on as it was.
        let mut same = json.clone();
        assert!(!close(
            &mut same,
            open(&mut json!({"content": [part.clone()]}))
        ));
        assert_eq!(same["content"][0], part);
        // Changed: replaced by a text part.
        json["content"][0]["text"] = text.replace("jane@corp.io", "[REDACTED:EMAIL]").into();
        assert!(close(&mut json, found));
        let sent = json["content"][0]["text"].as_str().unwrap();
        assert!(
            sent.starts_with("[Attachment r.pdf, text only]\n"),
            "{sent}"
        );
        assert!(sent.contains("[REDACTED:EMAIL]") && !sent.contains("jane@"));
    }

    #[cfg(feature = "pdf")]
    #[test]
    fn damaged_pdfs_are_unreadable_not_fatal() {
        let pdf = STANDARD.encode(b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 9 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF");
        let mut json = json!({"content": [{"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": pdf}}]});
        let found = open(&mut json);
        assert_eq!(found[0].unreadable, Some(Kind::AttachedFile));
    }

    #[cfg(feature = "pdf")]
    #[test]
    fn pdf_bombs_are_not_read() {
        use std::io::Write as _;

        // 128 MiB of spaces after the text, compressed to about 128 KiB.
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        z.write_all(b"BT /F1 12 Tf 72 720 Td (hi) Tj ET\n").unwrap();
        let spaces = vec![b' '; 1 << 20];
        for _ in 0..128 {
            z.write_all(&spaces).unwrap();
        }
        let content = z.finish().unwrap();
        let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Length ".to_vec();
        pdf.extend(content.len().to_string().bytes());
        pdf.extend(b" /Filter /FlateDecode >>\nstream\n");
        pdf.extend(&content);
        pdf.extend(b"\nendstream\nendobj\n%%EOF\n");
        assert!(pdf.len() < 1 << 20);
        assert!(!inflates_within(&pdf, MAX_PDF_INFLATED));
        assert!(pdf_text(&pdf).is_none());
        // An ordinary PDF passes.
        assert!(inflates_within(&minimal_pdf("hello"), MAX_PDF_INFLATED));
    }

    /// A one-page PDF showing `text` in Helvetica, with a correct xref table.
    #[cfg(feature = "pdf")]
    pub(crate) fn minimal_pdf(text: &str) -> Vec<u8> {
        let stream = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_owned(),
            format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
        ];
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, obj) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend(format!("{} 0 obj\n{obj}\nendobj\n", i + 1).bytes());
        }
        let xref = out.len();
        out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
        for o in offsets {
            out.extend(format!("{o:010} 00000 n \n").bytes());
        }
        out.extend(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objects.len() + 1
            )
            .bytes(),
        );
        out
    }
}
