//! Candidate findings, and the `dv-candidates` interchange document the scanner writes
//! as `candidates.json` beside its report.
//!
//! ```json
//! { "format": "dv-candidates", "version": 1,
//!   "candidates": [
//!     { "source": "tool:solana-authority-scan",
//!       "finding": { "title": "...", "severity": "high", "category": "...",
//!                    "location": "...", "description": "...", "evidence": "...",
//!                    "recommendation": "..." } } ] }
//! ```
//!
//! A candidate is unreviewed tool output: something for a person to check, not a
//! conclusion. The format is described in `docs/output-formats.md`; a review tool that
//! reads it can import the scanner's output unchanged. This crate writes findings only.
//! [`parse_document`] reads a document back with the same checks as [`document`], so
//! a test can show that every document the scanner writes is one a reader accepts.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The `format` value of a candidate document.
pub const FORMAT: &str = "dv-candidates";
/// The document version this build writes.
pub const VERSION: u32 = 1;
/// The most characters one text field may hold.
pub const MAX_FIELD_CHARS: usize = 20_000;

pub const CRITICAL: &str = "critical";
pub const HIGH: &str = "high";
pub const MEDIUM: &str = "medium";
pub const LOW: &str = "low";
pub const INFO: &str = "info";

/// How serious a finding is, most serious first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => CRITICAL,
            Severity::High => HIGH,
            Severity::Medium => MEDIUM,
            Severity::Low => LOW,
            Severity::Info => INFO,
        }
    }

    pub fn parse(text: &str) -> Option<Severity> {
        Severity::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Severity::parse(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown severity {text:?}; use critical, high, medium, low or info"
            ))
        })
    }
}

impl Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A finding: what was seen, why it matters and what to do.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub location: String,
    pub description: String,
    pub evidence: String,
    pub recommendation: String,
}

impl Finding {
    /// Refuses an empty field, a title, category or location of more than one line,
    /// a field over [`MAX_FIELD_CHARS`], and any forbidden character.
    pub fn check(&self) -> Result<(), String> {
        check_line("title", &self.title)?;
        check_line("category", &self.category)?;
        check_line("location", &self.location)?;
        check_field("description", &self.description)?;
        check_field("evidence", &self.evidence)?;
        check_field("recommendation", &self.recommendation)
    }
}

/// One entry of a document as this crate writes it: a source and a finding.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    source: String,
    finding: Finding,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    version: u32,
    candidates: Vec<Entry>,
}

/// Checks a `source`: `tool:<name>`, where a name is 1 to 64 lowercase letters,
/// digits, `-` and `_`.
pub fn check_source(source: &str) -> Result<(), String> {
    let ok = source.strip_prefix("tool:").is_some_and(|n| {
        !n.is_empty()
            && n.len() <= 64
            && n.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "source {:?} is not tool:<name>",
            for_terminal(source)
        ))
    }
}

/// The document for `candidates`, each `(source, finding)` one entry. Refuses a bad
/// source or finding, so the scanner cannot write a document a reader would refuse.
pub fn document(candidates: &[(String, Finding)]) -> Result<String, String> {
    let mut entries = Vec::with_capacity(candidates.len());
    for (index, (source, finding)) in candidates.iter().enumerate() {
        let at = |e: String| format!("candidate {}: {e}", index.saturating_add(1));
        check_source(source).map_err(at)?;
        finding.check().map_err(at)?;
        entries.push(Entry {
            source: source.clone(),
            finding: finding.clone(),
        });
    }
    let doc = Document {
        format: FORMAT.to_owned(),
        version: VERSION,
        candidates: entries,
    };
    let mut text =
        serde_json::to_string_pretty(&doc).map_err(|e| format!("cannot write JSON: {e}"))?;
    text.push('\n');
    Ok(text)
}

/// Reads a document of findings with the checks [`document`] applies: the format and
/// version, at least one candidate, no unknown field, a good source and finding.
pub fn parse_document(text: &str) -> Result<Vec<(String, Finding)>, String> {
    let doc: Document =
        serde_json::from_str(text).map_err(|e| format!("not a candidate document: {e}"))?;
    if doc.format != FORMAT {
        return Err(format!("format is {:?}, expected {FORMAT:?}", doc.format));
    }
    if doc.version != VERSION {
        return Err(format!(
            "version {} is not supported; this build reads version {VERSION}",
            doc.version
        ));
    }
    if doc.candidates.is_empty() {
        return Err("the document has no candidates".to_owned());
    }
    let mut out = Vec::with_capacity(doc.candidates.len());
    for (index, entry) in doc.candidates.into_iter().enumerate() {
        let at = |e: String| format!("candidate {}: {e}", index.saturating_add(1));
        check_source(&entry.source).map_err(at)?;
        entry.finding.check().map_err(at)?;
        out.push((entry.source, entry.finding));
    }
    Ok(out)
}

/// Checks one field: not empty or whitespace only, at most [`MAX_FIELD_CHARS`], and no
/// forbidden character. `name` is used in the error only.
fn check_field(name: &str, text: &str) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err(format!("{name} is empty"));
    }
    if text.chars().count() > MAX_FIELD_CHARS {
        return Err(format!(
            "{name} is longer than {MAX_FIELD_CHARS} characters"
        ));
    }
    if let Some(c) = text.chars().find(|c| is_forbidden(*c)) {
        return Err(format!(
            "{name} holds the control character U+{:04X}",
            u32::from(c)
        ));
    }
    Ok(())
}

/// [`check_field`], and one line only.
fn check_line(name: &str, text: &str) -> Result<(), String> {
    check_field(name, text)?;
    if text.contains(['\n', '\r']) {
        return Err(format!("{name} must be one line"));
    }
    Ok(())
}

/// Control characters other than newline and tab; zero-width and bidirectional marks;
/// the line and paragraph separators (U+2028, U+2029); the byte-order mark (U+FEFF);
/// and the Arabic letter mark (U+061C). Any of them could rewrite a terminal or hide
/// text from a reader.
fn is_forbidden(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{FEFF}'
                | '\u{061C}'
        )
}

/// Text that is safe to print to a terminal: every forbidden character except newline
/// is shown as `\u{..}`.
pub fn for_terminal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\n' || !is_forbidden(c) {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"{"format":"dv-candidates","version":1,"candidates":[
      {"source":"tool:solana-authority-scan","finding":{"title":"Time lock is 0",
        "severity":"medium","category":"admin-plane","location":"program EXAMPLE",
        "description":"d","evidence":"e","recommendation":"r"}}]}"#;

    #[test]
    fn a_document_round_trips() {
        let parsed = parse_document(DOC).unwrap();
        assert_eq!(parsed.len(), 1);
        let text = document(&parsed).unwrap();
        assert_eq!(parse_document(&text).unwrap(), parsed);
        assert!(text.starts_with("{\n  \"format\": \"dv-candidates\",\n  \"version\": 1,"));
    }

    #[test]
    fn refuses_malformed_documents() {
        for (bad, why) in [
            (DOC.replace("\"version\":1", "\"version\":2"), "version"),
            (DOC.replace("dv-candidates", "other"), "format"),
            (DOC.replace("tool:solana-authority-scan", "tool:"), "source"),
            (DOC.replace("tool:solana-authority-scan", "human"), "source"),
            (DOC.replace("\"medium\"", "\"severe\""), "severity"),
            (DOC.replace("\"category\"", "\"colour\""), "unknown field"),
            (DOC.replace("\"d\"", "\"\""), "empty"),
            (DOC.replace("\"d\"", "\"a\\u001b[2Jb\""), "control"),
            (DOC.replace("Time lock is 0", "two\\nlines"), "one line"),
            (
                DOC.replace("\"source\":\"tool", "\"id\":\"C-0009\",\"source\":\"tool"),
                "unknown field",
            ),
        ] {
            let error = parse_document(&bad).unwrap_err();
            assert!(error.contains(why), "{why}: {error}");
        }
        let empty = r#"{"format":"dv-candidates","version":1,"candidates":[]}"#;
        assert!(parse_document(empty).unwrap_err().contains("no candidates"));
    }

    #[test]
    fn document_refuses_what_a_reader_would() {
        let mut parsed = parse_document(DOC).unwrap();
        let (_, finding) = parsed.remove(0);
        assert!(
            document(&[("robot:x".to_owned(), finding.clone())])
                .unwrap_err()
                .contains("source")
        );
        let mut long = finding;
        long.evidence = "x".repeat(MAX_FIELD_CHARS + 1);
        assert!(
            document(&[("tool:x".to_owned(), long)])
                .unwrap_err()
                .contains("longer")
        );
    }

    #[test]
    fn forbidden_characters() {
        for c in [
            '\u{1b}', '\u{202e}', '\u{2028}', '\u{2029}', '\u{FEFF}', '\u{061C}',
        ] {
            let text = format!("a{c}b");
            assert!(check_field("x", &text).is_err(), "{c:?}");
            assert_eq!(
                for_terminal(&text),
                format!("a\\u{{{:04x}}}b", u32::from(c))
            );
        }
        assert!(check_field("x", "fine\ttext\nmore").is_ok());
        assert!(check_field("x", "  ").is_err());
    }

    #[test]
    fn sources() {
        for good in ["tool:solana-authority-scan", "tool:a_b-1"] {
            assert!(check_source(good).is_ok(), "{good}");
        }
        for bad in ["", "person", "tool:", "tool:Admin", "tool:a b", "agent:x"] {
            assert!(check_source(bad).is_err(), "{bad}");
        }
    }
}
