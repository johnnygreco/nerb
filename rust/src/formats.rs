use crate::error::{BankError, Result};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceFormat {
    Json,
    Yaml,
    Jsonl,
    CanonicalJson,
}

impl SourceFormat {
    pub fn from_hint(hint: Option<&str>) -> Result<Option<Self>> {
        let Some(hint) = hint else {
            return Ok(None);
        };
        let normalized = hint.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "" => Ok(None),
            "json" => Ok(Some(Self::Json)),
            "yaml" | "yml" => Ok(Some(Self::Yaml)),
            "jsonl" | "ndjson" => Ok(Some(Self::Jsonl)),
            "canonical_json" | "canonical" => Ok(Some(Self::CanonicalJson)),
            _ => Err(BankError::UnsupportedFormat(hint.to_string())),
        }
    }
}

pub fn parse_source_value(bytes: &[u8], format: SourceFormat) -> Result<Value> {
    match format {
        SourceFormat::Json | SourceFormat::CanonicalJson => parse_json(bytes),
        SourceFormat::Yaml => parse_yaml(bytes),
        SourceFormat::Jsonl => parse_jsonl(bytes),
    }
}

pub fn parse_source_auto(bytes: &[u8]) -> Result<(Value, SourceFormat)> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        return Ok((value, SourceFormat::Json));
    }

    if looks_like_jsonl(bytes) {
        if let Ok(value) = parse_jsonl(bytes) {
            return Ok((value, SourceFormat::Jsonl));
        }
    }

    parse_yaml(bytes).map(|value| (value, SourceFormat::Yaml))
}

fn parse_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|error| BankError::Parse {
        format: "json",
        message: error.to_string(),
    })
}

fn parse_yaml(bytes: &[u8]) -> Result<Value> {
    let value =
        serde_yaml::from_slice::<serde_yaml::Value>(bytes).map_err(|error| BankError::Parse {
            format: "yaml",
            message: error.to_string(),
        })?;
    serde_json::to_value(value).map_err(|error| BankError::Parse {
        format: "yaml",
        message: error.to_string(),
    })
}

fn parse_jsonl(bytes: &[u8]) -> Result<Value> {
    let source = std::str::from_utf8(bytes).map_err(|error| BankError::Parse {
        format: "jsonl",
        message: error.to_string(),
    })?;
    let mut rows = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row = serde_json::from_str::<Value>(trimmed).map_err(|error| BankError::Parse {
            format: "jsonl",
            message: format!("line {}: {error}", line_index + 1),
        })?;
        rows.push(row);
    }
    Ok(Value::Array(rows))
}

fn looks_like_jsonl(bytes: &[u8]) -> bool {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut non_empty = source.lines().filter(|line| !line.trim().is_empty());
    let Some(first) = non_empty.next() else {
        return false;
    };
    first.trim_start().starts_with('{') && non_empty.next().is_some()
}
