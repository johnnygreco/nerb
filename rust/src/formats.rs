use crate::error::{validation, BankError, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;

const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSONL_ROWS: usize = 100_000;
const MAX_JSONL_LINE_BYTES: usize = 256 * 1024;
const MAX_CONTAINER_DEPTH: usize = 128;

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
    match parse_json(bytes) {
        Ok(value) => {
            if is_jsonl_row_object(&value) {
                return Ok((Value::Array(vec![value]), SourceFormat::Jsonl));
            }
            return Ok((value, SourceFormat::Json));
        }
        Err(error) => {
            if looks_like_jsonl(bytes) {
                match parse_jsonl(bytes) {
                    Ok(value) => return Ok((value, SourceFormat::Jsonl)),
                    Err(jsonl_error) => return Err(jsonl_error),
                }
            }
            if starts_like_json(bytes) {
                return Err(error);
            }
        }
    }

    parse_yaml(bytes).map(|value| (value, SourceFormat::Yaml))
}

fn is_jsonl_row_object(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key("entity")
                && object.contains_key("canonical_name")
                && object.contains_key("regex")
        }
        _ => false,
    }
}

fn parse_json(bytes: &[u8]) -> Result<Value> {
    enforce_source_size(bytes, "json")?;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = JsonValueSeed::root()
        .deserialize(&mut deserializer)
        .map_err(|error| BankError::Parse {
            format: "json",
            message: error.to_string(),
        })?;
    deserializer.end().map_err(|error| BankError::Parse {
        format: "json",
        message: error.to_string(),
    })?;
    Ok(value)
}

fn parse_yaml(bytes: &[u8]) -> Result<Value> {
    enforce_source_size(bytes, "yaml")?;
    let deserializer = serde_yaml::Deserializer::from_slice(bytes);
    JsonValueSeed::root()
        .deserialize(deserializer)
        .map_err(|error| BankError::Parse {
            format: "yaml",
            message: error.to_string(),
        })
}

fn parse_jsonl(bytes: &[u8]) -> Result<Value> {
    enforce_source_size(bytes, "jsonl")?;
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
        if rows.len() == MAX_JSONL_ROWS {
            return Err(validation(
                "",
                format!("JSONL row count exceeds limit {MAX_JSONL_ROWS}"),
            ));
        }
        if trimmed.len() > MAX_JSONL_LINE_BYTES {
            return Err(validation(
                format!("/{}", line_index + 1),
                format!(
                    "JSONL line length {} exceeds limit {MAX_JSONL_LINE_BYTES}",
                    trimmed.len()
                ),
            ));
        }
        let mut deserializer = serde_json::Deserializer::from_str(trimmed);
        let row = JsonValueSeed::new(format!("/{}", rows.len()), 0)
            .deserialize(&mut deserializer)
            .map_err(|error| BankError::Parse {
                format: "jsonl",
                message: format!("line {}: {error}", line_index + 1),
            })?;
        deserializer.end().map_err(|error| BankError::Parse {
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

fn starts_like_json(bytes: &[u8]) -> bool {
    matches!(
        bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace()),
        Some(b'{') | Some(b'[')
    )
}

fn enforce_source_size(bytes: &[u8], format: &'static str) -> Result<()> {
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(validation(
            "",
            format!(
                "{format} source size {} exceeds limit {MAX_SOURCE_BYTES}",
                bytes.len()
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct JsonValueSeed {
    path: String,
    depth: usize,
}

impl JsonValueSeed {
    fn root() -> Self {
        Self::new(String::new(), 0)
    }

    fn new(path: String, depth: usize) -> Self {
        Self { path, depth }
    }

    fn child(&self, key: &str) -> Self {
        Self::new(json_pointer_child(&self.path, key), self.depth + 1)
    }
}

impl<'de> DeserializeSeed<'de> for JsonValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_CONTAINER_DEPTH {
            return Err(de::Error::custom(format!(
                "source nesting at {} exceeds limit {MAX_CONTAINER_DEPTH}",
                display_path(&self.path),
            )));
        }
        deserializer.deserialize_any(JsonValueVisitor { seed: self })
    }
}

struct JsonValueVisitor {
    seed: JsonValueSeed,
}

impl<'de> Visitor<'de> for JsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-compatible source value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| {
                E::custom(format!(
                    "non-finite number at {}",
                    display_path(&self.seed.path)
                ))
            })
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) =
            access.next_element_seed(self.seed.child(&values.len().to_string()))?
        {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut access: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = serde_json::Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = access.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate key {key:?} at {}",
                    display_path(&self.seed.path),
                )));
            }
            let value = access.next_value_seed(self.seed.child(&key))?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn json_pointer_child(parent: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    if parent.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{parent}/{escaped}")
    }
}

fn display_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}
