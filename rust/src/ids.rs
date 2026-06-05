use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn entity_stable_id(name: &str) -> String {
    format!("entity:sha256:{}", digest_prefixed(&["entity", name]))
}

pub fn pattern_stable_id(
    entity: &str,
    canonical_name: &str,
    surface_name: &str,
    regex: &str,
    flags: &[String],
    word_boundaries: bool,
    normalization: &str,
) -> String {
    let mut fields = vec![
        "pattern".to_string(),
        entity.to_string(),
        canonical_name.to_string(),
        surface_name.to_string(),
        regex.to_string(),
        word_boundaries.to_string(),
        normalization.to_string(),
    ];
    fields.extend(flags.iter().cloned());
    let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
    format!("pattern:sha256:{}", digest_prefixed(&refs))
}

pub fn bank_hash<T: Serialize>(canonical_bank: &T, compile_options: &Value) -> String {
    let payload = serde_json::json!({
        "semantic_hash_version": 1,
        "canonical_bank": canonical_bank,
        "compile_options": canonicalize_json_value(compile_options),
    });
    let bytes = serde_json::to_vec(&payload).expect("hash payload must serialize");
    format!("sha256:{}", digest_bytes(&bytes))
}

pub fn canonicalize_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json_value).collect()),
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize_json_value(&object[key]));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn digest_prefixed(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hex(&hasher.finalize())
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bank_hash_sorts_compile_option_keys() {
        let bank = serde_json::json!({"schema": 1});
        let first = serde_json::json!({"mode": "entity_independent", "limits": {"b": 2, "a": 1}});
        let second = serde_json::json!({"limits": {"a": 1, "b": 2}, "mode": "entity_independent"});

        assert_eq!(bank_hash(&bank, &first), bank_hash(&bank, &second));
    }

    #[test]
    fn bank_hash_changes_when_compile_options_change() {
        let bank = serde_json::json!({"schema": 1});

        assert_ne!(
            bank_hash(
                &bank,
                &serde_json::json!({"match_mode": "entity_independent"})
            ),
            bank_hash(&bank, &serde_json::json!({"match_mode": "all_overlaps"})),
        );
    }
}
