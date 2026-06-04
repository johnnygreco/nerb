use crate::error::{validation, Result};
use serde_json::Value;
use std::collections::HashSet;

const FLAG_ORDER: [&str; 5] = ["ASCII", "IGNORECASE", "MULTILINE", "DOTALL", "VERBOSE"];

pub fn canonicalize_flag_values(values: &[Value], path: &str) -> Result<Vec<String>> {
    let mut flags = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match value {
            Value::String(flag) => {
                flags.push(normalize_flag_name(flag, &format!("{path}/{index}"))?)
            }
            _ => {
                return Err(validation(
                    format!("{path}/{index}"),
                    "regex flags must be strings in Rust source banks",
                ))
            }
        }
    }
    canonicalize_flag_names(flags, path)
}

pub fn canonicalize_flag_names(values: Vec<String>, path: &str) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut flags = Vec::new();
    for value in values {
        let flag = normalize_flag_name(&value, path)?;
        if seen.insert(flag.clone()) {
            flags.push(flag);
        }
    }
    flags.sort_by_key(|flag| {
        FLAG_ORDER
            .iter()
            .position(|known| known == flag)
            .expect("normalize_flag_name only returns supported flags")
    });
    Ok(flags)
}

pub fn parse_flags_value(value: Option<&Value>, path: &str) -> Result<Vec<String>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(flag)) => canonicalize_flag_names(vec![flag.clone()], path),
        Some(Value::Array(flags)) => canonicalize_flag_values(flags, path),
        Some(_) => Err(validation(
            path,
            "regex flags must be a flag string or an array of flag strings",
        )),
    }
}

pub fn merge_flags(flag_sets: &[Vec<String>]) -> Result<Vec<String>> {
    let mut merged = Vec::new();
    for flags in flag_sets {
        merged.extend(flags.iter().cloned());
    }
    canonicalize_flag_names(merged, "/flags")
}

fn normalize_flag_name(raw: &str, path: &str) -> Result<String> {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix("re.").unwrap_or(trimmed);
    let upper = stripped.to_ascii_uppercase();
    if FLAG_ORDER.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(validation(
            path,
            format!(
                "unsupported regex flag {raw:?}; supported flags are {}",
                FLAG_ORDER.join(", ")
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_deduplicated_and_sorted() {
        let flags = canonicalize_flag_names(
            vec![
                "verbose".to_string(),
                "IGNORECASE".to_string(),
                "re.ASCII".to_string(),
                "IGNORECASE".to_string(),
            ],
            "/flags",
        )
        .unwrap();

        assert_eq!(flags, ["ASCII", "IGNORECASE", "VERBOSE"]);
    }

    #[test]
    fn unsupported_flags_fail() {
        let error = canonicalize_flag_names(vec!["UNICODE".to_string()], "/flags").unwrap_err();

        assert!(error.to_string().contains("unsupported regex flag"));
    }
}
