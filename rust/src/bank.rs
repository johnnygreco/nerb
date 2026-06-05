use crate::engine::{DetectorMetadata, NativeEngine};
use crate::error::{validation, BankError, Result};
use crate::flags::{canonicalize_flag_names, merge_flags, parse_flags_value};
use crate::formats::{parse_source_auto, parse_source_value, SourceFormat};
use crate::ids::{bank_hash, entity_stable_id, pattern_stable_id};
use crate::match_buffer::NativeMatchBuffer;
use regex_syntax::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

const CANONICAL_SCHEMA: u32 = 1;
const ENGINE_NAME: &str = "rust-regex-meta";
const MAX_ENTITIES: usize = 10_000;
const MAX_PATTERNS: usize = 100_000;
const MAX_PATTERNS_PER_ENTITY: usize = 50_000;
const MAX_PATTERN_BYTES: usize = 10_000;
const MAX_TOTAL_PATTERN_BYTES: usize = 10_000_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBank {
    pub schema: u32,
    pub defaults: CanonicalDefaults,
    pub entities: Vec<CanonicalEntity>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDefaults {
    pub engine: String,
    pub unicode: bool,
    pub case_insensitive: bool,
    pub word_boundaries: bool,
    pub normalization: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntity {
    pub stable_id: String,
    pub name: String,
    pub patterns: Vec<CanonicalPattern>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPattern {
    pub stable_id: String,
    pub priority: i64,
    pub canonical_name: String,
    pub surface_name: String,
    pub regex: String,
    pub flags: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct NativeBank {
    canonical: CanonicalBank,
    canonical_json: Vec<u8>,
    bank_hash: String,
    compile_options: Value,
    engine: NativeEngine,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompileOptions {
    #[serde(default = "default_match_mode")]
    match_mode: MatchMode,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            match_mode: default_match_mode(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatchMode {
    EntityIndependent,
    AllOverlaps,
    GlobalLeftmost,
}

fn default_match_mode() -> MatchMode {
    MatchMode::EntityIndependent
}

impl MatchMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::EntityIndependent => "entity_independent",
            Self::AllOverlaps => "all_overlaps",
            Self::GlobalLeftmost => "global_leftmost",
        }
    }
}

impl NativeBank {
    pub fn from_source_bytes(
        source: &[u8],
        format_hint: Option<&str>,
        compile_options_json: Option<&str>,
    ) -> Result<Self> {
        let format = SourceFormat::from_hint(format_hint)?;
        let (value, source_format) = match format {
            Some(format) => (parse_source_value(source, format)?, format),
            None => parse_source_auto(source)?,
        };

        if source_format == SourceFormat::CanonicalJson {
            return Self::from_canonical_value(value, compile_options_json);
        }

        match &value {
            Value::Object(object) if is_canonical_json_object(object) => {
                Self::from_canonical_value(value, compile_options_json)
            }
            _ => {
                let canonical = canonicalize_source_value(value, source_format)?;
                Self::from_canonical_bank(canonical, compile_options_json)
            }
        }
    }

    pub fn from_canonical_json_bytes(
        source: &[u8],
        compile_options_json: Option<&str>,
    ) -> Result<Self> {
        let value = parse_source_value(source, SourceFormat::CanonicalJson)?;
        Self::from_canonical_value(value, compile_options_json)
    }

    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn hash(&self) -> &str {
        &self.bank_hash
    }

    pub fn canonical(&self) -> &CanonicalBank {
        &self.canonical
    }

    pub fn compile_options(&self) -> &Value {
        &self.compile_options
    }

    pub fn detectors(&self) -> &[DetectorMetadata] {
        self.engine.detectors()
    }

    pub fn scan_bytes(&self, haystack: &[u8]) -> Result<NativeMatchBuffer> {
        self.engine.scan_bytes(haystack)
    }

    pub fn scan_bytes_into(&self, haystack: &[u8], buffer: &mut NativeMatchBuffer) -> Result<()> {
        self.engine.scan_bytes_into(haystack, buffer)
    }

    pub fn scan_bytes_leftmost_from_all_overlaps(
        &self,
        haystack: &[u8],
        buffer: &mut NativeMatchBuffer,
    ) -> Result<()> {
        self.engine
            .scan_bytes_leftmost_from_all_overlaps(haystack, buffer)
    }

    fn from_canonical_value(value: Value, compile_options_json: Option<&str>) -> Result<Self> {
        let canonical =
            serde_json::from_value::<CanonicalBank>(value).map_err(|error| BankError::Parse {
                format: "canonical_json",
                message: error.to_string(),
            })?;
        Self::from_canonical_bank(canonical, compile_options_json)
    }

    fn from_canonical_bank(
        mut canonical: CanonicalBank,
        compile_options_json: Option<&str>,
    ) -> Result<Self> {
        validate_and_normalize_canonical_bank(&mut canonical)?;
        let compile_options = parse_compile_options_struct(compile_options_json)?;
        let compile_options_value = compile_options_value(&compile_options);
        let canonical_json = serde_json::to_vec(&canonical).expect("canonical bank must serialize");
        let bank_hash = bank_hash(&canonical, &compile_options_value);
        let engine = NativeEngine::compile(&canonical, compile_options.match_mode)?;
        Ok(Self {
            canonical,
            canonical_json,
            bank_hash,
            compile_options: compile_options_value,
            engine,
        })
    }
}

fn parse_compile_options_struct(compile_options_json: Option<&str>) -> Result<CompileOptions> {
    let options = match compile_options_json {
        None => CompileOptions::default(),
        Some(raw) => {
            let value = parse_source_value(raw.as_bytes(), SourceFormat::Json)?;
            if !value.is_object() {
                return Err(validation(
                    "/compile_options",
                    "compile options must be a JSON object because they are part of the semantic bank hash",
                ));
            }
            serde_json::from_value::<CompileOptions>(value).map_err(|error| BankError::Parse {
                format: "compile_options_json",
                message: error.to_string(),
            })?
        }
    };
    Ok(options)
}

fn compile_options_value(options: &CompileOptions) -> Value {
    let value = serde_json::to_value(options).expect("compile options must serialize");
    crate::ids::canonicalize_json_value(&value)
}

fn canonicalize_source_value(value: Value, source_format: SourceFormat) -> Result<CanonicalBank> {
    match source_format {
        SourceFormat::Jsonl => canonicalize_jsonl_rows(value),
        SourceFormat::Json | SourceFormat::Yaml | SourceFormat::CanonicalJson => {
            let object = as_object(&value, "")?;
            if is_current_json_bank_object(object) {
                canonicalize_current_json_bank(object)
            } else if object.contains_key("schema") || object.contains_key("schema_version") {
                Err(validation(
                    "",
                    "compact detector maps cannot use reserved entity names \"schema\" or \"schema_version\"",
                ))
            } else {
                canonicalize_detector_map(object)
            }
        }
    }
}

fn is_canonical_json_object(object: &Map<String, Value>) -> bool {
    matches!(object.get("schema"), Some(Value::Number(_)))
        && matches!(object.get("defaults"), Some(Value::Object(_)))
        && matches!(object.get("entities"), Some(Value::Array(_)))
}

fn is_current_json_bank_object(object: &Map<String, Value>) -> bool {
    matches!(object.get("schema_version"), Some(Value::String(_)))
}

fn canonicalize_jsonl_rows(value: Value) -> Result<CanonicalBank> {
    let rows = match value {
        Value::Array(rows) => rows,
        _ => {
            return Err(validation(
                "",
                "JSONL source must parse to detector row objects",
            ))
        }
    };
    let mut candidates = Vec::new();
    let mut next_priority_by_entity: HashMap<String, i64> = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        let path = format!("/{index}");
        let object = as_object(row, &path)?;
        reject_unknown(
            object,
            &path,
            &[
                "entity",
                "canonical_name",
                "surface_name",
                "regex",
                "flags",
                "priority",
            ],
        )?;
        let entity = required_string(object, "entity", &path)?;
        let canonical_name = required_string(object, "canonical_name", &path)?;
        let surface_name = optional_string(object, "surface_name", &path)?
            .unwrap_or_else(|| canonical_name.clone());
        let regex = required_string(object, "regex", &path)?;
        let flags = parse_flags_value(object.get("flags"), &format!("{path}/flags"))?;
        let source_priority = next_priority_by_entity.entry(entity.clone()).or_insert(0);
        let default_priority = *source_priority;
        *source_priority += 1;
        let priority = Some(optional_i64(object, "priority", &path)?.unwrap_or(default_priority));
        candidates.push(PatternCandidate {
            entity,
            canonical_name,
            surface_name,
            regex,
            flags,
            priority,
        });
    }
    build_canonical_bank(defaults(), candidates)
}

fn canonicalize_detector_map(object: &Map<String, Value>) -> Result<CanonicalBank> {
    if object.is_empty() {
        return Err(validation(
            "",
            "source bank must define at least one entity",
        ));
    }

    let mut candidates = Vec::new();
    let mut entity_names: Vec<&String> = object.keys().collect();
    entity_names.sort();
    for entity_name in entity_names {
        validate_non_empty(entity_name, &format!("/{entity_name}"), "entity names")?;
        let entity_path = format!("/{entity_name}");
        let entity_object = as_object(&object[entity_name], &entity_path)?;
        if entity_object.is_empty() {
            return Err(validation(
                &entity_path,
                "entity must define at least one detector pattern",
            ));
        }
        let entity_flags = parse_flags_value(
            entity_object.get("_flags"),
            &format!("{entity_path}/_flags"),
        )?;
        let mut pattern_names: Vec<&String> = entity_object
            .keys()
            .filter(|key| key.as_str() != "_flags")
            .collect();
        pattern_names.sort();
        if pattern_names.is_empty() {
            return Err(validation(
                &entity_path,
                "entity must define at least one detector pattern",
            ));
        }
        for pattern_name in pattern_names {
            validate_non_empty(
                pattern_name,
                &format!("{entity_path}/{pattern_name}"),
                "pattern names",
            )?;
            let pattern_path = format!("{entity_path}/{pattern_name}");
            let regex = match &entity_object[pattern_name] {
                Value::String(pattern) => pattern.clone(),
                _ => {
                    return Err(validation(
                        &pattern_path,
                        "detector map patterns must be regex strings; use JSONL rows for structured detector input",
                    ))
                }
            };
            candidates.push(PatternCandidate {
                entity: entity_name.clone(),
                canonical_name: pattern_name.clone(),
                surface_name: pattern_name.clone(),
                regex,
                flags: entity_flags.clone(),
                priority: None,
            });
        }
    }
    build_canonical_bank(defaults(), candidates)
}

fn canonicalize_current_json_bank(object: &Map<String, Value>) -> Result<CanonicalBank> {
    reject_unknown(
        object,
        "",
        &[
            "schema_version",
            "id",
            "name",
            "description",
            "version",
            "status",
            "created_at",
            "updated_at",
            "unicode_normalization",
            "default_regex_flags",
            "entities",
            "metadata",
            "eval_refs",
        ],
    )?;
    let schema_version = required_string(object, "schema_version", "")?;
    if schema_version != "nerb.bank.v1" {
        return Err(validation(
            "/schema_version",
            "current JSON bank schema_version must be \"nerb.bank.v1\"",
        ));
    }
    validate_current_id(&required_string(object, "id", "")?, "/id")?;
    let normalization = required_string(object, "unicode_normalization", "")?;
    if normalization != "none" {
        return Err(validation(
            "/unicode_normalization",
            "Rust canonicalization currently supports unicode_normalization \"none\" only",
        ));
    }

    let default_flags =
        parse_flags_value(object.get("default_regex_flags"), "/default_regex_flags")?;
    let entities = as_object(required_value(object, "entities", "")?, "/entities")?;
    if entities.is_empty() {
        return Err(validation(
            "/entities",
            "bank must define at least one entity",
        ));
    }

    let mut candidates = Vec::new();
    let mut entity_ids: Vec<&String> = entities.keys().collect();
    entity_ids.sort();
    for entity_id in entity_ids {
        validate_current_id(entity_id, &format!("/entities/{entity_id}"))?;
        let entity_path = format!("/entities/{entity_id}");
        let entity = as_object(&entities[entity_id], &entity_path)?;
        reject_unknown(
            entity,
            &entity_path,
            &[
                "description",
                "status",
                "regex_flags",
                "names",
                "metadata",
                "eval_refs",
            ],
        )?;
        let entity_flags = parse_flags_value(
            entity.get("regex_flags"),
            &format!("{entity_path}/regex_flags"),
        )?;
        let names = as_object(
            required_value(entity, "names", &entity_path)?,
            &format!("{entity_path}/names"),
        )?;
        if names.is_empty() {
            return Err(validation(
                format!("{entity_path}/names"),
                "entity must define at least one name",
            ));
        }

        let mut name_ids: Vec<&String> = names.keys().collect();
        name_ids.sort();
        for name_id in name_ids {
            validate_current_id(name_id, &format!("{entity_path}/names/{name_id}"))?;
            let name_path = format!("{entity_path}/names/{name_id}");
            let name = as_object(&names[name_id], &name_path)?;
            reject_unknown(
                name,
                &name_path,
                &[
                    "canonical",
                    "description",
                    "status",
                    "patterns",
                    "metadata",
                    "eval_refs",
                ],
            )?;
            let canonical_name = required_string(name, "canonical", &name_path)?;
            let patterns = as_object(
                required_value(name, "patterns", &name_path)?,
                &format!("{name_path}/patterns"),
            )?;
            if patterns.is_empty() {
                return Err(validation(
                    format!("{name_path}/patterns"),
                    "name must define at least one pattern",
                ));
            }

            let mut pattern_ids: Vec<&String> = patterns.keys().collect();
            pattern_ids.sort();
            for pattern_id in pattern_ids {
                validate_current_id(pattern_id, &format!("{name_path}/patterns/{pattern_id}"))?;
                let pattern_path = format!("{name_path}/patterns/{pattern_id}");
                let pattern = as_object(&patterns[pattern_id], &pattern_path)?;
                let candidate = candidate_from_current_pattern(
                    entity_id,
                    &canonical_name,
                    pattern_id,
                    pattern,
                    &pattern_path,
                    &default_flags,
                    &entity_flags,
                )?;
                candidates.push(candidate);
            }
        }
    }
    build_canonical_bank(defaults(), candidates)
}

fn candidate_from_current_pattern(
    entity_id: &str,
    canonical_name: &str,
    pattern_id: &str,
    pattern: &Map<String, Value>,
    path: &str,
    default_flags: &[String],
    entity_flags: &[String],
) -> Result<PatternCandidate> {
    reject_unknown(
        pattern,
        path,
        &[
            "kind",
            "value",
            "description",
            "status",
            "priority",
            "regex_flags",
            "case_sensitive",
            "normalize_whitespace",
            "left_boundary",
            "right_boundary",
            "metadata",
            "eval_refs",
        ],
    )?;
    let kind = required_string(pattern, "kind", path)?;
    let value = required_string(pattern, "value", path)?;
    let priority = Some(required_i64(pattern, "priority", path)?);
    let flags = match kind.as_str() {
        "regex" => {
            reject_present(pattern, "case_sensitive", path, "regex patterns")?;
            reject_present(pattern, "normalize_whitespace", path, "regex patterns")?;
            reject_present(pattern, "left_boundary", path, "regex patterns")?;
            reject_present(pattern, "right_boundary", path, "regex patterns")?;
            let pattern_flags = parse_flags_value(
                Some(required_value(pattern, "regex_flags", path)?),
                &format!("{path}/regex_flags"),
            )?;
            merge_flags(&[default_flags.to_vec(), entity_flags.to_vec(), pattern_flags])?
        }
        "literal" => {
            reject_present(pattern, "regex_flags", path, "literal patterns")?;
            let case_sensitive = required_bool(pattern, "case_sensitive", path)?;
            let mut literal_flags = Vec::new();
            if !case_sensitive {
                literal_flags.push("IGNORECASE".to_string());
            }
            merge_flags(&[default_flags.to_vec(), entity_flags.to_vec(), literal_flags])?
        }
        _ => {
            return Err(validation(
                format!("{path}/kind"),
                "pattern kind must be \"literal\" or \"regex\"",
            ))
        }
    };
    let regex = match kind.as_str() {
        "regex" => value,
        "literal" => literal_regex(
            &value,
            required_bool(pattern, "normalize_whitespace", path)?,
            &required_boundary(pattern, "left_boundary", path)?,
            &required_boundary(pattern, "right_boundary", path)?,
            flags.iter().any(|flag| flag == "VERBOSE"),
        )?,
        _ => unreachable!("kind is validated above"),
    };
    let surface_name = match kind.as_str() {
        "literal" => required_string(pattern, "value", path)?,
        "regex" => pattern_id.to_string(),
        _ => unreachable!("kind is validated above"),
    };

    Ok(PatternCandidate {
        entity: entity_id.to_string(),
        canonical_name: canonical_name.to_string(),
        surface_name,
        regex,
        flags,
        priority,
    })
}

fn literal_regex(
    value: &str,
    normalize_whitespace: bool,
    left: &str,
    right: &str,
    verbose_safe: bool,
) -> Result<String> {
    let escaped = if normalize_whitespace {
        normalize_literal_whitespace(value, verbose_safe)
    } else {
        escape_literal_run(value, verbose_safe)
    };
    let left_boundary = match left {
        "none" => "",
        "word" => r"\b",
        other => {
            return Err(validation(
                "/left_boundary",
                format!("unsupported literal left_boundary {other:?}"),
            ))
        }
    };
    let right_boundary = match right {
        "none" => "",
        "word" => r"\b",
        other => {
            return Err(validation(
                "/right_boundary",
                format!("unsupported literal right_boundary {other:?}"),
            ))
        }
    };
    if left_boundary.is_empty() && right_boundary.is_empty() {
        Ok(escaped)
    } else {
        Ok(format!("{left_boundary}(?:{escaped}){right_boundary}"))
    }
}

fn normalize_literal_whitespace(value: &str, verbose_safe: bool) -> String {
    let mut regex = String::new();
    let mut literal_run = String::new();
    let mut in_whitespace = false;
    for char in value.chars() {
        if char.is_whitespace() {
            if !literal_run.is_empty() {
                regex.push_str(&escape_literal_run(&literal_run, verbose_safe));
                literal_run.clear();
            }
            if !in_whitespace {
                regex.push_str(r"\s+");
                in_whitespace = true;
            }
        } else {
            in_whitespace = false;
            literal_run.push(char);
        }
    }
    if !literal_run.is_empty() {
        regex.push_str(&escape_literal_run(&literal_run, verbose_safe));
    }
    regex
}

fn escape_literal_run(value: &str, verbose_safe: bool) -> String {
    if !verbose_safe {
        return regex_syntax::escape(value);
    }

    let mut escaped = String::new();
    for char in value.chars() {
        if char.is_whitespace() || char == '#' {
            escaped.push_str(&format!(r"\x{{{:X}}}", char as u32));
        } else {
            escaped.push_str(&regex_syntax::escape(&char.to_string()));
        }
    }
    escaped
}

#[derive(Clone, Debug)]
struct PatternCandidate {
    entity: String,
    canonical_name: String,
    surface_name: String,
    regex: String,
    flags: Vec<String>,
    priority: Option<i64>,
}

fn build_canonical_bank(
    defaults: CanonicalDefaults,
    candidates: Vec<PatternCandidate>,
) -> Result<CanonicalBank> {
    if candidates.is_empty() {
        return Err(validation(
            "",
            "source bank must define at least one detector pattern",
        ));
    }
    let mut by_entity: BTreeMap<String, Vec<PatternCandidate>> = BTreeMap::new();
    for mut candidate in candidates {
        validate_candidate(&candidate, &defaults)?;
        candidate.flags = canonicalize_flag_names(candidate.flags, "/flags")?;
        by_entity
            .entry(candidate.entity.clone())
            .or_default()
            .push(candidate);
    }

    if by_entity.len() > MAX_ENTITIES {
        return Err(validation(
            "/entities",
            format!(
                "entity count {} exceeds limit {MAX_ENTITIES}",
                by_entity.len()
            ),
        ));
    }

    let mut total_pattern_bytes = 0usize;
    let mut total_patterns = 0usize;
    let mut duplicate_keys = HashSet::new();
    let mut entities = Vec::with_capacity(by_entity.len());
    for (entity_name, mut entity_patterns) in by_entity {
        if entity_patterns.len() > MAX_PATTERNS_PER_ENTITY {
            return Err(validation(
                format!("/entities/{entity_name}/patterns"),
                format!(
                    "pattern count {} exceeds per-entity limit {MAX_PATTERNS_PER_ENTITY}",
                    entity_patterns.len()
                ),
            ));
        }
        entity_patterns.sort_by(|left, right| {
            (
                left.priority.unwrap_or(i64::MAX),
                &left.canonical_name,
                &left.surface_name,
                &left.regex,
                &left.flags,
            )
                .cmp(&(
                    right.priority.unwrap_or(i64::MAX),
                    &right.canonical_name,
                    &right.surface_name,
                    &right.regex,
                    &right.flags,
                ))
        });
        for (index, pattern) in entity_patterns.iter_mut().enumerate() {
            if pattern.priority.is_none() {
                pattern.priority = Some(index as i64);
            }
        }

        let mut canonical_patterns = Vec::with_capacity(entity_patterns.len());
        for pattern in entity_patterns {
            total_patterns += 1;
            if total_patterns > MAX_PATTERNS {
                return Err(validation(
                    "/entities",
                    format!("pattern count {total_patterns} exceeds bank limit {MAX_PATTERNS}"),
                ));
            }
            total_pattern_bytes += pattern.regex.len();
            if total_pattern_bytes > MAX_TOTAL_PATTERN_BYTES {
                return Err(validation(
                    "/entities",
                    format!("total pattern bytes {total_pattern_bytes} exceeds limit {MAX_TOTAL_PATTERN_BYTES}"),
                ));
            }

            let duplicate_key = format!(
                "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
                entity_name,
                pattern.canonical_name,
                pattern.surface_name,
                pattern.regex,
                pattern.flags.join("\u{0}")
            );
            if !duplicate_keys.insert(duplicate_key) {
                return Err(validation(
                    format!("/entities/{entity_name}/patterns"),
                    format!(
                        "duplicate logical detector for entity {:?}, canonical_name {:?}, surface_name {:?}",
                        entity_name, pattern.canonical_name, pattern.surface_name
                    ),
                ));
            }

            canonical_patterns.push(CanonicalPattern {
                stable_id: pattern_stable_id(
                    &entity_name,
                    &pattern.canonical_name,
                    &pattern.surface_name,
                    &pattern.regex,
                    &pattern.flags,
                    &defaults.normalization,
                ),
                priority: pattern.priority.expect("priority assigned above"),
                canonical_name: pattern.canonical_name,
                surface_name: pattern.surface_name,
                regex: pattern.regex,
                flags: pattern.flags,
            });
        }

        entities.push(CanonicalEntity {
            stable_id: entity_stable_id(&entity_name),
            name: entity_name,
            patterns: canonical_patterns,
        });
    }

    Ok(CanonicalBank {
        schema: CANONICAL_SCHEMA,
        defaults,
        entities,
    })
}

fn validate_and_normalize_canonical_bank(bank: &mut CanonicalBank) -> Result<()> {
    if bank.schema != CANONICAL_SCHEMA {
        return Err(validation(
            "/schema",
            format!(
                "unsupported canonical schema {}; expected {CANONICAL_SCHEMA}",
                bank.schema
            ),
        ));
    }
    validate_defaults(&bank.defaults)?;
    if bank.entities.is_empty() {
        return Err(validation(
            "/entities",
            "canonical bank must define at least one entity",
        ));
    }
    let mut candidates = Vec::new();
    for entity in &bank.entities {
        validate_non_empty(&entity.name, "/entities/name", "entity names")?;
        let expected_entity_id = entity_stable_id(&entity.name);
        if entity.stable_id != expected_entity_id {
            return Err(validation(
                format!("/entities/{}/stable_id", entity.name),
                format!(
                    "invalid entity stable_id {:?}; expected {expected_entity_id:?}",
                    entity.stable_id
                ),
            ));
        }
        if entity.patterns.is_empty() {
            return Err(validation(
                format!("/entities/{}/patterns", entity.name),
                "canonical entity must define at least one pattern",
            ));
        }
        for pattern in &entity.patterns {
            let flags = canonicalize_flag_names(pattern.flags.clone(), "/flags")?;
            let expected_pattern_id = pattern_stable_id(
                &entity.name,
                &pattern.canonical_name,
                &pattern.surface_name,
                &pattern.regex,
                &flags,
                &bank.defaults.normalization,
            );
            if pattern.stable_id != expected_pattern_id {
                return Err(validation(
                    format!(
                        "/entities/{}/patterns/{}/stable_id",
                        entity.name, pattern.canonical_name
                    ),
                    format!(
                        "invalid pattern stable_id {:?}; expected {expected_pattern_id:?}",
                        pattern.stable_id
                    ),
                ));
            }
            candidates.push(PatternCandidate {
                entity: entity.name.clone(),
                canonical_name: pattern.canonical_name.clone(),
                surface_name: pattern.surface_name.clone(),
                regex: pattern.regex.clone(),
                flags: pattern.flags.clone(),
                priority: Some(pattern.priority),
            });
        }
    }
    let rebuilt = build_canonical_bank(bank.defaults.clone(), candidates)?;
    if rebuilt != *bank {
        return Err(validation(
            "",
            "canonical JSON is not in canonical order or contains invalid stable IDs",
        ));
    }
    Ok(())
}

fn validate_candidate(candidate: &PatternCandidate, defaults: &CanonicalDefaults) -> Result<()> {
    validate_non_empty(&candidate.entity, "/entity", "entity names")?;
    validate_non_empty(
        &candidate.canonical_name,
        "/canonical_name",
        "canonical names",
    )?;
    validate_text_field(&candidate.surface_name, "/surface_name", "surface names")?;
    validate_text_field(&candidate.regex, "/regex", "regex patterns")?;
    if candidate.regex.len() > MAX_PATTERN_BYTES {
        return Err(validation(
            "/regex",
            format!(
                "pattern length {} exceeds limit {MAX_PATTERN_BYTES}",
                candidate.regex.len()
            ),
        ));
    }
    if let Some(priority) = candidate.priority {
        if priority < 0 {
            return Err(validation(
                "/priority",
                "pattern priority must be non-negative",
            ));
        }
    }
    validate_defaults(defaults)?;
    Parser::new().parse(&candidate.regex).map_err(|error| {
        validation(
            "/regex",
            format!(
                "unsupported Rust regex syntax for detector {:?}/{:?}: {error}",
                candidate.entity, candidate.canonical_name
            ),
        )
    })?;
    Ok(())
}

fn validate_defaults(defaults: &CanonicalDefaults) -> Result<()> {
    if defaults.engine != ENGINE_NAME {
        return Err(validation(
            "/defaults/engine",
            format!(
                "unsupported engine {:?}; expected {ENGINE_NAME:?}",
                defaults.engine
            ),
        ));
    }
    if !defaults.unicode {
        return Err(validation(
            "/defaults/unicode",
            "Rust canonicalization currently requires unicode=true",
        ));
    }
    if defaults.case_insensitive {
        return Err(validation(
            "/defaults/case_insensitive",
            "bank-level case_insensitive defaults are not supported; migrate flags to patterns",
        ));
    }
    if defaults.word_boundaries {
        return Err(validation(
            "/defaults/word_boundaries",
            "bank-level word_boundaries defaults are not supported; migrate boundaries to patterns",
        ));
    }
    if defaults.normalization != "none" {
        return Err(validation(
            "/defaults/normalization",
            "Rust canonicalization currently supports normalization \"none\" only",
        ));
    }
    Ok(())
}

fn defaults() -> CanonicalDefaults {
    CanonicalDefaults {
        engine: ENGINE_NAME.to_string(),
        unicode: true,
        case_insensitive: false,
        word_boundaries: false,
        normalization: "none".to_string(),
    }
}

fn as_object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(validation(path, "expected an object")),
    }
}

fn reject_unknown(object: &Map<String, Value>, path: &str, allowed: &[&str]) -> Result<()> {
    let allowed_set: HashSet<&str> = allowed.iter().copied().collect();
    for key in object.keys() {
        if !allowed_set.contains(key.as_str()) {
            let field_path = if path.is_empty() {
                format!("/{key}")
            } else {
                format!("{path}/{key}")
            };
            return Err(validation(field_path, format!("unknown field {key:?}")));
        }
    }
    Ok(())
}

fn reject_present(object: &Map<String, Value>, key: &str, path: &str, context: &str) -> Result<()> {
    if object.contains_key(key) {
        return Err(validation(
            field_path(path, key),
            format!("field {key:?} is not allowed for {context}"),
        ));
    }
    Ok(())
}

fn required_value<'a>(object: &'a Map<String, Value>, key: &str, path: &str) -> Result<&'a Value> {
    object.get(key).ok_or_else(|| {
        validation(
            if path.is_empty() {
                format!("/{key}")
            } else {
                format!("{path}/{key}")
            },
            format!("missing required field {key:?}"),
        )
    })
}

fn required_string(object: &Map<String, Value>, key: &str, path: &str) -> Result<String> {
    let value = required_value(object, key, path)?;
    match value {
        Value::String(text) => Ok(text.clone()),
        _ => Err(validation(
            field_path(path, key),
            format!("field {key:?} must be a string"),
        )),
    }
}

fn optional_string(object: &Map<String, Value>, key: &str, path: &str) -> Result<Option<String>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(validation(
            field_path(path, key),
            format!("field {key:?} must be a string"),
        )),
    }
}

fn required_bool(object: &Map<String, Value>, key: &str, path: &str) -> Result<bool> {
    let value = required_value(object, key, path)?;
    match value {
        Value::Bool(value) => Ok(*value),
        _ => Err(validation(
            field_path(path, key),
            format!("field {key:?} must be a boolean"),
        )),
    }
}

fn required_i64(object: &Map<String, Value>, key: &str, path: &str) -> Result<i64> {
    let value = required_value(object, key, path)?;
    value.as_i64().ok_or_else(|| {
        validation(
            field_path(path, key),
            format!("field {key:?} must be an integer"),
        )
    })
}

fn optional_i64(object: &Map<String, Value>, key: &str, path: &str) -> Result<Option<i64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            validation(
                field_path(path, key),
                format!("field {key:?} must be an integer"),
            )
        }),
    }
}

fn required_boundary(object: &Map<String, Value>, key: &str, path: &str) -> Result<String> {
    let boundary = required_string(object, key, path)?;
    if boundary != "none" && boundary != "word" {
        return Err(validation(
            field_path(path, key),
            format!("field {key:?} must be \"none\" or \"word\""),
        ));
    }
    Ok(boundary)
}

fn validate_non_empty(value: &str, path: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(validation(
            path,
            format!("{label} must be non-empty strings"),
        ));
    }
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(validation(
            path,
            format!("{label} cannot contain control separators"),
        ));
    }
    Ok(())
}

fn validate_text_field(value: &str, path: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(validation(
            path,
            format!("{label} must be non-empty strings"),
        ));
    }
    if value.contains('\0') {
        return Err(validation(
            path,
            format!("{label} cannot contain NUL bytes"),
        ));
    }
    Ok(())
}

fn validate_current_id(value: &str, path: &str) -> Result<()> {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => {
            return Err(validation(
                path,
                "current JSON bank IDs must start with a lowercase ASCII letter",
            ))
        }
    }
    if value.len() > 80
        || !chars.all(|char| char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_')
    {
        return Err(validation(
            path,
            "current JSON bank IDs must match ^[a-z][a-z0-9_]{0,79}$",
        ));
    }
    Ok(())
}

fn field_path(path: &str, key: &str) -> String {
    if path.is_empty() {
        format!("/{key}")
    } else {
        format!("{path}/{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_bank_source_with_pattern(pattern: Value) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "nerb.bank.v1",
            "id": "company_entities",
            "unicode_normalization": "none",
            "default_regex_flags": [],
            "entities": {
                "customer": {
                    "regex_flags": [],
                    "names": {
                        "acme_corp": {
                            "canonical": "Acme Corp",
                            "patterns": {
                                "primary": pattern,
                            }
                        }
                    }
                }
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn yaml_detector_map_canonicalizes_flags_and_ids() {
        let bank = NativeBank::from_source_bytes(
            br#"
GENRE:
  _flags: IGNORECASE
  Rock: rock
"#,
            Some("yaml"),
            None,
        )
        .unwrap();
        let canonical = bank.canonical();

        assert_eq!(canonical.entities[0].name, "GENRE");
        assert_eq!(canonical.entities[0].patterns[0].canonical_name, "Rock");
        assert_eq!(canonical.entities[0].patterns[0].flags, ["IGNORECASE"]);
        assert!(canonical.entities[0]
            .stable_id
            .starts_with("entity:sha256:"));
        assert!(canonical.entities[0].patterns[0]
            .stable_id
            .starts_with("pattern:sha256:"));
    }

    #[test]
    fn jsonl_preserves_distinct_same_regex_detectors() {
        let source = br#"
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
{"entity":"CODE","canonical_name":"Beta","surface_name":"B","regex":"A"}
"#;

        let bank = NativeBank::from_source_bytes(source, Some("jsonl"), None).unwrap();

        assert_eq!(bank.canonical().entities[0].patterns.len(), 2);
        assert_ne!(
            bank.canonical().entities[0].patterns[0].stable_id,
            bank.canonical().entities[0].patterns[1].stable_id,
        );
    }

    #[test]
    fn exact_duplicate_logical_detectors_are_rejected() {
        let source = br#"
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
{"entity":"CODE","canonical_name":"Alpha","surface_name":"A","regex":"A"}
"#;

        let error = NativeBank::from_source_bytes(source, Some("jsonl"), None).unwrap_err();

        assert!(error.to_string().contains("duplicate logical detector"));
    }

    #[test]
    fn current_json_bank_rejects_kind_specific_pattern_fields() {
        let literal_with_regex_flags = current_bank_source_with_pattern(serde_json::json!({
            "kind": "literal",
            "value": "Acme Corp",
            "priority": 0,
            "case_sensitive": false,
            "normalize_whitespace": true,
            "left_boundary": "word",
            "right_boundary": "word",
            "regex_flags": [],
        }));
        let error = NativeBank::from_source_bytes(&literal_with_regex_flags, Some("json"), None)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("not allowed for literal patterns"));

        let regex_missing_flags = current_bank_source_with_pattern(serde_json::json!({
            "kind": "regex",
            "value": "Acme",
            "priority": 0,
        }));
        let error =
            NativeBank::from_source_bytes(&regex_missing_flags, Some("json"), None).unwrap_err();
        assert!(error
            .to_string()
            .contains("missing required field \"regex_flags\""));

        let regex_with_literal_field = current_bank_source_with_pattern(serde_json::json!({
            "kind": "regex",
            "value": "Acme",
            "priority": 0,
            "regex_flags": [],
            "case_sensitive": false,
        }));
        let error = NativeBank::from_source_bytes(&regex_with_literal_field, Some("json"), None)
            .unwrap_err();
        assert!(error.to_string().contains("not allowed for regex patterns"));
    }

    #[test]
    fn hash_changes_with_compile_options() {
        let source = br#"{"CODE":{"Alpha":"A"}}"#;
        let first = NativeBank::from_source_bytes(source, Some("json"), None).unwrap();
        let second = NativeBank::from_source_bytes(
            source,
            Some("json"),
            Some(r#"{"match_mode":"all_overlaps"}"#),
        )
        .unwrap();

        assert_ne!(first.hash(), second.hash());
    }
}
