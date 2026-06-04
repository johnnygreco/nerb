use crate::bank::{CanonicalBank, MatchMode};
use crate::error::{validation, Result};
use crate::match_buffer::{NativeMatchBuffer, RawMatch};
use regex_automata::meta::Regex;
use regex_automata::{MatchKind, PatternID};
use regex_syntax::hir::Hir;
use regex_syntax::ParserBuilder;

const ENTITY_INDEPENDENT_NFA_SIZE_LIMIT: usize = 10 * 1024 * 1024;
const ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_DFA_STATE_LIMIT: usize = 1_000;

#[derive(Clone, Debug)]
pub struct NativeEngine {
    match_mode: MatchMode,
    detectors: Vec<DetectorMetadata>,
    shards: Vec<MatcherShard>,
}

#[derive(Clone, Debug)]
pub struct DetectorMetadata {
    pub detector_index: u32,
    pub entity: String,
    pub canonical_name: String,
    pub surface_name: String,
    pub stable_id: String,
    pub priority: i64,
}

#[derive(Clone, Debug)]
struct MatcherShard {
    entity: String,
    regex: Regex,
    local_to_detector: Vec<u32>,
}

impl NativeEngine {
    pub fn compile(canonical: &CanonicalBank, match_mode: MatchMode) -> Result<Self> {
        let detectors = detector_metadata(canonical)?;
        let shards = compile_entity_independent(canonical)?;
        Ok(Self {
            match_mode,
            detectors,
            shards,
        })
    }

    pub fn detectors(&self) -> &[DetectorMetadata] {
        &self.detectors
    }

    pub fn scan_bytes(&self, haystack: &[u8]) -> Result<NativeMatchBuffer> {
        let mut buffer = NativeMatchBuffer::new();
        self.scan_bytes_into(haystack, &mut buffer)?;
        Ok(buffer)
    }

    pub fn scan_bytes_into(&self, haystack: &[u8], buffer: &mut NativeMatchBuffer) -> Result<()> {
        buffer.clear();
        if self.match_mode != MatchMode::EntityIndependent {
            return Err(validation(
                "/compile_options/match_mode",
                format!(
                    "Bank.scan_bytes currently supports match_mode {:?} only; got {:?}",
                    MatchMode::EntityIndependent.as_str(),
                    self.match_mode.as_str()
                ),
            ));
        }
        std::str::from_utf8(haystack).map_err(|error| {
            validation(
                "/scan_bytes/haystack",
                format!("Bank.scan_bytes requires valid UTF-8 input: {error}"),
            )
        })?;

        let result = scan_entity_independent(&self.shards, haystack, buffer);
        if result.is_err() {
            buffer.clear();
        }
        result
    }
}

fn scan_entity_independent(
    shards: &[MatcherShard],
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    for shard in shards {
        for raw_match in shard.regex.find_iter(haystack) {
            let local_index = raw_match.pattern().as_usize();
            let Some(&detector_index) = shard.local_to_detector.get(local_index) else {
                return Err(validation(
                    format!("/engine/shards/{}/local_to_detector", shard.entity),
                    format!(
                        "regex engine returned local pattern index {local_index} outside detector map"
                    ),
                ));
            };
            buffer.push(RawMatch::new(
                detector_index,
                raw_match.start() as u64,
                raw_match.end() as u64,
            )?)?;
        }
    }
    buffer.sort();
    Ok(())
}

fn detector_metadata(canonical: &CanonicalBank) -> Result<Vec<DetectorMetadata>> {
    let mut detectors = Vec::new();
    for entity in &canonical.entities {
        for pattern in &entity.patterns {
            let detector_index = u32::try_from(detectors.len()).map_err(|_| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
            detectors.push(DetectorMetadata {
                detector_index,
                entity: entity.name.clone(),
                canonical_name: pattern.canonical_name.clone(),
                surface_name: pattern.surface_name.clone(),
                stable_id: pattern.stable_id.clone(),
                priority: pattern.priority,
            });
        }
    }
    Ok(detectors)
}

fn compile_entity_independent(canonical: &CanonicalBank) -> Result<Vec<MatcherShard>> {
    let mut shards = Vec::with_capacity(canonical.entities.len());
    let mut next_detector_index = 0u32;
    for entity in &canonical.entities {
        let mut patterns = Vec::with_capacity(entity.patterns.len());
        let mut local_to_detector = Vec::with_capacity(entity.patterns.len());
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            patterns.push(parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?);
            local_to_detector.push(next_detector_index);
            next_detector_index = next_detector_index.checked_add(1).ok_or_else(|| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
        }

        let regex = Regex::builder()
            .configure(
                Regex::config()
                    .match_kind(MatchKind::LeftmostFirst)
                    .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT))
                    .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                    .hybrid_cache_capacity(ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY)
                    .dfa_size_limit(Some(ENTITY_INDEPENDENT_DFA_SIZE_LIMIT))
                    .dfa_state_limit(Some(ENTITY_INDEPENDENT_DFA_STATE_LIMIT)),
            )
            .build_many_from_hir(&patterns)
            .map_err(|error| {
                let path = match error.pattern() {
                    Some(pattern_id) => pattern_path(&entity.name, pattern_id),
                    None => format!("/entities/{}/patterns", entity.name),
                };
                validation(
                    path,
                    format!(
                        "could not compile entity-independent regex matcher for entity {:?}: {error}",
                        entity.name
                    ),
                )
            })?;

        shards.push(MatcherShard {
            entity: entity.name.clone(),
            regex,
            local_to_detector,
        });
    }
    Ok(shards)
}

fn pattern_path(entity_name: &str, pattern_id: PatternID) -> String {
    format!("/entities/{entity_name}/patterns/{}", pattern_id.as_usize())
}

fn parse_pattern_with_flags(
    entity_name: &str,
    pattern_index: usize,
    regex: &str,
    flags: &[String],
) -> Result<Hir> {
    let mut parser = ParserBuilder::new();
    for flag in flags {
        match flag.as_str() {
            "ASCII" => {
                return Err(validation(
                    pattern_path_by_index(entity_name, pattern_index),
                    "ASCII regex flag is not supported by the UTF-8 native scan path yet",
                ))
            }
            "DOTALL" => {
                parser.dot_matches_new_line(true);
            }
            "IGNORECASE" => {
                parser.case_insensitive(true);
            }
            "MULTILINE" => {
                parser.multi_line(true);
            }
            "VERBOSE" => {
                parser.ignore_whitespace(true);
            }
            _ => {}
        }
    }
    parser.build().parse(regex).map_err(|error| {
        validation(
            pattern_path_by_index(entity_name, pattern_index),
            format!("unsupported Rust regex syntax for native scanner: {error}"),
        )
    })
}

fn pattern_path_by_index(entity_name: &str, pattern_index: usize) -> String {
    format!("/entities/{entity_name}/patterns/{pattern_index}")
}

#[cfg(test)]
mod tests {
    use crate::bank::NativeBank;

    fn raw_matches(bank: NativeBank, text: &str) -> Vec<(u32, u64, u64)> {
        let buffer = bank.scan_bytes(text.as_bytes()).unwrap();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    #[test]
    fn entity_independent_scan_preserves_cross_entity_overlap() {
        let bank = NativeBank::from_source_bytes(
            br#"{"PERSON":{"Sam":"Sam"},"PROJECT":{"Samba":"Samba"}}"#,
            Some("json"),
            None,
        )
        .unwrap();

        assert_eq!(raw_matches(bank, "Samba ships"), [(0, 0, 3), (1, 0, 5)]);
    }

    #[test]
    fn entity_independent_scan_uses_leftmost_first_within_entity() {
        let bank = NativeBank::from_source_bytes(
            br#"{"PERSON":{"Sam":"Sam","Samba":"Samba"}}"#,
            Some("json"),
            None,
        )
        .unwrap();

        assert_eq!(raw_matches(bank, "Samba ships"), [(0, 0, 3)]);
    }

    #[test]
    fn entity_independent_scan_honors_regex_flags() {
        let bank = NativeBank::from_source_bytes(
            br#"{"GENRE":{"_flags":"IGNORECASE","Jazz":"jazz"}}"#,
            Some("json"),
            None,
        )
        .unwrap();

        assert_eq!(raw_matches(bank, "JaZz"), [(0, 0, 4)]);
    }

    #[test]
    fn scan_rejects_invalid_utf8() {
        let bank = NativeBank::from_source_bytes(br#"{"CODE":{"Alpha":"A"}}"#, Some("json"), None)
            .unwrap();
        let error = bank.scan_bytes(&[0xff]).unwrap_err();

        assert!(error.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn future_match_modes_still_enforce_compile_limits() {
        let source =
            br#"{"entity":"CODE","canonical_name":"Bomb","surface_name":"Bomb","regex":"(?:a{1000000}){1000000}"}"#;
        let error = NativeBank::from_source_bytes(
            source,
            Some("jsonl"),
            Some(r#"{"match_mode":"all_overlaps"}"#),
        )
        .unwrap_err();

        assert!(error.to_string().contains("could not compile"));
    }
}
