use crate::bank::{CanonicalBank, CanonicalPattern, MatchMode};
use crate::error::{validation, Result};
use crate::match_buffer::{NativeMatchBuffer, RawMatch};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind as AhoMatchKind};
use regex_automata::hybrid::dfa::{Cache as HybridCache, OverlappingState, DFA as HybridDfa};
use regex_automata::meta::Regex;
use regex_automata::nfa::thompson::{self, WhichCaptures};
use regex_automata::{Anchored, Input, MatchKind as RegexMatchKind, PatternID};
use regex_syntax::hir::Hir;
use regex_syntax::ParserBuilder;
use std::sync::{Arc, Mutex};

const ENTITY_INDEPENDENT_NFA_SIZE_LIMIT: usize = 10 * 1024 * 1024;
const ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_DFA_STATE_LIMIT: usize = 1_000;

#[derive(Debug)]
pub struct NativeEngine {
    match_mode: MatchMode,
    detectors: Vec<DetectorMetadata>,
    shards: Vec<MatcherShard>,
    all_overlaps: Option<AllOverlapsMatcher>,
    global_leftmost: Option<GlobalLeftmostMatcher>,
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

#[derive(Debug)]
enum MatcherShard {
    Regex(RegexMatcherShard),
    Literal(LiteralMatcherShard),
}

#[derive(Debug)]
struct RegexMatcherShard {
    entity: String,
    regex: Regex,
    local_to_detector: Vec<u32>,
}

#[derive(Debug)]
struct LiteralMatcherShard {
    entity: String,
    matcher: AhoCorasick,
    case_insensitive: bool,
    local_to_detector: Vec<u32>,
    fallback_patterns: Option<Vec<Hir>>,
    fallback_regex: Mutex<Option<Arc<Regex>>>,
}

#[derive(Debug)]
struct SimpleLiteralPattern {
    value: String,
    case_insensitive: bool,
}

#[derive(Clone, Debug)]
struct AllOverlapsMatcher {
    forward: HybridDfa,
    reverse: HybridDfa,
    local_to_detector: Vec<u32>,
}

#[derive(Clone, Debug)]
struct GlobalLeftmostMatcher {
    regex: Regex,
    local_to_detector: Vec<u32>,
}

impl NativeEngine {
    pub fn compile(canonical: &CanonicalBank, match_mode: MatchMode) -> Result<Self> {
        let detectors = detector_metadata(canonical)?;
        let shards = if matches!(
            match_mode,
            MatchMode::EntityIndependent | MatchMode::AllOverlaps
        ) {
            compile_entity_independent(canonical)?
        } else {
            Vec::new()
        };
        let all_overlaps = if match_mode == MatchMode::AllOverlaps {
            Some(compile_all_overlaps(canonical)?)
        } else {
            None
        };
        let global_leftmost = if match_mode == MatchMode::GlobalLeftmost {
            Some(compile_global_leftmost(canonical)?)
        } else {
            None
        };
        Ok(Self {
            match_mode,
            detectors,
            shards,
            all_overlaps,
            global_leftmost,
        })
    }

    pub fn detectors(&self) -> &[DetectorMetadata] {
        &self.detectors
    }

    pub fn match_mode(&self) -> MatchMode {
        self.match_mode
    }

    pub fn scan_bytes(&self, haystack: &[u8]) -> Result<NativeMatchBuffer> {
        let mut buffer = NativeMatchBuffer::new();
        self.scan_bytes_into(haystack, &mut buffer)?;
        Ok(buffer)
    }

    pub fn scan_bytes_bounded(
        &self,
        haystack: &[u8],
        max_matches: usize,
    ) -> Result<NativeMatchBuffer> {
        let mut buffer = NativeMatchBuffer::with_match_limit(max_matches)?;
        self.scan_bytes_into(haystack, &mut buffer)?;
        Ok(buffer)
    }

    pub fn scan_bytes_into(&self, haystack: &[u8], buffer: &mut NativeMatchBuffer) -> Result<()> {
        buffer.clear();
        std::str::from_utf8(haystack).map_err(|error| {
            validation(
                "/scan_bytes/haystack",
                format!("Bank.scan_bytes requires valid UTF-8 input: {error}"),
            )
        })?;

        let result = match self.match_mode {
            MatchMode::EntityIndependent => scan_entity_independent(&self.shards, haystack, buffer),
            MatchMode::AllOverlaps => scan_all_overlaps(
                self.all_overlaps
                    .as_ref()
                    .expect("all_overlaps matcher must exist for all_overlaps mode"),
                haystack,
                buffer,
            ),
            MatchMode::GlobalLeftmost => scan_global_leftmost(
                self.global_leftmost
                    .as_ref()
                    .expect("global_leftmost matcher must exist for global_leftmost mode"),
                haystack,
                buffer,
            ),
        };
        if result.is_err() {
            buffer.clear();
        }
        result
    }

    pub fn scan_bytes_leftmost_from_all_overlaps(
        &self,
        haystack: &[u8],
        buffer: &mut NativeMatchBuffer,
    ) -> Result<()> {
        buffer.clear();
        if self.match_mode != MatchMode::AllOverlaps {
            return Err(validation(
                "/compile_options/match_mode",
                format!(
                    "Bank.scan_bytes_leftmost_from_all_overlaps requires match_mode {:?}; got {:?}",
                    MatchMode::AllOverlaps.as_str(),
                    self.match_mode.as_str()
                ),
            ));
        }
        std::str::from_utf8(haystack).map_err(|error| {
            validation(
                "/scan_bytes/haystack",
                format!("Bank.scan_bytes_leftmost_from_all_overlaps requires valid UTF-8 input: {error}"),
            )
        })?;

        let mut raw = NativeMatchBuffer::new();
        let result = scan_all_overlaps(
            self.all_overlaps
                .as_ref()
                .expect("all_overlaps matcher must exist for all_overlaps mode"),
            haystack,
            &mut raw,
        )
        .and_then(|()| {
            // MatchKind::All can lose ordered-alternation information inside one
            // detector, so exact leftmost reconstruction currently reuses the
            // entity-independent shards after measuring raw overlap scan cost.
            buffer.clear();
            scan_entity_independent(&self.shards, haystack, buffer)
        });
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
        match shard {
            MatcherShard::Regex(shard) => scan_regex_shard(shard, haystack, buffer)?,
            MatcherShard::Literal(shard) => scan_literal_shard(shard, haystack, buffer)?,
        }
    }
    buffer.sort();
    Ok(())
}

fn scan_regex_shard(
    shard: &RegexMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    scan_regex_matches(
        &shard.entity,
        &shard.regex,
        &shard.local_to_detector,
        haystack,
        buffer,
    )
}

fn scan_literal_shard(
    shard: &LiteralMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    if shard.case_insensitive && !haystack.is_ascii() {
        let regex = {
            let mut fallback = shard.fallback_regex.lock().map_err(|_| {
                validation(
                    format!("/engine/shards/{}/fallback_regex", shard.entity),
                    "literal matcher fallback lock was poisoned",
                )
            })?;
            if fallback.is_none() {
                let fallback_patterns = shard.fallback_patterns.as_ref().ok_or_else(|| {
                    validation(
                        format!("/engine/shards/{}/fallback_patterns", shard.entity),
                        "case-insensitive literal shard is missing fallback regex patterns",
                    )
                })?;
                *fallback = Some(Arc::new(compile_entity_regex(
                    &shard.entity,
                    fallback_patterns,
                )?));
            }
            fallback
                .as_ref()
                .expect("fallback regex is initialized above")
                .clone()
        };
        return scan_regex_matches(
            &shard.entity,
            &regex,
            &shard.local_to_detector,
            haystack,
            buffer,
        );
    }

    for raw_match in shard.matcher.find_iter(haystack) {
        let local_index = raw_match.pattern().as_usize();
        let Some(&detector_index) = shard.local_to_detector.get(local_index) else {
            return Err(validation(
                format!("/engine/shards/{}/local_to_detector", shard.entity),
                format!(
                    "literal engine returned local pattern index {local_index} outside detector map"
                ),
            ));
        };
        push_utf8_match(
            buffer,
            haystack,
            detector_index,
            raw_match.start() as u64,
            raw_match.end() as u64,
        )?;
    }
    Ok(())
}

fn scan_regex_matches(
    entity: &str,
    regex: &Regex,
    local_to_detector: &[u32],
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    for raw_match in regex.find_iter(haystack) {
        let local_index = raw_match.pattern().as_usize();
        let Some(&detector_index) = local_to_detector.get(local_index) else {
            return Err(validation(
                format!("/engine/shards/{entity}/local_to_detector"),
                format!(
                    "regex engine returned local pattern index {local_index} outside detector map"
                ),
            ));
        };
        push_utf8_match(
            buffer,
            haystack,
            detector_index,
            raw_match.start() as u64,
            raw_match.end() as u64,
        )?;
    }
    Ok(())
}

fn scan_all_overlaps(
    matcher: &AllOverlapsMatcher,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    buffer.clear();
    let input = Input::new(haystack);
    let mut forward_cache = HybridCache::new(&matcher.forward);
    let mut reverse_cache = HybridCache::new(&matcher.reverse);
    let mut state = OverlappingState::start();
    loop {
        matcher
            .forward
            .try_search_overlapping_fwd(&mut forward_cache, &input, &mut state)
            .map_err(|error| {
                validation(
                    "/engine/all_overlaps/forward",
                    format!("all_overlaps forward search failed: {error}"),
                )
            })?;
        let Some(end) = state.get_match() else {
            break;
        };
        let local_index = end.pattern().as_usize();
        let Some(&detector_index) = matcher.local_to_detector.get(local_index) else {
            return Err(validation(
                "/engine/all_overlaps/local_to_detector",
                format!(
                    "regex engine returned local pattern index {local_index} outside detector map"
                ),
            ));
        };

        let reverse_input = input
            .clone()
            .range(input.start()..end.offset())
            .anchored(Anchored::Pattern(end.pattern()))
            .earliest(false);
        let mut reverse_state = OverlappingState::start();
        let mut recovered_start = false;
        loop {
            matcher
                .reverse
                .try_search_overlapping_rev(&mut reverse_cache, &reverse_input, &mut reverse_state)
                .map_err(|error| {
                    validation(
                        "/engine/all_overlaps/reverse",
                        format!("all_overlaps reverse search failed: {error}"),
                    )
                })?;
            let Some(start) = reverse_state.get_match() else {
                break;
            };
            recovered_start = true;
            push_utf8_match(
                buffer,
                haystack,
                detector_index,
                start.offset() as u64,
                end.offset() as u64,
            )?;
        }
        if !recovered_start {
            return Err(validation(
                "/engine/all_overlaps/reverse",
                "all_overlaps reverse search failed to recover a match start",
            ));
        }
    }
    buffer.sort();
    Ok(())
}

fn scan_global_leftmost(
    matcher: &GlobalLeftmostMatcher,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    for raw_match in matcher.regex.find_iter(haystack) {
        let local_index = raw_match.pattern().as_usize();
        let Some(&detector_index) = matcher.local_to_detector.get(local_index) else {
            return Err(validation(
                "/engine/global_leftmost/local_to_detector",
                format!(
                    "regex engine returned local pattern index {local_index} outside detector map"
                ),
            ));
        };
        push_utf8_match(
            buffer,
            haystack,
            detector_index,
            raw_match.start() as u64,
            raw_match.end() as u64,
        )?;
    }
    buffer.sort();
    Ok(())
}

fn push_utf8_match(
    buffer: &mut NativeMatchBuffer,
    haystack: &[u8],
    detector_index: u32,
    start_byte: u64,
    end_byte: u64,
) -> Result<()> {
    let start = usize::try_from(start_byte).map_err(|_| {
        validation(
            "/match/start_byte",
            format!("raw match start_byte {start_byte} cannot be represented on this platform"),
        )
    })?;
    let end = usize::try_from(end_byte).map_err(|_| {
        validation(
            "/match/end_byte",
            format!("raw match end_byte {end_byte} cannot be represented on this platform"),
        )
    })?;
    if end > haystack.len() || start > end {
        return Err(validation(
            "/match",
            format!("raw match span ({start_byte}, {end_byte}) is outside the haystack"),
        ));
    }
    std::str::from_utf8(&haystack[start..end]).map_err(|error| {
        validation(
            "/match",
            format!(
                "regex match span ({start_byte}, {end_byte}) is not valid UTF-8; ASCII-mode patterns must not match partial codepoints: {error}"
            ),
        )
    })?;
    buffer.push(RawMatch::new(detector_index, start_byte, end_byte)?)?;
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

fn compile_all_overlaps(canonical: &CanonicalBank) -> Result<AllOverlapsMatcher> {
    let mut patterns = Vec::new();
    let mut local_to_detector = Vec::new();
    let mut next_detector_index = 0u32;
    for entity in &canonical.entities {
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            let hir = parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?;
            if hir.properties().look_set().contains_word_unicode() {
                return Err(validation(
                    pattern_path_by_index(&entity.name, pattern_index),
                    "Unicode word-boundary assertions are not supported by the all_overlaps prototype; use explicit ASCII word boundaries such as (?-u:\\b) or the entity_independent mode",
                ));
            }
            patterns.push(hir);
            local_to_detector.push(next_detector_index);
            next_detector_index = next_detector_index.checked_add(1).ok_or_else(|| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
        }
    }

    let forward_nfa = thompson::Compiler::new()
        .configure(
            thompson::Config::new()
                .which_captures(WhichCaptures::None)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT)),
        )
        .build_many_from_hir(&patterns)
        .map_err(|error| {
            validation(
                "/entities",
                format!("could not compile all_overlaps forward NFA: {error}"),
            )
        })?;
    let reverse_nfa = thompson::Compiler::new()
        .configure(
            thompson::Config::new()
                .reverse(true)
                .which_captures(WhichCaptures::None)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT)),
        )
        .build_many_from_hir(&patterns)
        .map_err(|error| {
            validation(
                "/entities",
                format!("could not compile all_overlaps reverse NFA: {error}"),
            )
        })?;

    let forward = HybridDfa::builder()
        .configure(
            HybridDfa::config()
                .match_kind(RegexMatchKind::All)
                .cache_capacity(ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY),
        )
        .build_from_nfa(forward_nfa)
        .map_err(|error| {
            validation(
                "/entities",
                format!("could not compile all_overlaps forward DFA: {error}"),
            )
        })?;
    let reverse = HybridDfa::builder()
        .configure(
            HybridDfa::config()
                .match_kind(RegexMatchKind::All)
                .starts_for_each_pattern(true)
                .prefilter(None)
                .specialize_start_states(false)
                .cache_capacity(ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY),
        )
        .build_from_nfa(reverse_nfa)
        .map_err(|error| {
            validation(
                "/entities",
                format!("could not compile all_overlaps reverse DFA: {error}"),
            )
        })?;

    Ok(AllOverlapsMatcher {
        forward,
        reverse,
        local_to_detector,
    })
}

fn compile_global_leftmost(canonical: &CanonicalBank) -> Result<GlobalLeftmostMatcher> {
    let mut patterns = Vec::new();
    let mut pattern_paths = Vec::new();
    let mut local_to_detector = Vec::new();
    let mut next_detector_index = 0u32;
    for entity in &canonical.entities {
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            patterns.push(parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?);
            pattern_paths.push(pattern_path_by_index(&entity.name, pattern_index));
            local_to_detector.push(next_detector_index);
            next_detector_index = next_detector_index.checked_add(1).ok_or_else(|| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
        }
    }

    let regex = Regex::builder()
        .configure(
            Regex::config()
                .match_kind(RegexMatchKind::LeftmostFirst)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT))
                .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                .hybrid_cache_capacity(ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY)
                .dfa_size_limit(Some(ENTITY_INDEPENDENT_DFA_SIZE_LIMIT))
                .dfa_state_limit(Some(ENTITY_INDEPENDENT_DFA_STATE_LIMIT)),
        )
        .build_many_from_hir(&patterns)
        .map_err(|error| {
            let path = match error.pattern() {
                Some(pattern_id) => pattern_paths
                    .get(pattern_id.as_usize())
                    .cloned()
                    .unwrap_or_else(|| format!("/entities/patterns/{}", pattern_id.as_usize())),
                None => "/entities".to_string(),
            };
            validation(
                path,
                format!("could not compile global_leftmost regex matcher: {error}"),
            )
        })?;

    Ok(GlobalLeftmostMatcher {
        regex,
        local_to_detector,
    })
}

fn compile_entity_independent(canonical: &CanonicalBank) -> Result<Vec<MatcherShard>> {
    let mut shards = Vec::with_capacity(canonical.entities.len());
    let mut next_detector_index = 0u32;
    for entity in &canonical.entities {
        let mut patterns = Vec::with_capacity(entity.patterns.len());
        let mut literal_patterns = Vec::with_capacity(entity.patterns.len());
        let mut literal_case_insensitive = None;
        let mut literal_only = true;
        let mut local_to_detector = Vec::with_capacity(entity.patterns.len());
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            patterns.push(parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?);
            match simple_literal_pattern(pattern) {
                Some(literal_pattern)
                    if literal_case_insensitive
                        .map(|case_insensitive| {
                            case_insensitive == literal_pattern.case_insensitive
                        })
                        .unwrap_or(true) =>
                {
                    literal_case_insensitive = Some(literal_pattern.case_insensitive);
                    literal_patterns.push(literal_pattern.value);
                }
                _ => {
                    literal_only = false;
                }
            }
            local_to_detector.push(next_detector_index);
            next_detector_index = next_detector_index.checked_add(1).ok_or_else(|| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
        }

        let shard = if literal_only && literal_patterns.len() == patterns.len() {
            MatcherShard::Literal(compile_literal_shard(
                &entity.name,
                literal_patterns,
                literal_case_insensitive.unwrap_or(false),
                local_to_detector,
                patterns,
            )?)
        } else {
            MatcherShard::Regex(RegexMatcherShard {
                entity: entity.name.clone(),
                regex: compile_entity_regex(&entity.name, &patterns)?,
                local_to_detector,
            })
        };

        shards.push(shard);
    }
    Ok(shards)
}

fn compile_entity_regex(entity_name: &str, patterns: &[Hir]) -> Result<Regex> {
    Regex::builder()
        .configure(
            Regex::config()
                .match_kind(RegexMatchKind::LeftmostFirst)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT))
                .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                .hybrid_cache_capacity(ENTITY_INDEPENDENT_HYBRID_CACHE_CAPACITY)
                .dfa_size_limit(Some(ENTITY_INDEPENDENT_DFA_SIZE_LIMIT))
                .dfa_state_limit(Some(ENTITY_INDEPENDENT_DFA_STATE_LIMIT)),
        )
        .build_many_from_hir(patterns)
        .map_err(|error| {
            let path = match error.pattern() {
                Some(pattern_id) => pattern_path(entity_name, pattern_id),
                None => format!("/entities/{entity_name}/patterns"),
            };
            validation(
                path,
                format!(
                    "could not compile entity-independent regex matcher for entity {entity_name:?}: {error}"
                ),
            )
        })
}

fn compile_literal_shard(
    entity_name: &str,
    literal_patterns: Vec<String>,
    case_insensitive: bool,
    local_to_detector: Vec<u32>,
    fallback_patterns: Vec<Hir>,
) -> Result<LiteralMatcherShard> {
    let matcher = AhoCorasickBuilder::new()
        .match_kind(AhoMatchKind::LeftmostFirst)
        .ascii_case_insensitive(case_insensitive)
        .build(&literal_patterns)
        .map_err(|error| {
            validation(
                format!("/entities/{entity_name}/patterns"),
                format!(
                    "could not compile entity-independent literal matcher for entity {entity_name:?}: {error}"
                ),
            )
        })?;

    Ok(LiteralMatcherShard {
        entity: entity_name.to_string(),
        matcher,
        case_insensitive,
        local_to_detector,
        fallback_patterns: if case_insensitive {
            Some(fallback_patterns)
        } else {
            None
        },
        fallback_regex: Mutex::new(None),
    })
}

fn simple_literal_pattern(pattern: &CanonicalPattern) -> Option<SimpleLiteralPattern> {
    let case_insensitive = match pattern.flags.as_slice() {
        [] => false,
        [flag] if flag == "IGNORECASE" => true,
        _ => return None,
    };
    let value = unescape_simple_literal_regex(&pattern.regex)?;
    if value.is_empty() {
        return None;
    }
    if case_insensitive && !value.is_ascii() {
        return None;
    }
    Some(SimpleLiteralPattern {
        value,
        case_insensitive,
    })
}

fn unescape_simple_literal_regex(regex: &str) -> Option<String> {
    let mut literal = String::with_capacity(regex.len());
    let mut chars = regex.chars();
    while let Some(char) = chars.next() {
        if char == '\\' {
            let escaped = chars.next()?;
            if !is_simple_literal_escape(escaped) {
                return None;
            }
            literal.push(escaped);
        } else {
            if is_regex_meta_character(char) {
                return None;
            }
            literal.push(char);
        }
    }
    Some(literal)
}

fn is_regex_meta_character(char: char) -> bool {
    matches!(
        char,
        '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
    )
}

fn is_simple_literal_escape(char: char) -> bool {
    !char.is_alphanumeric()
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
    let mut ascii = false;
    for flag in flags {
        match flag.as_str() {
            "ASCII" => {
                ascii = true;
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
    let pattern = if ascii {
        ascii_lower_pattern(regex)
    } else {
        Ok(regex.to_string())
    }?;
    parser.build().parse(&pattern).map_err(|error| {
        validation(
            pattern_path_by_index(entity_name, pattern_index),
            format!("unsupported Rust regex syntax for native scanner: {error}"),
        )
    })
}

fn ascii_lower_pattern(regex: &str) -> Result<String> {
    let mut lowered = String::with_capacity(regex.len());
    let mut chars = regex.chars();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                lowered.push(ch);
                break;
            };
            match escaped {
                'w' if in_class => lowered.push_str("A-Za-z0-9_"),
                'w' => lowered.push_str("[A-Za-z0-9_]"),
                'W' if in_class => {
                    return Err(validation(
                        "/regex",
                        "ASCII flag lowering does not support \\W inside character classes; use an explicit negated ASCII class",
                    ))
                }
                'W' => lowered.push_str("[^A-Za-z0-9_]"),
                'd' if in_class => lowered.push_str("0-9"),
                'd' => lowered.push_str("[0-9]"),
                'D' if in_class => {
                    return Err(validation(
                        "/regex",
                        "ASCII flag lowering does not support \\D inside character classes; use an explicit negated ASCII digit class",
                    ))
                }
                'D' => lowered.push_str("[^0-9]"),
                's' if in_class => lowered.push_str(r" \t\n\r\f\x{0B}"),
                's' => lowered.push_str(r"[ \t\n\r\f\x{0B}]"),
                'S' if in_class => {
                    return Err(validation(
                        "/regex",
                        "ASCII flag lowering does not support \\S inside character classes; use an explicit negated ASCII whitespace class",
                    ))
                }
                'S' => lowered.push_str(r"[^ \t\n\r\f\x{0B}]"),
                'b' if in_class => lowered.push_str(r"\b"),
                'b' => lowered.push_str(r"(?-u:\b)"),
                'B' if in_class => lowered.push_str(r"\B"),
                'B' => lowered.push_str(r"(?-u:\B)"),
                _ => {
                    lowered.push('\\');
                    lowered.push(escaped);
                }
            }
            continue;
        }

        if ch == '[' && !in_class {
            in_class = true;
        } else if ch == ']' && in_class {
            in_class = false;
        }
        lowered.push(ch);
    }
    Ok(lowered)
}

fn pattern_path_by_index(entity_name: &str, pattern_index: usize) -> String {
    format!("/entities/{entity_name}/patterns/{pattern_index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bank::{
        CanonicalBank, CanonicalDefaults, CanonicalEntity, CanonicalPattern, NativeBank,
    };

    fn raw_matches(bank: NativeBank, text: &str) -> Vec<(u32, u64, u64)> {
        let buffer = bank.scan_bytes(text.as_bytes()).unwrap();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    fn engine_for_patterns(patterns: Vec<CanonicalPattern>) -> NativeEngine {
        let canonical = CanonicalBank {
            schema: 1,
            defaults: CanonicalDefaults {
                engine: "rust-regex-meta".to_string(),
                unicode: true,
                case_insensitive: false,
                word_boundaries: false,
                normalization: "none".to_string(),
            },
            entities: vec![CanonicalEntity {
                stable_id: "entity".to_string(),
                name: "entity".to_string(),
                patterns,
            }],
        };
        NativeEngine::compile(&canonical, MatchMode::EntityIndependent).unwrap()
    }

    fn canonical_pattern(regex: &str, flags: &[&str]) -> CanonicalPattern {
        CanonicalPattern {
            stable_id: regex.to_string(),
            priority: 0,
            canonical_name: regex.to_string(),
            surface_name: regex.to_string(),
            regex: regex.to_string(),
            flags: flags.iter().map(|flag| flag.to_string()).collect(),
        }
    }

    fn engine_raw_matches(engine: &NativeEngine, text: &str) -> Vec<(u32, u64, u64)> {
        let mut buffer = NativeMatchBuffer::new();
        engine
            .scan_bytes_into(text.as_bytes(), &mut buffer)
            .unwrap();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    #[test]
    fn literal_only_entity_uses_literal_shard_for_ascii_case_insensitive_patterns() {
        let engine = engine_for_patterns(vec![
            canonical_pattern(r"alpha@example\.com", &["IGNORECASE"]),
            canonical_pattern(r"beta@example\.com", &["IGNORECASE"]),
        ]);

        assert!(matches!(
            engine.shards.as_slice(),
            [MatcherShard::Literal(_)]
        ));
        assert_eq!(
            engine_raw_matches(&engine, "BETA@EXAMPLE.COM"),
            [(1, 0, 16)]
        );
    }

    #[test]
    fn literal_shard_falls_back_for_non_ascii_case_folding() {
        let engine = engine_for_patterns(vec![canonical_pattern("k", &["IGNORECASE"])]);

        assert!(matches!(
            engine.shards.as_slice(),
            [MatcherShard::Literal(_)]
        ));
        assert_eq!(engine_raw_matches(&engine, "K"), [(0, 0, 3)]);
    }

    #[test]
    fn regex_like_entity_stays_on_regex_shard() {
        let engine = engine_for_patterns(vec![canonical_pattern(r"\d+", &[])]);

        assert!(matches!(engine.shards.as_slice(), [MatcherShard::Regex(_)]));
        assert_eq!(engine_raw_matches(&engine, "123"), [(0, 0, 3)]);
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
    fn global_leftmost_scan_collapses_cross_entity_overlap() {
        let source = br#"{"PERSON":{"Sam":"Sam"},"PROJECT":{"Samba":"Samba"}}"#;
        let default_bank = NativeBank::from_source_bytes(source, Some("json"), None).unwrap();
        let global_bank = NativeBank::from_source_bytes(
            source,
            Some("json"),
            Some(r#"{"match_mode":"global_leftmost"}"#),
        )
        .unwrap();

        assert_eq!(
            raw_matches(default_bank, "Samba ships"),
            [(0, 0, 3), (1, 0, 5)]
        );
        assert_eq!(raw_matches(global_bank, "Samba ships"), [(0, 0, 3)]);
    }

    #[test]
    fn scan_rejects_invalid_utf8() {
        let bank = NativeBank::from_source_bytes(br#"{"CODE":{"Alpha":"A"}}"#, Some("json"), None)
            .unwrap();
        let error = bank.scan_bytes(&[0xff]).unwrap_err();

        assert!(error.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn internal_match_modes_still_enforce_compile_limits() {
        let source =
            br#"{"entity":"CODE","canonical_name":"Bomb","surface_name":"Bomb","regex":"(?:a{1000000}){1000000}"}"#;
        let all_overlaps_error = NativeBank::from_source_bytes(
            source,
            Some("jsonl"),
            Some(r#"{"match_mode":"all_overlaps"}"#),
        )
        .unwrap_err();
        let global_leftmost_error = NativeBank::from_source_bytes(
            source,
            Some("jsonl"),
            Some(r#"{"match_mode":"global_leftmost"}"#),
        )
        .unwrap_err();

        assert!(all_overlaps_error.to_string().contains("could not compile"));
        assert!(global_leftmost_error
            .to_string()
            .contains("could not compile"));
    }
}
