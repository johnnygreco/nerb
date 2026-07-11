use crate::bank::{CanonicalBank, CanonicalPattern, MatchMode};
use crate::error::{validation, Result};
use crate::match_buffer::{NativeMatchBuffer, RawMatch};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Input as AhoInput, MatchKind as AhoMatchKind};
use regex_automata::hybrid::dfa::{Cache as HybridCache, OverlappingState, DFA as HybridDfa};
use regex_automata::meta::Regex;
use regex_automata::nfa::thompson::{self, WhichCaptures};
use regex_automata::{Anchored, Input, MatchKind as RegexMatchKind};
use regex_syntax::hir::{Hir, HirKind, Look};
use regex_syntax::{is_word_character, ParserBuilder};
use std::cmp::Ordering;
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
    Layered(LayeredMatcherShard),
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
struct LayeredMatcherShard {
    entity: String,
    case_sensitive_literals: Option<LiteralMatcherLayer>,
    ascii_case_insensitive_literals: Option<LiteralMatcherLayer>,
    residual_regex: Option<RegexMatcherLayer>,
    fallback_patterns: Option<Vec<Hir>>,
    fallback_local_to_detector: Option<Vec<u32>>,
    fallback_regex: Mutex<Option<Arc<Regex>>>,
}

#[derive(Debug)]
struct LiteralMatcherLayer {
    matcher: AhoCorasick,
    case_insensitive: bool,
    all_require_left_unicode_word_boundary: bool,
    patterns: Vec<LayerLiteralPattern>,
    prefix_index: LiteralPrefixIndex,
}

#[derive(Debug)]
struct LayerLiteralPattern {
    literal: SimpleLiteralPattern,
    detector_index: u32,
    pattern_order: usize,
}

#[derive(Debug)]
struct LiteralPrefixIndex {
    sorted_pattern_indices: Vec<usize>,
}

#[derive(Debug, Default)]
struct SameStartLookup {
    candidate: Option<LayerCandidate>,
    prefix_bytes_examined: usize,
    index_comparisons: usize,
    terminal_candidates_examined: usize,
}

#[derive(Debug)]
struct RegexMatcherLayer {
    regex: Regex,
    local_to_detector: Vec<u32>,
    local_to_pattern_order: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LayerCandidate {
    detector_index: u32,
    pattern_order: usize,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct SimpleLiteralPattern {
    value: String,
    case_insensitive: bool,
    left_unicode_word_boundary: bool,
    right_unicode_word_boundary: bool,
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
            MatcherShard::Layered(shard) => scan_layered_shard(shard, haystack, buffer)?,
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

fn scan_layered_shard(
    shard: &LayeredMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    // Aho-Corasick's case-insensitive mode is deliberately ASCII-only. A
    // non-ASCII haystack can participate in Unicode folds (for example, `k`
    // and the Kelvin sign), so use the full entity regex in that case.
    if shard.ascii_case_insensitive_literals.is_some() && !haystack.is_ascii() {
        let regex = lazy_fallback_regex(
            &shard.entity,
            shard.fallback_patterns.as_deref(),
            &shard.fallback_regex,
        )?;
        let local_to_detector = shard
            .fallback_local_to_detector
            .as_ref()
            .expect("fallback detector map is present when a fallback regex is required");
        return scan_regex_matches(&shard.entity, &regex, local_to_detector, haystack, buffer);
    }
    let haystack_text = std::str::from_utf8(haystack)
        .expect("scan_bytes_into validates UTF-8 before dispatching to the layered matcher");

    let mut cursor = 0;
    let mut case_sensitive = next_literal_candidate(
        &shard.entity,
        shard.case_sensitive_literals.as_ref(),
        haystack,
        haystack_text,
        cursor,
    )?;
    let mut case_insensitive = next_literal_candidate(
        &shard.entity,
        shard.ascii_case_insensitive_literals.as_ref(),
        haystack,
        haystack_text,
        cursor,
    )?;
    let mut residual = next_regex_candidate(
        &shard.entity,
        shard.residual_regex.as_ref(),
        haystack,
        cursor,
    )?;

    loop {
        // Each layer applies its own leftmost-first semantics. Merging the
        // layers by start and then original pattern order reconstructs the
        // same winner as one leftmost-first regex over every entity pattern.
        let Some(winner) = [case_sensitive, case_insensitive, residual]
            .into_iter()
            .flatten()
            .min_by_key(|candidate| (candidate.start, candidate.pattern_order))
        else {
            break;
        };
        debug_assert!(winner.end > winner.start);
        push_utf8_match(
            buffer,
            haystack,
            winner.detector_index,
            winner.start as u64,
            winner.end as u64,
        )?;
        cursor = winner.end;

        // Keep a losing candidate when it starts beyond the consumed span.
        // It remains the first candidate in its layer, avoiding rescans of a
        // distant residual regex after every dense literal match.
        if candidate_precedes_cursor(case_sensitive, cursor) {
            case_sensitive = next_literal_candidate(
                &shard.entity,
                shard.case_sensitive_literals.as_ref(),
                haystack,
                haystack_text,
                cursor,
            )?;
        }
        if candidate_precedes_cursor(case_insensitive, cursor) {
            case_insensitive = next_literal_candidate(
                &shard.entity,
                shard.ascii_case_insensitive_literals.as_ref(),
                haystack,
                haystack_text,
                cursor,
            )?;
        }
        if candidate_precedes_cursor(residual, cursor) {
            residual = next_regex_candidate(
                &shard.entity,
                shard.residual_regex.as_ref(),
                haystack,
                cursor,
            )?;
        }
    }
    Ok(())
}

fn lazy_fallback_regex(
    entity: &str,
    fallback_patterns: Option<&[Hir]>,
    fallback_regex: &Mutex<Option<Arc<Regex>>>,
) -> Result<Arc<Regex>> {
    let mut fallback = fallback_regex.lock().map_err(|_| {
        validation(
            format!("/engine/shards/{entity}/fallback_regex"),
            "layered matcher fallback lock was poisoned",
        )
    })?;
    if fallback.is_none() {
        let patterns = fallback_patterns.ok_or_else(|| {
            validation(
                format!("/engine/shards/{entity}/fallback_patterns"),
                "layered matcher is missing fallback regex patterns",
            )
        })?;
        *fallback = Some(Arc::new(compile_entity_regex(entity, patterns)?));
    }
    Ok(fallback
        .as_ref()
        .expect("fallback regex is initialized above")
        .clone())
}

fn candidate_precedes_cursor(candidate: Option<LayerCandidate>, cursor: usize) -> bool {
    candidate
        .map(|candidate| candidate.start < cursor)
        .unwrap_or(false)
}

fn next_literal_candidate(
    entity: &str,
    layer: Option<&LiteralMatcherLayer>,
    haystack: &[u8],
    haystack_text: &str,
    cursor: usize,
) -> Result<Option<LayerCandidate>> {
    let Some(layer) = layer else {
        return Ok(None);
    };
    let mut search_cursor = cursor;
    loop {
        let Some(raw_match) = layer
            .matcher
            .find(AhoInput::new(haystack).span(search_cursor..haystack.len()))
        else {
            return Ok(None);
        };
        let local_index = raw_match.pattern().as_usize();
        let Some(pattern) = layer.patterns.get(local_index) else {
            return Err(validation(
                format!("/engine/shards/{entity}/literal/patterns"),
                format!(
                    "literal engine returned local pattern index {local_index} outside pattern map"
                ),
            ));
        };
        if literal_boundaries_match(
            &pattern.literal,
            haystack_text,
            raw_match.start(),
            raw_match.end(),
        ) {
            return Ok(Some(LayerCandidate {
                detector_index: pattern.detector_index,
                pattern_order: pattern.pattern_order,
                start: raw_match.start(),
                end: raw_match.end(),
            }));
        }

        // Leftmost-first Aho-Corasick reports only the highest-priority raw
        // literal at a start. If its boundary fails, a lower-priority longer
        // literal at that same start can still be the regex winner.
        let same_start =
            indexed_valid_literal_at_start(layer, haystack, haystack_text, raw_match.start());
        if let Some(candidate) = same_start.candidate {
            return Ok(Some(candidate));
        }
        search_cursor = next_literal_search_start(layer, haystack_text, raw_match.start());
    }
}

fn indexed_valid_literal_at_start(
    layer: &LiteralMatcherLayer,
    haystack: &[u8],
    haystack_text: &str,
    start: usize,
) -> SameStartLookup {
    let mut lookup = SameStartLookup::default();
    let mut range_start = 0;
    let mut range_end = layer.prefix_index.sorted_pattern_indices.len();

    for (offset, &haystack_byte) in haystack[start..].iter().enumerate() {
        let target = normalized_literal_byte(haystack_byte, layer.case_insensitive);
        let current_range = &layer.prefix_index.sorted_pattern_indices[range_start..range_end];
        // The current range shares every previously consumed prefix byte.
        // In lexicographic order, literals ending here come first and the
        // remaining literals are contiguous by their next byte, so two binary
        // partitions narrow the range without inspecting the whole layer.
        let lower = current_range.partition_point(|&local_index| {
            lookup.index_comparisons += 1;
            let literal = layer.patterns[local_index].literal.value.as_bytes();
            literal.len() <= offset
                || normalized_literal_byte(literal[offset], layer.case_insensitive) < target
        });
        let upper = current_range.partition_point(|&local_index| {
            lookup.index_comparisons += 1;
            let literal = layer.patterns[local_index].literal.value.as_bytes();
            literal.len() <= offset
                || normalized_literal_byte(literal[offset], layer.case_insensitive) <= target
        });
        range_start += lower;
        range_end = range_start + (upper - lower);
        lookup.prefix_bytes_examined += 1;
        if range_start == range_end {
            break;
        }

        let matched_len = offset + 1;
        for &local_index in &layer.prefix_index.sorted_pattern_indices[range_start..range_end] {
            let pattern = &layer.patterns[local_index];
            let literal_len = pattern.literal.value.len();
            if literal_len != matched_len {
                break;
            }
            lookup.terminal_candidates_examined += 1;
            let end = start + literal_len;
            if !literal_boundaries_match(&pattern.literal, haystack_text, start, end) {
                continue;
            }
            let candidate = LayerCandidate {
                detector_index: pattern.detector_index,
                pattern_order: pattern.pattern_order,
                start,
                end,
            };
            if lookup
                .candidate
                .map(|winner| candidate.pattern_order < winner.pattern_order)
                .unwrap_or(true)
            {
                lookup.candidate = Some(candidate);
            }
        }
    }
    lookup
}

fn normalized_literal_byte(byte: u8, case_insensitive: bool) -> u8 {
    if case_insensitive {
        byte.to_ascii_lowercase()
    } else {
        byte
    }
}

fn literal_boundaries_match(
    literal: &SimpleLiteralPattern,
    haystack: &str,
    start: usize,
    end: usize,
) -> bool {
    (!literal.left_unicode_word_boundary || is_unicode_word_boundary(haystack, start))
        && (!literal.right_unicode_word_boundary || is_unicode_word_boundary(haystack, end))
}

fn is_unicode_word_boundary(haystack: &str, at: usize) -> bool {
    debug_assert!(haystack.is_char_boundary(at));
    let word_before = haystack[..at]
        .chars()
        .next_back()
        .map(is_word_character)
        .unwrap_or(false);
    let word_after = haystack[at..]
        .chars()
        .next()
        .map(is_word_character)
        .unwrap_or(false);
    word_before != word_after
}

fn next_utf8_start(haystack: &str, start: usize) -> usize {
    debug_assert!(start < haystack.len());
    start
        + haystack[start..]
            .chars()
            .next()
            .expect("a non-empty literal match starts before the haystack end")
            .len_utf8()
}

fn next_literal_search_start(layer: &LiteralMatcherLayer, haystack: &str, start: usize) -> usize {
    if !layer.all_require_left_unicode_word_boundary {
        return next_utf8_start(haystack, start);
    }
    let mut at = next_utf8_start(haystack, start);
    while at < haystack.len() && !is_unicode_word_boundary(haystack, at) {
        at = next_utf8_start(haystack, at);
    }
    at
}

fn next_regex_candidate(
    entity: &str,
    layer: Option<&RegexMatcherLayer>,
    haystack: &[u8],
    cursor: usize,
) -> Result<Option<LayerCandidate>> {
    let Some(layer) = layer else {
        return Ok(None);
    };
    let Some(raw_match) = layer
        .regex
        .find(Input::new(haystack).span(cursor..haystack.len()))
    else {
        return Ok(None);
    };
    layer_candidate(
        entity,
        "regex",
        &layer.local_to_detector,
        &layer.local_to_pattern_order,
        raw_match.pattern().as_usize(),
        raw_match.start(),
        raw_match.end(),
    )
    .map(Some)
}

fn layer_candidate(
    entity: &str,
    layer_kind: &str,
    local_to_detector: &[u32],
    local_to_pattern_order: &[usize],
    local_index: usize,
    start: usize,
    end: usize,
) -> Result<LayerCandidate> {
    let Some(&detector_index) = local_to_detector.get(local_index) else {
        return Err(validation(
            format!("/engine/shards/{entity}/{layer_kind}/local_to_detector"),
            format!("{layer_kind} engine returned local pattern index {local_index} outside detector map"),
        ));
    };
    let Some(&pattern_order) = local_to_pattern_order.get(local_index) else {
        return Err(validation(
            format!("/engine/shards/{entity}/{layer_kind}/local_to_pattern_order"),
            format!("{layer_kind} engine returned local pattern index {local_index} outside pattern-order map"),
        ));
    };
    if end <= start {
        return Err(validation(
            format!("/engine/shards/{entity}/{layer_kind}"),
            "layered matcher unexpectedly produced an empty match",
        ));
    }
    Ok(LayerCandidate {
        detector_index,
        pattern_order,
        start,
        end,
    })
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
        let mut local_to_detector = Vec::with_capacity(entity.patterns.len());
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            let hir = parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?;
            literal_patterns.push(layer_literal_pattern(pattern, &hir));
            patterns.push(hir);
            local_to_detector.push(next_detector_index);
            next_detector_index = next_detector_index.checked_add(1).ok_or_else(|| {
                validation(
                    "/entities",
                    "detector count exceeds u32::MAX and cannot be represented in raw matches",
                )
            })?;
        }

        // Shared-cursor merging relies on every winner advancing the cursor.
        // If a pattern can match empty (or matches nothing, for which the HIR
        // has no minimum), retain the single-regex entity implementation.
        let all_patterns_non_empty = patterns
            .iter()
            .all(|hir| matches!(hir.properties().minimum_len(), Some(minimum) if minimum > 0));
        let literal_count = literal_patterns
            .iter()
            .filter(|literal| literal.is_some())
            .count();
        let first_literal_case = literal_patterns
            .iter()
            .flatten()
            .next()
            .map(|literal| literal.case_insensitive);

        let shard = if !all_patterns_non_empty || literal_count == 0 {
            MatcherShard::Regex(RegexMatcherShard {
                entity: entity.name.clone(),
                regex: compile_entity_regex(&entity.name, &patterns)?,
                local_to_detector,
            })
        } else if literal_count == patterns.len()
            && literal_patterns
                .iter()
                .flatten()
                .map(|literal| literal.case_insensitive)
                .all(|case_insensitive| {
                    case_insensitive
                        == literal_patterns[0]
                            .as_ref()
                            .expect("every pattern is classified as a literal")
                            .case_insensitive
                })
            && literal_patterns.iter().flatten().all(|literal| {
                !literal.left_unicode_word_boundary && !literal.right_unicode_word_boundary
            })
        {
            let case_insensitive = first_literal_case.expect("the entity has literal patterns");
            MatcherShard::Literal(compile_literal_shard(
                &entity.name,
                literal_patterns
                    .into_iter()
                    .map(|literal| {
                        literal
                            .expect("every pattern is classified as a literal")
                            .value
                    })
                    .collect(),
                case_insensitive,
                local_to_detector,
                patterns,
            )?)
        } else {
            MatcherShard::Layered(compile_layered_shard(
                &entity.name,
                patterns,
                literal_patterns,
                local_to_detector,
            )?)
        };

        shards.push(shard);
    }
    Ok(shards)
}

fn compile_layered_shard(
    entity_name: &str,
    patterns: Vec<Hir>,
    literal_patterns: Vec<Option<SimpleLiteralPattern>>,
    local_to_detector: Vec<u32>,
) -> Result<LayeredMatcherShard> {
    let mut case_sensitive_patterns = Vec::new();
    let mut case_insensitive_patterns = Vec::new();
    let mut residual_patterns = Vec::new();
    let mut residual_detectors = Vec::new();
    let mut residual_orders = Vec::new();
    let has_case_insensitive_literals = literal_patterns
        .iter()
        .flatten()
        .any(|literal| literal.case_insensitive);
    let fallback_patterns = has_case_insensitive_literals.then(|| patterns.clone());

    for (pattern_order, ((hir, literal), detector_index)) in patterns
        .into_iter()
        .zip(literal_patterns)
        .zip(local_to_detector.iter().copied())
        .enumerate()
    {
        match literal {
            Some(literal) if literal.case_insensitive => {
                case_insensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            Some(literal) => {
                case_sensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            None => {
                residual_patterns.push(hir);
                residual_detectors.push(detector_index);
                residual_orders.push(pattern_order);
            }
        }
    }

    Ok(LayeredMatcherShard {
        entity: entity_name.to_string(),
        case_sensitive_literals: compile_literal_layer(
            entity_name,
            case_sensitive_patterns,
            false,
        )?,
        ascii_case_insensitive_literals: compile_literal_layer(
            entity_name,
            case_insensitive_patterns,
            true,
        )?,
        residual_regex: if residual_patterns.is_empty() {
            None
        } else {
            Some(RegexMatcherLayer {
                regex: compile_entity_regex_with_pattern_orders(
                    entity_name,
                    &residual_patterns,
                    Some(&residual_orders),
                )?,
                local_to_detector: residual_detectors,
                local_to_pattern_order: residual_orders,
            })
        },
        fallback_patterns,
        fallback_local_to_detector: has_case_insensitive_literals.then_some(local_to_detector),
        fallback_regex: Mutex::new(None),
    })
}

fn compile_literal_layer(
    entity_name: &str,
    patterns: Vec<LayerLiteralPattern>,
    case_insensitive: bool,
) -> Result<Option<LiteralMatcherLayer>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let all_require_left_unicode_word_boundary = patterns
        .iter()
        .all(|pattern| pattern.literal.left_unicode_word_boundary);
    let prefix_index = LiteralPrefixIndex::new(&patterns, case_insensitive);
    Ok(Some(LiteralMatcherLayer {
        matcher: compile_literal_matcher(
            entity_name,
            patterns
                .iter()
                .map(|pattern| pattern.literal.value.as_str()),
            case_insensitive,
        )?,
        case_insensitive,
        all_require_left_unicode_word_boundary,
        patterns,
        prefix_index,
    }))
}

impl LiteralPrefixIndex {
    fn new(patterns: &[LayerLiteralPattern], case_insensitive: bool) -> Self {
        debug_assert!(
            !case_insensitive
                || patterns
                    .iter()
                    .all(|pattern| pattern.literal.value.is_ascii())
        );
        let mut sorted_pattern_indices = (0..patterns.len()).collect::<Vec<_>>();
        sorted_pattern_indices.sort_unstable_by(|&left_index, &right_index| {
            let left = &patterns[left_index];
            let right = &patterns[right_index];
            compare_normalized_literals(&left.literal.value, &right.literal.value, case_insensitive)
                .then_with(|| left.pattern_order.cmp(&right.pattern_order))
        });
        let mut compact_pattern_indices: Vec<usize> =
            Vec::with_capacity(sorted_pattern_indices.len());
        let mut normalized_group_start = 0;
        for local_index in sorted_pattern_indices {
            let starts_new_group = compact_pattern_indices
                .get(normalized_group_start)
                .map(|&representative_index| {
                    compare_normalized_literals(
                        &patterns[representative_index].literal.value,
                        &patterns[local_index].literal.value,
                        case_insensitive,
                    ) != Ordering::Equal
                })
                .unwrap_or(true);
            if starts_new_group {
                normalized_group_start = compact_pattern_indices.len();
            } else {
                let signature = literal_boundary_signature(&patterns[local_index].literal);
                if compact_pattern_indices[normalized_group_start..]
                    .iter()
                    .any(|&representative_index| {
                        literal_boundary_signature(&patterns[representative_index].literal)
                            == signature
                    })
                {
                    continue;
                }
            }
            compact_pattern_indices.push(local_index);
        }
        compact_pattern_indices.shrink_to_fit();
        Self {
            sorted_pattern_indices: compact_pattern_indices,
        }
    }
}

fn literal_boundary_signature(literal: &SimpleLiteralPattern) -> u8 {
    u8::from(literal.left_unicode_word_boundary)
        | (u8::from(literal.right_unicode_word_boundary) << 1)
}

fn compare_normalized_literals(left: &str, right: &str, case_insensitive: bool) -> Ordering {
    for (&left_byte, &right_byte) in left.as_bytes().iter().zip(right.as_bytes()) {
        let ordering = normalized_literal_byte(left_byte, case_insensitive)
            .cmp(&normalized_literal_byte(right_byte, case_insensitive));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compile_entity_regex(entity_name: &str, patterns: &[Hir]) -> Result<Regex> {
    compile_entity_regex_with_pattern_orders(entity_name, patterns, None)
}

fn compile_entity_regex_with_pattern_orders(
    entity_name: &str,
    patterns: &[Hir],
    pattern_orders: Option<&[usize]>,
) -> Result<Regex> {
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
                Some(pattern_id) => {
                    let local_index = pattern_id.as_usize();
                    let pattern_index = pattern_orders
                        .and_then(|orders| orders.get(local_index))
                        .copied()
                        .unwrap_or(local_index);
                    pattern_path_by_index(entity_name, pattern_index)
                }
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
    let matcher = compile_literal_matcher(
        entity_name,
        literal_patterns.iter().map(String::as_str),
        case_insensitive,
    )?;

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

fn compile_literal_matcher<'a>(
    entity_name: &str,
    literal_patterns: impl IntoIterator<Item = &'a str>,
    case_insensitive: bool,
) -> Result<AhoCorasick> {
    let matcher = AhoCorasickBuilder::new()
        .match_kind(AhoMatchKind::LeftmostFirst)
        .ascii_case_insensitive(case_insensitive)
        .build(literal_patterns)
        .map_err(|error| {
            validation(
                format!("/entities/{entity_name}/patterns"),
                format!(
                    "could not compile entity-independent literal matcher for entity {entity_name:?}: {error}"
                ),
            )
        })?;

    Ok(matcher)
}

fn layer_literal_pattern(pattern: &CanonicalPattern, hir: &Hir) -> Option<SimpleLiteralPattern> {
    simple_literal_pattern(pattern)
        .or_else(|| bounded_simple_literal_pattern(pattern, hir))
        .or_else(|| exact_hir_literal_pattern(hir))
}

fn exact_hir_literal_pattern(hir: &Hir) -> Option<SimpleLiteralPattern> {
    let mut parts = Vec::new();
    flatten_hir_sequence(hir, &mut parts);
    let (body_start, body_end, left_boundary, right_boundary) = unicode_word_boundary_body(&parts)?;
    let mut bytes = Vec::new();
    for part in &parts[body_start..body_end] {
        let HirKind::Literal(literal) = part.kind() else {
            return None;
        };
        bytes.extend_from_slice(&literal.0);
    }
    let value = std::str::from_utf8(&bytes).ok()?.to_string();
    if value.is_empty() {
        return None;
    }
    Some(SimpleLiteralPattern {
        value,
        case_insensitive: false,
        left_unicode_word_boundary: left_boundary,
        right_unicode_word_boundary: right_boundary,
    })
}

fn flatten_hir_sequence<'a>(hir: &'a Hir, parts: &mut Vec<&'a Hir>) {
    match hir.kind() {
        HirKind::Capture(capture) => flatten_hir_sequence(&capture.sub, parts),
        HirKind::Concat(children) => {
            for part in children {
                flatten_hir_sequence(part, parts);
            }
        }
        _ => parts.push(hir),
    }
}

fn unicode_word_boundary_body(parts: &[&Hir]) -> Option<(usize, usize, bool, bool)> {
    let left_boundary = matches!(
        parts.first().map(|part| part.kind()),
        Some(HirKind::Look(Look::WordUnicode))
    );
    let right_boundary = matches!(
        parts.last().map(|part| part.kind()),
        Some(HirKind::Look(Look::WordUnicode))
    );
    let body_start = usize::from(left_boundary);
    let body_end = parts.len().checked_sub(usize::from(right_boundary))?;
    (body_start < body_end).then_some((body_start, body_end, left_boundary, right_boundary))
}

fn bounded_simple_literal_pattern(
    pattern: &CanonicalPattern,
    hir: &Hir,
) -> Option<SimpleLiteralPattern> {
    let (regex, raw_left_boundary, raw_right_boundary) =
        strip_simple_unicode_word_boundaries(&pattern.regex)?;
    let mut parts = Vec::new();
    flatten_hir_sequence(hir, &mut parts);
    let (_, _, hir_left_boundary, hir_right_boundary) = unicode_word_boundary_body(&parts)?;
    if (raw_left_boundary, raw_right_boundary) != (hir_left_boundary, hir_right_boundary) {
        return None;
    }
    simple_literal_pattern_parts(regex, &pattern.flags, raw_left_boundary, raw_right_boundary)
}

fn strip_simple_unicode_word_boundaries(regex: &str) -> Option<(&str, bool, bool)> {
    let (without_left, left_boundary) = regex
        .strip_prefix(r"\b")
        .map(|regex| (regex, true))
        .unwrap_or((regex, false));
    let (mut body, right_boundary) = without_left
        .strip_suffix(r"\b")
        .map(|regex| (regex, true))
        .unwrap_or((without_left, false));
    if !left_boundary && !right_boundary {
        return None;
    }
    if let Some(group_body) = body
        .strip_prefix("(?:")
        .and_then(|body| body.strip_suffix(')'))
    {
        body = group_body;
    }
    Some((body, left_boundary, right_boundary))
}

fn simple_literal_pattern(pattern: &CanonicalPattern) -> Option<SimpleLiteralPattern> {
    simple_literal_pattern_parts(&pattern.regex, &pattern.flags, false, false)
}

fn simple_literal_pattern_parts(
    regex: &str,
    flags: &[String],
    left_unicode_word_boundary: bool,
    right_unicode_word_boundary: bool,
) -> Option<SimpleLiteralPattern> {
    let case_insensitive = match flags {
        [] => false,
        [flag] if flag == "IGNORECASE" => true,
        _ => return None,
    };
    let value = unescape_simple_literal_regex(regex)?;
    if value.is_empty() {
        return None;
    }
    if case_insensitive && !value.is_ascii() {
        return None;
    }
    Some(SimpleLiteralPattern {
        value,
        case_insensitive,
        left_unicode_word_boundary,
        right_unicode_word_boundary,
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

    fn monolithic_raw_matches(patterns: &[CanonicalPattern], text: &str) -> Vec<(u32, u64, u64)> {
        let hirs = patterns
            .iter()
            .enumerate()
            .map(|(pattern_index, pattern)| {
                parse_pattern_with_flags("entity", pattern_index, &pattern.regex, &pattern.flags)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let regex = compile_entity_regex("entity", &hirs).unwrap();
        let local_to_detector = (0..patterns.len())
            .map(|index| u32::try_from(index).unwrap())
            .collect::<Vec<_>>();
        let mut buffer = NativeMatchBuffer::new();
        scan_regex_matches(
            "entity",
            &regex,
            &local_to_detector,
            text.as_bytes(),
            &mut buffer,
        )
        .unwrap();
        buffer.sort();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    fn assert_layered_matches_monolithic(patterns: Vec<CanonicalPattern>, text: &str) {
        let expected = monolithic_raw_matches(&patterns, text);
        let engine = engine_for_patterns(patterns);
        assert!(matches!(
            engine.shards.as_slice(),
            [MatcherShard::Layered(_)]
        ));
        assert_eq!(engine_raw_matches(&engine, text), expected);
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
    fn mixed_entity_uses_layered_matcher_and_preserves_same_start_priority() {
        let regex_first = vec![
            canonical_pattern(r"a(?:b)?", &[]),
            canonical_pattern("a", &[]),
        ];
        let literal_first = vec![
            canonical_pattern("a", &[]),
            canonical_pattern(r"a(?:b)?", &[]),
        ];

        assert_layered_matches_monolithic(regex_first.clone(), "ab ab");
        assert_layered_matches_monolithic(literal_first.clone(), "ab ab");
        assert_eq!(monolithic_raw_matches(&regex_first, "ab"), [(0, 0, 2)]);
        assert_eq!(monolithic_raw_matches(&literal_first, "ab"), [(0, 0, 1)]);
    }

    #[test]
    fn layered_matcher_preserves_long_short_overlap_and_ordered_alternatives() {
        let patterns = vec![
            canonical_pattern(r"(Samba|Sam)", &[]),
            canonical_pattern("Sam", &[]),
            canonical_pattern("SambaX", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "SambaX Sam");
        assert_eq!(
            monolithic_raw_matches(&patterns, "SambaX Sam"),
            [(0, 0, 5), (0, 7, 10)]
        );
    }

    #[test]
    fn layered_matcher_preserves_case_sensitive_and_insensitive_priority() {
        let patterns = vec![
            canonical_pattern("FOO", &[]),
            canonical_pattern("foo", &["IGNORECASE"]),
            canonical_pattern(r"\d+", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "foo FOO 12");
        assert_eq!(
            monolithic_raw_matches(&patterns, "foo FOO 12"),
            [(1, 0, 3), (0, 4, 7), (2, 8, 10)]
        );
    }

    #[test]
    fn layered_matcher_falls_back_for_unicode_case_folding() {
        let patterns = vec![
            canonical_pattern("k", &["IGNORECASE"]),
            canonical_pattern(r"\p{Letter}+", &[]),
            canonical_pattern("done", &[]),
        ];
        let expected = monolithic_raw_matches(&patterns, "K done");
        let engine = engine_for_patterns(patterns);
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed case-folding entity should use a layered matcher");
        };

        assert!(shard.fallback_regex.lock().unwrap().is_none());
        assert_eq!(engine_raw_matches(&engine, "K done"), expected);
        assert!(shard.fallback_regex.lock().unwrap().is_some());
    }

    #[test]
    fn layered_matcher_handles_non_ascii_literals_without_case_folding() {
        let patterns = vec![
            canonical_pattern("café", &[]),
            canonical_pattern(r"\d+", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "café 42 café");
        assert_eq!(
            monolithic_raw_matches(&patterns, "café 42 café"),
            [(0, 0, 5), (1, 6, 8), (0, 9, 14)]
        );
    }

    #[test]
    fn layered_matcher_preserves_boundary_context_and_adjacent_matches() {
        let patterns = vec![
            canonical_pattern("X", &[]),
            canonical_pattern(r"\bfoo\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "Xfoo foo12 X 34");
        assert_eq!(
            monolithic_raw_matches(&patterns, "Xfoo foo12 X 34"),
            [(0, 0, 1), (2, 8, 10), (0, 11, 12), (2, 13, 15)]
        );
    }

    #[test]
    fn bounded_literal_tries_longer_same_start_after_short_boundary_rejection() {
        let patterns = vec![
            canonical_pattern(r"\b(?:a)\b", &[]),
            canonical_pattern(r"\b(?:ab)\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "ab a abx 7");
        assert_eq!(
            monolithic_raw_matches(&patterns, "ab a abx 7"),
            [(1, 0, 2), (0, 3, 4), (2, 9, 10)]
        );
    }

    #[test]
    fn failed_boundary_same_start_lookup_is_prefix_index_bounded() {
        let patterns = (0..2_048)
            .map(|index| canonical_pattern(&format!(r"\b(?:token{index:04})\b"), &[]))
            .collect::<Vec<_>>();
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("bounded literals should use the layered matcher");
        };
        let layer = shard.case_sensitive_literals.as_ref().unwrap();
        let text = "token1024x";
        let lookup = indexed_valid_literal_at_start(layer, text.as_bytes(), text, 0);

        assert!(lookup.candidate.is_none());
        assert_eq!(lookup.terminal_candidates_examined, 1);
        assert!(lookup.prefix_bytes_examined <= text.len());
        assert!(lookup.index_comparisons < 512);
        assert!(lookup.index_comparisons < layer.patterns.len());

        let repeated = std::iter::repeat(text)
            .take(64)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            engine_raw_matches(&engine, &repeated),
            monolithic_raw_matches(&patterns, &repeated)
        );
    }

    #[test]
    fn duplicate_normalized_literals_compact_to_boundary_representatives() {
        let patterns = (0..4_096)
            .map(|index| {
                let regex = match index % 4 {
                    0 => r"\b(?:token)\b",
                    1 => r"(?:token)\b",
                    2 => r"\b(?:token)",
                    _ => "token",
                };
                let mut pattern = canonical_pattern(regex, &[]);
                pattern.stable_id = format!("pattern-{index}");
                pattern.canonical_name = format!("canonical-{index}");
                pattern.surface_name = format!("surface-{index}");
                pattern
            })
            .collect::<Vec<_>>();
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed boundary signatures should use the layered matcher");
        };
        let layer = shard.case_sensitive_literals.as_ref().unwrap();
        let text = "tokenx";
        let lookup = indexed_valid_literal_at_start(layer, text.as_bytes(), text, 0);

        assert_eq!(layer.patterns.len(), 4_096);
        assert_eq!(layer.prefix_index.sorted_pattern_indices.len(), 4);
        assert!(lookup.terminal_candidates_examined <= 4);
        assert_eq!(lookup.candidate.unwrap().pattern_order, 2);
        assert_eq!(
            engine_raw_matches(&engine, text),
            monolithic_raw_matches(&patterns, text)
        );
    }

    #[test]
    fn all_left_bounded_layer_skips_overlapping_word_internal_restarts() {
        let patterns = vec![canonical_pattern(r"\b(?:aaaaaaaaaaaaaaaa)\b", &[])];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("bounded literals should use the layered matcher");
        };
        let layer = shard.case_sensitive_literals.as_ref().unwrap();
        let text = "aaaaaaaaaaaaaaaaa";

        assert!(layer.all_require_left_unicode_word_boundary);
        assert_eq!(next_literal_search_start(layer, text, 0), text.len());
        let repeated = std::iter::repeat(text)
            .take(128)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            engine_raw_matches(&engine, &repeated),
            monolithic_raw_matches(&patterns, &repeated)
        );
    }

    #[test]
    fn bounded_literal_uses_unicode_word_and_combining_mark_semantics() {
        let patterns = vec![
            canonical_pattern(r"\b(?:art)\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];
        let text = "βart artβ \u{301}art art\u{301} (art)";
        let expected = monolithic_raw_matches(&patterns, text);
        let engine = engine_for_patterns(patterns);
        let actual = engine_raw_matches(&engine, text);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 1);
        let (_, start, end) = actual[0];
        assert_eq!(&text[start as usize..end as usize], "art");
    }

    #[test]
    fn bounded_literal_supports_one_sided_unicode_boundaries() {
        let patterns = vec![
            canonical_pattern(r"\b(?:foo)", &[]),
            canonical_pattern(r"(?:bar)\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "xfoo foo barx bar 3");
        assert_eq!(
            engine_raw_matches(&engine_for_patterns(patterns), "xfoo foo barx bar 3"),
            [(0, 5, 8), (1, 14, 17), (2, 18, 19)]
        );
    }

    #[test]
    fn bounded_literal_preserves_case_layer_priority_on_ascii() {
        let patterns = vec![
            canonical_pattern(r"\b(?:foo)\b", &["IGNORECASE"]),
            canonical_pattern(r"\b(?:FOOBAR)\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];

        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("bounded case-sensitive and insensitive literals should be layered");
        };
        assert_eq!(
            shard
                .ascii_case_insensitive_literals
                .as_ref()
                .unwrap()
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            engine_raw_matches(&engine, "FOOBAR FoO food 9"),
            monolithic_raw_matches(&patterns, "FOOBAR FoO food 9")
        );
        assert_eq!(
            monolithic_raw_matches(&patterns, "FOOBAR FoO food 9"),
            [(1, 0, 6), (0, 7, 10), (2, 16, 17)]
        );
    }

    #[test]
    fn bounded_literal_handles_punctuation_and_word_adjacency() {
        let patterns = vec![
            canonical_pattern(r"\b(?:foo)\b", &[]),
            canonical_pattern(r"\d+", &[]),
        ];
        let text = "(foo),foo-bar_foo foo";

        assert_layered_matches_monolithic(patterns.clone(), text);
        assert_eq!(
            monolithic_raw_matches(&patterns, text),
            [(0, 1, 4), (0, 6, 9), (0, 18, 21)]
        );
    }

    #[test]
    fn normalized_whitespace_literal_remains_in_residual_regex_layer() {
        let patterns = vec![
            canonical_pattern(r"\b(?:alpha)\b", &[]),
            canonical_pattern(r"\b(?:John\s+Doe)\b", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("bounded literal plus normalized whitespace should be layered");
        };

        assert_eq!(
            shard
                .case_sensitive_literals
                .as_ref()
                .unwrap()
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            shard
                .residual_regex
                .as_ref()
                .unwrap()
                .local_to_pattern_order,
            [1]
        );
        assert_eq!(
            engine_raw_matches(&engine, "alpha John   Doe"),
            monolithic_raw_matches(&patterns, "alpha John   Doe")
        );
    }

    #[test]
    fn layered_matcher_preserves_anchor_context_after_cursor_advances() {
        let patterns = vec![
            canonical_pattern("X", &[]),
            canonical_pattern(r"^foo", &["MULTILINE"]),
            canonical_pattern(r"\Abar", &[]),
        ];

        assert_layered_matches_monolithic(patterns.clone(), "Xfoo\nfoo bar");
        assert_eq!(
            monolithic_raw_matches(&patterns, "Xfoo\nfoo bar"),
            [(0, 0, 1), (1, 5, 8)]
        );
    }

    #[test]
    fn layered_entity_keeps_cross_entity_overlap() {
        let bank = NativeBank::from_source_bytes(
            br#"{"PERSON":{"Sam":"Sam","S-name":"Sa.+"},"PROJECT":{"Samba":"Samba"}}"#,
            Some("json"),
            None,
        )
        .unwrap();

        assert_eq!(raw_matches(bank, "Samba"), [(0, 0, 3), (2, 0, 5)]);
    }

    #[test]
    fn exact_grouped_hir_literal_is_eligible_for_literal_layer() {
        let patterns = vec![
            canonical_pattern(r"(alpha)", &[]),
            canonical_pattern(r"\d+", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("grouped exact literal should use the layered matcher");
        };

        assert_eq!(
            shard
                .case_sensitive_literals
                .as_ref()
                .unwrap()
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            engine_raw_matches(&engine, "alpha 7"),
            monolithic_raw_matches(&patterns, "alpha 7")
        );
    }

    #[test]
    fn possibly_empty_pattern_conservatively_uses_monolithic_matcher() {
        let engine = engine_for_patterns(vec![
            canonical_pattern("a", &[]),
            canonical_pattern(r"b*", &[]),
        ]);

        assert!(matches!(engine.shards.as_slice(), [MatcherShard::Regex(_)]));
    }

    #[test]
    fn layered_matcher_preserves_bounded_match_failure_and_clears_output() {
        let engine = engine_for_patterns(vec![
            canonical_pattern("a", &[]),
            canonical_pattern(r"\d+", &[]),
        ]);
        let mut buffer = NativeMatchBuffer::with_match_limit(2).unwrap();

        let error = engine
            .scan_bytes_into(b"a1a2", &mut buffer)
            .expect_err("the third match must exceed the configured limit");

        assert!(error.to_string().contains("configured match limit 2"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn layered_matcher_rejects_invalid_utf8_before_search() {
        let engine = engine_for_patterns(vec![
            canonical_pattern("a", &[]),
            canonical_pattern(r"\d+", &[]),
        ]);
        let mut buffer = NativeMatchBuffer::new();

        let error = engine.scan_bytes_into(&[0xff], &mut buffer).unwrap_err();

        assert!(error.to_string().contains("valid UTF-8"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn layered_matcher_matches_monolithic_reference_across_generated_cases() {
        let mut state = 0x5eed_cafe_f00d_u64;
        for case_index in 0..192 {
            let mut patterns = vec![canonical_pattern("a", &[]), canonical_pattern(r"a+", &[])];
            let extra_patterns = 1 + next_generated(&mut state) % 6;
            for _ in 0..extra_patterns {
                patterns.push(generated_pattern(next_generated(&mut state)));
            }
            rotate_generated(&mut patterns, next_generated(&mut state));

            let text_len = next_generated(&mut state) % 96;
            let mut text = String::new();
            for _ in 0..text_len {
                const PIECES: [&str; 17] = [
                    "a", "b", "A", "B", "f", "o", "0", "1", " ", "-", "_", "(", ")", "é", "β", "K",
                    "\u{301}",
                ];
                text.push_str(PIECES[next_generated(&mut state) % PIECES.len()]);
            }

            let expected = monolithic_raw_matches(&patterns, &text);
            let engine = engine_for_patterns(patterns.clone());
            assert!(matches!(
                engine.shards.as_slice(),
                [MatcherShard::Layered(_)]
            ));
            assert_eq!(
                engine_raw_matches(&engine, &text),
                expected,
                "generated differential case {case_index} failed for patterns {patterns:?} and text {text:?}"
            );
        }
    }

    #[test]
    fn layered_matcher_matches_monolithic_reference_for_dense_large_entity() {
        let mut patterns = (0..500)
            .map(|index| {
                canonical_pattern(&format!(r"\b(?:contact{index:03}@example\.com)\b"), &[])
            })
            .collect::<Vec<_>>();
        patterns.insert(173, canonical_pattern(r"ticket-[0-9]+", &[]));
        let text = (0..120)
            .map(|index| {
                format!(
                    "contact{:03}@example.com ticket-{}",
                    index % 500,
                    10_000 + index
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let expected = monolithic_raw_matches(&patterns, &text);
        let engine = engine_for_patterns(patterns);

        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("bounded literals plus residual regex should be layered");
        };
        assert_eq!(
            shard
                .case_sensitive_literals
                .as_ref()
                .unwrap()
                .patterns
                .len(),
            500
        );
        assert_eq!(
            shard
                .residual_regex
                .as_ref()
                .unwrap()
                .local_to_pattern_order
                .len(),
            1
        );
        assert_eq!(engine_raw_matches(&engine, &text), expected);
    }

    fn next_generated(state: &mut u64) -> usize {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state as usize
    }

    fn generated_pattern(selector: usize) -> CanonicalPattern {
        match selector % 20 {
            0 => canonical_pattern("a", &[]),
            1 => canonical_pattern("ab", &[]),
            2 => canonical_pattern("foo", &[]),
            3 => canonical_pattern("FOO", &[]),
            4 => canonical_pattern("foo", &["IGNORECASE"]),
            5 => canonical_pattern("k", &["IGNORECASE"]),
            6 => canonical_pattern("é", &[]),
            7 => canonical_pattern(r"a+", &[]),
            8 => canonical_pattern(r"a(?:b)?", &[]),
            9 => canonical_pattern(r"(ab|a)", &[]),
            10 => canonical_pattern(r"\bfoo\b", &[]),
            11 => canonical_pattern(r"[A-B]+", &[]),
            12 => canonical_pattern(r"\d+", &[]),
            13 => canonical_pattern(r"é+", &[]),
            14 => canonical_pattern(r"\b(?:a)\b", &[]),
            15 => canonical_pattern(r"\b(?:ab)\b", &[]),
            16 => canonical_pattern(r"\b(?:foo)", &[]),
            17 => canonical_pattern(r"(?:foo)\b", &[]),
            18 => canonical_pattern(r"\b(?:foo)\b", &["IGNORECASE"]),
            _ => canonical_pattern(r"\b(?:a\s+b)\b", &[]),
        }
    }

    fn rotate_generated(patterns: &mut [CanonicalPattern], selector: usize) {
        if !patterns.is_empty() {
            patterns.rotate_left(selector % patterns.len());
        }
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
