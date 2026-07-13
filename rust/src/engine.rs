use crate::bank::{CanonicalBank, CanonicalPattern, MatchMode};
use crate::error::{memory, validation, Result};
use crate::match_buffer::{NativeMatchBuffer, RawMatch};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, Input as AhoInput, MatchKind as AhoMatchKind};
use regex_automata::hybrid::dfa::{Cache as HybridCache, OverlappingState, DFA as HybridDfa};
use regex_automata::meta::{BuildError as RegexBuildError, Cache as RegexCache, Regex};
use regex_automata::nfa::thompson::{self, WhichCaptures};
use regex_automata::util::iter::Searcher;
use regex_automata::{Anchored, Input, MatchError, MatchKind as RegexMatchKind};
use regex_syntax::hir::{Hir, HirKind, Look};
use regex_syntax::{is_word_character, ParserBuilder};
use std::cmp::Ordering;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

const ENTITY_INDEPENDENT_NFA_SIZE_LIMIT: usize = 10 * 1024 * 1024;
const ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const INTERNAL_MODE_HYBRID_CACHE_CAPACITY: usize = 2 * 1024 * 1024;
pub(crate) const ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY: usize = 32 * 1024;
pub(crate) const MAX_LAZY_DFA_CACHES_PER_META_REGEX: usize = 3;
pub(crate) const PIKEVM_STACK_NFA_MEMORY_MULTIPLIER: usize = 16;
const PIKEVM_ACTIVE_STATE_ID_VECTORS: usize = 4;
const PIKEVM_ACTIVE_STATE_SLOT_TABLES: usize = 2;
const PIKEVM_STATE_ID_BYTES: usize = 4;
const ENTITY_INDEPENDENT_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const ENTITY_INDEPENDENT_DFA_STATE_LIMIT: usize = 1_000;
pub(crate) const MAX_CONCURRENT_SCANS_PER_ENGINE: usize = 8;
pub(crate) const MAX_SCAN_INPUT_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY: usize = 128;
pub(crate) const MAX_ENTITY_INDEPENDENT_REGEX_ACCOUNTED_BYTES: usize = 768 * 1024 * 1024;
pub(crate) const MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER: usize = 128;
const BOUNDED_REGEX_INITIAL_MAX_MINIMUM_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct NativeEngine {
    match_mode: MatchMode,
    detectors: Vec<DetectorMetadata>,
    shards: Vec<MatcherShard>,
    all_overlaps: Option<AllOverlapsMatcher>,
    global_leftmost: Option<GlobalLeftmostMatcher>,
    regex_resources: Option<RegexResourceProfile>,
    scan_limiter: ScanLimiter,
}

#[derive(Debug, Default)]
struct ScanLimiter {
    state: Mutex<ScanLimiterState>,
    available: Condvar,
}

#[derive(Debug, Default)]
struct ScanLimiterState {
    active: usize,
    slots_in_use: [bool; MAX_CONCURRENT_SCANS_PER_ENGINE],
    #[cfg(test)]
    maximum_observed: usize,
}

#[derive(Debug)]
struct ScanPermit<'a> {
    limiter: &'a ScanLimiter,
    slot: usize,
}

impl ScanLimiter {
    fn acquire(&self) -> ScanPermit<'_> {
        let mut state = self.lock_state();
        while state.active >= MAX_CONCURRENT_SCANS_PER_ENGINE {
            state = self
                .available
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        let slot = state
            .slots_in_use
            .iter()
            .position(|in_use| !in_use)
            .expect("active scan count guarantees an available cache slot");
        state.slots_in_use[slot] = true;
        state.active += 1;
        #[cfg(test)]
        {
            state.maximum_observed = state.maximum_observed.max(state.active);
        }
        drop(state);
        ScanPermit {
            limiter: self,
            slot,
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, ScanLimiterState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn observed_concurrency(&self) -> (usize, usize) {
        let state = self.lock_state();
        (state.active, state.maximum_observed)
    }
}

impl ScanPermit<'_> {
    fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for ScanPermit<'_> {
    fn drop(&mut self) {
        let mut state = self.limiter.lock_state();
        if let Some(in_use) = state.slots_in_use.get_mut(self.slot) {
            *in_use = false;
        }
        if state.active > 0 {
            state.active -= 1;
        }
        drop(state);
        self.limiter.available.notify_one();
    }
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
    matcher: RegexShardMatcher,
}

#[derive(Debug)]
enum RegexShardMatcher {
    Monolithic {
        regex: CachedRegex,
        local_to_detector: Vec<u32>,
    },
    Bounded {
        layers: Vec<RegexMatcherLayer>,
    },
}

#[derive(Debug)]
struct LiteralMatcherShard {
    entity: String,
    matcher: AhoCorasick,
    case_insensitive: bool,
    local_to_detector: Vec<u32>,
}

#[derive(Debug)]
struct LayeredMatcherShard {
    entity: String,
    case_sensitive_literals: LiteralMatcherLayers,
    ascii_case_insensitive_literals: LiteralMatcherLayers,
    normalized_case_sensitive_literals: LiteralMatcherLayers,
    normalized_ascii_case_insensitive_literals: LiteralMatcherLayers,
    residual_regex_layers: Vec<RegexMatcherLayer>,
}

#[derive(Debug)]
struct MappedHaystack {
    bytes: Vec<u8>,
    checkpoints: Vec<(usize, usize)>,
}

impl MappedHaystack {
    fn original_boundary(&self, mapped: usize) -> Option<usize> {
        if mapped > self.bytes.len() {
            return None;
        }
        let checkpoint_index = self
            .checkpoints
            .partition_point(|&(mapped_after, _)| mapped_after <= mapped);
        let delta = checkpoint_index
            .checked_sub(1)
            .and_then(|index| self.checkpoints.get(index))
            .map(|&(mapped_after, original_after)| original_after - mapped_after)
            .unwrap_or(0);
        mapped.checked_add(delta)
    }

    fn mapped_boundary_at_or_after(&self, original: usize) -> usize {
        let mut low = 0;
        let mut high = self.bytes.len();
        while low < high {
            let middle = low + (high - low) / 2;
            if self
                .original_boundary(middle)
                .expect("mapped offset is within the haystack")
                < original
            {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
}

#[derive(Debug, Default)]
struct LiteralMatcherLayers {
    without_left_boundary: Option<LiteralMatcherLayer>,
    with_left_boundary: Option<LiteralMatcherLayer>,
}

#[derive(Debug)]
struct LiteralMatcherLayer {
    matcher: AhoCorasick,
    case_insensitive: bool,
    requires_left_unicode_word_boundary: bool,
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
    regex: CachedRegex,
    local_to_detector: Vec<u32>,
    local_to_pattern_order: Vec<usize>,
}

#[derive(Debug)]
struct RegexResourceBudget {
    entity_layers: usize,
    total_layers: usize,
    max_entity_layers: usize,
    static_bytes: usize,
    eager_cache_bytes_per_scan: usize,
    pikevm_cache_projection_bytes_per_scan: usize,
    pikevm_stack_growth_allowance_bytes_per_scan: usize,
    lazy_dfa_growth_allowance_bytes_per_scan: usize,
    regex_cache_allowance_bytes: usize,
    size_limit_bisections: usize,
    resource_limit_bisections: usize,
    maximum_accounted_bytes: usize,
}

impl Default for RegexResourceBudget {
    fn default() -> Self {
        Self {
            entity_layers: 0,
            total_layers: 0,
            max_entity_layers: 0,
            static_bytes: 0,
            eager_cache_bytes_per_scan: 0,
            pikevm_cache_projection_bytes_per_scan: 0,
            pikevm_stack_growth_allowance_bytes_per_scan: 0,
            lazy_dfa_growth_allowance_bytes_per_scan: 0,
            regex_cache_allowance_bytes: 0,
            size_limit_bisections: 0,
            resource_limit_bisections: 0,
            maximum_accounted_bytes: MAX_ENTITY_INDEPENDENT_REGEX_ACCOUNTED_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RegexResourceProfile {
    pub physical_regex_layers: usize,
    pub maximum_regex_layers_per_entity: usize,
    pub compiled_regex_static_bytes: usize,
    pub eager_cache_bytes_per_scan: usize,
    pub pikevm_cache_projection_bytes_per_scan: usize,
    pub pikevm_stack_growth_allowance_bytes_per_scan: usize,
    pub lazy_dfa_growth_allowance_bytes_per_scan: usize,
    pub regex_cache_allowance_bytes: usize,
    pub size_limit_bisections: usize,
    pub resource_limit_bisections: usize,
}

impl RegexResourceBudget {
    fn start_entity(&mut self) {
        self.entity_layers = 0;
    }

    fn record(
        &mut self,
        entity_name: &str,
        regex: &Regex,
        patterns: &[Hir],
        cache_capacity: usize,
    ) -> Result<()> {
        let next_layers = self.entity_layers.checked_add(1).ok_or_else(|| {
            memory(
                format!("/engine/shards/{entity_name}/regex_resource_budget"),
                "compiled regex layer count overflowed",
            )
        })?;
        let next_total_layers = self.total_layers.checked_add(1).ok_or_else(|| {
            memory(
                format!("/engine/shards/{entity_name}/regex_resource_budget"),
                "compiled regex total layer count overflowed",
            )
        })?;
        let next_static_bytes = self
            .static_bytes
            .checked_add(regex.memory_usage())
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex static memory accounting overflowed",
                )
            })?;
        let (eager_cache_bytes, pikevm_cache_projection_bytes, pikevm_stack_growth_allowance_bytes) =
            regex_cache_components(entity_name, regex, patterns)?;
        let lazy_dfa_growth_allowance_bytes = cache_capacity
            .checked_mul(MAX_LAZY_DFA_CACHES_PER_META_REGEX)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex lazy-DFA growth allowance overflowed",
                )
            })?;
        let next_eager_cache_bytes_per_scan = self
            .eager_cache_bytes_per_scan
            .checked_add(eager_cache_bytes)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex eager cache aggregate overflowed",
                )
            })?;
        let next_pikevm_cache_projection_bytes_per_scan = self
            .pikevm_cache_projection_bytes_per_scan
            .checked_add(pikevm_cache_projection_bytes)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex PikeVM cache aggregate overflowed",
                )
            })?;
        let next_pikevm_stack_growth_allowance_bytes_per_scan = self
            .pikevm_stack_growth_allowance_bytes_per_scan
            .checked_add(pikevm_stack_growth_allowance_bytes)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex PikeVM stack allowance aggregate overflowed",
                )
            })?;
        let next_lazy_dfa_growth_allowance_bytes_per_scan = self
            .lazy_dfa_growth_allowance_bytes_per_scan
            .checked_add(lazy_dfa_growth_allowance_bytes)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex lazy-DFA growth aggregate overflowed",
                )
            })?;
        let next_regex_cache_allowance_bytes = next_eager_cache_bytes_per_scan
            .checked_add(next_pikevm_cache_projection_bytes_per_scan)
            .and_then(|bytes| bytes.checked_add(next_pikevm_stack_growth_allowance_bytes_per_scan))
            .and_then(|bytes| bytes.checked_add(next_lazy_dfa_growth_allowance_bytes_per_scan))
            .and_then(|bytes| bytes.checked_mul(MAX_CONCURRENT_SCANS_PER_ENGINE))
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex concurrent cache allowance overflowed",
                )
            })?;
        let next_bytes = next_static_bytes
            .checked_add(next_regex_cache_allowance_bytes)
            .ok_or_else(|| {
                memory(
                    format!("/engine/shards/{entity_name}/regex_resource_budget"),
                    "compiled regex aggregate memory accounting overflowed",
                )
            })?;
        if next_layers > MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY
            || next_bytes > self.maximum_accounted_bytes
        {
            return Err(memory(
                format!("/engine/shards/{entity_name}/regex_resource_budget"),
                format!(
                    "compiled regex resource budget exceeded: entity layers {next_layers}/{MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY}, static bytes {next_static_bytes}, eager cache bytes per scan {next_eager_cache_bytes_per_scan}, PikeVM fixed cache projection bytes per scan {next_pikevm_cache_projection_bytes_per_scan}, PikeVM stack growth allowance bytes per scan {next_pikevm_stack_growth_allowance_bytes_per_scan}, lazy-DFA growth allowance bytes per scan {next_lazy_dfa_growth_allowance_bytes_per_scan}, concurrent cache allowance bytes {next_regex_cache_allowance_bytes}, accounted bytes {next_bytes}/{} across {MAX_CONCURRENT_SCANS_PER_ENGINE} scan slots",
                    self.maximum_accounted_bytes,
                ),
            ));
        }
        self.entity_layers = next_layers;
        self.total_layers = next_total_layers;
        self.max_entity_layers = self.max_entity_layers.max(next_layers);
        self.static_bytes = next_static_bytes;
        self.eager_cache_bytes_per_scan = next_eager_cache_bytes_per_scan;
        self.pikevm_cache_projection_bytes_per_scan = next_pikevm_cache_projection_bytes_per_scan;
        self.pikevm_stack_growth_allowance_bytes_per_scan =
            next_pikevm_stack_growth_allowance_bytes_per_scan;
        self.lazy_dfa_growth_allowance_bytes_per_scan =
            next_lazy_dfa_growth_allowance_bytes_per_scan;
        self.regex_cache_allowance_bytes = next_regex_cache_allowance_bytes;
        Ok(())
    }

    fn profile(&self) -> RegexResourceProfile {
        RegexResourceProfile {
            physical_regex_layers: self.total_layers,
            maximum_regex_layers_per_entity: self.max_entity_layers,
            compiled_regex_static_bytes: self.static_bytes,
            eager_cache_bytes_per_scan: self.eager_cache_bytes_per_scan,
            pikevm_cache_projection_bytes_per_scan: self.pikevm_cache_projection_bytes_per_scan,
            pikevm_stack_growth_allowance_bytes_per_scan: self
                .pikevm_stack_growth_allowance_bytes_per_scan,
            lazy_dfa_growth_allowance_bytes_per_scan: self.lazy_dfa_growth_allowance_bytes_per_scan,
            regex_cache_allowance_bytes: self.regex_cache_allowance_bytes,
            size_limit_bisections: self.size_limit_bisections,
            resource_limit_bisections: self.resource_limit_bisections,
        }
    }
}

fn regex_cache_components(
    entity_name: &str,
    regex: &Regex,
    patterns: &[Hir],
) -> Result<(usize, usize, usize)> {
    let budget_path = || format!("/engine/shards/{entity_name}/regex_resource_budget");
    let cache = regex.create_cache();
    let capture_slot_bytes = regex
        .group_info()
        .slot_len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or_else(|| {
            memory(
                budget_path(),
                "compiled regex capture-slot accounting overflowed",
            )
        })?;
    let eager_cache_bytes = cache
        .memory_usage()
        .checked_add(std::mem::size_of::<Mutex<RegexCache>>())
        .and_then(|bytes| bytes.checked_add(capture_slot_bytes))
        .ok_or_else(|| {
            memory(
                budget_path(),
                "compiled regex eager cache accounting overflowed",
            )
        })?;

    // regex-automata's meta cache creates its PikeVM cache lazily. Compile
    // the equivalent implicit-capture NFA and project its fixed allocations
    // with checked arithmetic before any potentially quadratic slot table is
    // allocated.
    let nfa = thompson::NFA::compiler()
        .configure(
            thompson::Config::new()
                .which_captures(WhichCaptures::Implicit)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT)),
        )
        .build_many_from_hir(patterns)
        .map_err(|error| {
            validation(
                budget_path(),
                format!("could not compile PikeVM cache-accounting NFA: {error}"),
            )
        })?;
    let pikevm_cache_projection_bytes = project_pikevm_cache_bytes(&nfa)
        .ok_or_else(|| memory(budget_path(), "PikeVM fixed cache projection overflowed"))?;

    // PikeVM's epsilon-closure stack is empty at cache creation and grows at
    // search time. In regex-automata 0.4.14, every pushed Explore frame is
    // represented by a State or Union alternate in NFA::memory_usage, and
    // every RestoreCapture frame is represented by a Capture state. A frame
    // is at most four machine words, versus a four-byte StateID for the
    // smallest backing edge. A 16x multiplier therefore covers that worst
    // 8x representation ratio and Vec's at-most-2x geometric retained
    // capacity.
    let pikevm_stack_growth_allowance_bytes = nfa
        .memory_usage()
        .checked_mul(PIKEVM_STACK_NFA_MEMORY_MULTIPLIER)
        .ok_or_else(|| memory(budget_path(), "PikeVM epsilon-stack allowance overflowed"))?;

    Ok((
        eager_cache_bytes,
        pikevm_cache_projection_bytes,
        pikevm_stack_growth_allowance_bytes,
    ))
}

fn project_pikevm_cache_bytes(nfa: &thompson::NFA) -> Option<usize> {
    project_pikevm_cache_bytes_from_counts(
        nfa.states().len(),
        nfa.group_info().slot_len(),
        nfa.pattern_len(),
    )
}

fn project_pikevm_cache_bytes_from_counts(
    states: usize,
    slots_per_state: usize,
    patterns: usize,
) -> Option<usize> {
    let implicit_slots = patterns.checked_mul(2)?;
    let scratch_slots = slots_per_state.max(implicit_slots);

    let active_state_id_bytes = states
        .checked_mul(PIKEVM_ACTIVE_STATE_ID_VECTORS)?
        .checked_mul(PIKEVM_STATE_ID_BYTES)?;
    let slots_per_table = states
        .checked_mul(slots_per_state)?
        .checked_add(scratch_slots)?;
    let slot_table_bytes = slots_per_table
        .checked_mul(PIKEVM_ACTIVE_STATE_SLOT_TABLES)?
        .checked_mul(std::mem::size_of::<usize>())?;
    active_state_id_bytes.checked_add(slot_table_bytes)
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

#[derive(Debug)]
struct GlobalLeftmostMatcher {
    regex: CachedRegex,
    local_to_detector: Vec<u32>,
}

#[derive(Debug)]
struct CachedRegex {
    regex: Regex,
    caches: Vec<Mutex<RegexCache>>,
}

impl CachedRegex {
    fn new(regex: Regex) -> CachedRegex {
        let caches = (0..MAX_CONCURRENT_SCANS_PER_ENGINE)
            .map(|_| Mutex::new(regex.create_cache()))
            .collect();
        CachedRegex { regex, caches }
    }

    fn cache(&self, scan_slot: usize) -> MutexGuard<'_, RegexCache> {
        let cache_mutex = self
            .caches
            .get(scan_slot)
            .expect("scan limiter returned an invalid cache slot");
        match cache_mutex.lock() {
            Ok(cache) => cache,
            Err(poisoned) => {
                let mut cache = poisoned.into_inner();
                cache.reset(&self.regex);
                cache_mutex.clear_poison();
                cache
            }
        }
    }
}

impl NativeEngine {
    pub fn compile(canonical: &CanonicalBank, match_mode: MatchMode) -> Result<Self> {
        let detectors = detector_metadata(canonical)?;
        let (shards, regex_resources) = if matches!(
            match_mode,
            MatchMode::EntityIndependent | MatchMode::AllOverlaps
        ) {
            let (shards, resources) = compile_entity_independent(canonical)?;
            (shards, Some(resources))
        } else {
            (Vec::new(), None)
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
            regex_resources,
            scan_limiter: ScanLimiter::default(),
        })
    }

    pub fn detectors(&self) -> &[DetectorMetadata] {
        &self.detectors
    }

    pub fn match_mode(&self) -> MatchMode {
        self.match_mode
    }

    pub fn regex_resource_profile(&self) -> Option<&RegexResourceProfile> {
        self.regex_resources.as_ref()
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
        validate_scan_input_size(haystack)?;
        let mut buffer = NativeMatchBuffer::with_match_limit(max_matches)?;
        self.scan_bytes_into(haystack, &mut buffer)?;
        Ok(buffer)
    }

    pub fn scan_bytes_into(&self, haystack: &[u8], buffer: &mut NativeMatchBuffer) -> Result<()> {
        buffer.clear();
        validate_scan_input_size(haystack)?;
        std::str::from_utf8(haystack).map_err(|error| {
            validation(
                "/scan_bytes/haystack",
                format!("Bank.scan_bytes requires valid UTF-8 input: {error}"),
            )
        })?;
        let permit = self.scan_limiter.acquire();
        let scan_slot = permit.slot();

        let result = match self.match_mode {
            MatchMode::EntityIndependent => {
                scan_entity_independent(&self.shards, haystack, buffer, scan_slot)
            }
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
                scan_slot,
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
        validate_scan_input_size(haystack)?;
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
        let permit = self.scan_limiter.acquire();
        let scan_slot = permit.slot();

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
            scan_entity_independent(&self.shards, haystack, buffer, scan_slot)
        });
        if result.is_err() {
            buffer.clear();
        }
        result
    }
}

pub(crate) fn validate_scan_input_size(haystack: &[u8]) -> Result<()> {
    if haystack.len() > MAX_SCAN_INPUT_BYTES {
        return Err(validation(
            "/scan_bytes/haystack",
            format!(
                "Bank scan input size {} exceeds the configured limit of {MAX_SCAN_INPUT_BYTES} bytes",
                haystack.len()
            ),
        ));
    }
    Ok(())
}

fn scan_entity_independent(
    shards: &[MatcherShard],
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
    scan_slot: usize,
) -> Result<()> {
    for shard in shards {
        match shard {
            MatcherShard::Regex(shard) => scan_regex_shard(shard, haystack, buffer, scan_slot)?,
            MatcherShard::Literal(shard) => scan_literal_shard(shard, haystack, buffer)?,
            MatcherShard::Layered(shard) => scan_layered_shard(shard, haystack, buffer, scan_slot)?,
        }
    }
    buffer.sort();
    Ok(())
}

fn scan_regex_shard(
    shard: &RegexMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
    scan_slot: usize,
) -> Result<()> {
    match &shard.matcher {
        RegexShardMatcher::Monolithic {
            regex,
            local_to_detector,
        } => scan_regex_matches(
            &shard.entity,
            regex,
            local_to_detector,
            haystack,
            buffer,
            scan_slot,
        ),
        RegexShardMatcher::Bounded { layers } => {
            scan_regex_layers_leftmost(&shard.entity, layers, haystack, buffer, scan_slot)
        }
    }
}

fn scan_literal_shard(
    shard: &LiteralMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
) -> Result<()> {
    let haystack_text = std::str::from_utf8(haystack)
        .expect("scan_bytes_into validates UTF-8 before literal dispatch");
    let mapped = (shard.case_insensitive && requires_ascii_casefold_mapping(haystack_text))
        .then(|| map_haystack(haystack_text, false, true));
    let matcher_haystack = mapped
        .as_ref()
        .map(|mapped| mapped.bytes.as_slice())
        .unwrap_or(haystack);

    for raw_match in shard.matcher.find_iter(matcher_haystack) {
        let local_index = raw_match.pattern().as_usize();
        let Some(&detector_index) = shard.local_to_detector.get(local_index) else {
            return Err(validation(
                format!("/engine/shards/{}/local_to_detector", shard.entity),
                format!(
                    "literal engine returned local pattern index {local_index} outside detector map"
                ),
            ));
        };
        let (start, end) = match &mapped {
            Some(mapped) => (
                mapped.original_boundary(raw_match.start()).ok_or_else(|| {
                    validation(
                        format!("/engine/shards/{}/mapped_literal/start", shard.entity),
                        "mapped literal start is outside the offset map",
                    )
                })?,
                mapped.original_boundary(raw_match.end()).ok_or_else(|| {
                    validation(
                        format!("/engine/shards/{}/mapped_literal/end", shard.entity),
                        "mapped literal end is outside the offset map",
                    )
                })?,
            ),
            None => (raw_match.start(), raw_match.end()),
        };
        push_utf8_match(buffer, haystack, detector_index, start as u64, end as u64)?;
    }
    Ok(())
}

fn scan_layered_shard(
    shard: &LayeredMatcherShard,
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
    scan_slot: usize,
) -> Result<()> {
    let haystack_text = std::str::from_utf8(haystack)
        .expect("scan_bytes_into validates UTF-8 before dispatching to the layered matcher");
    let needs_casefold_mapping = requires_ascii_casefold_mapping(haystack_text);
    let needs_whitespace_mapping = requires_whitespace_mapping(haystack_text);
    let casefold_haystack = (needs_casefold_mapping
        && !shard.ascii_case_insensitive_literals.is_empty())
    .then(|| map_haystack(haystack_text, false, true));
    let normalized_case_sensitive_haystack = (needs_whitespace_mapping
        && !shard.normalized_case_sensitive_literals.is_empty())
    .then(|| map_haystack(haystack_text, true, false));
    let normalized_case_insensitive_haystack = ((needs_whitespace_mapping
        || needs_casefold_mapping)
        && !shard.normalized_ascii_case_insensitive_literals.is_empty())
    .then(|| map_haystack(haystack_text, true, true));

    let mut cursor = 0;
    let mut case_sensitive_without_left_boundary = next_literal_candidate(
        &shard.entity,
        shard.case_sensitive_literals.without_left_boundary.as_ref(),
        haystack,
        haystack_text,
        cursor,
    )?;
    let mut case_sensitive_with_left_boundary = next_literal_candidate(
        &shard.entity,
        shard.case_sensitive_literals.with_left_boundary.as_ref(),
        haystack,
        haystack_text,
        cursor,
    )?;
    let mut case_insensitive_without_left_boundary = next_literal_candidate_with_mapping(
        &shard.entity,
        shard
            .ascii_case_insensitive_literals
            .without_left_boundary
            .as_ref(),
        haystack,
        haystack_text,
        casefold_haystack.as_ref(),
        cursor,
    )?;
    let mut case_insensitive_with_left_boundary = next_literal_candidate_with_mapping(
        &shard.entity,
        shard
            .ascii_case_insensitive_literals
            .with_left_boundary
            .as_ref(),
        haystack,
        haystack_text,
        casefold_haystack.as_ref(),
        cursor,
    )?;
    let mut normalized_case_sensitive_without_left_boundary = next_literal_candidate_with_mapping(
        &shard.entity,
        shard
            .normalized_case_sensitive_literals
            .without_left_boundary
            .as_ref(),
        haystack,
        haystack_text,
        normalized_case_sensitive_haystack.as_ref(),
        cursor,
    )?;
    let mut normalized_case_sensitive_with_left_boundary = next_literal_candidate_with_mapping(
        &shard.entity,
        shard
            .normalized_case_sensitive_literals
            .with_left_boundary
            .as_ref(),
        haystack,
        haystack_text,
        normalized_case_sensitive_haystack.as_ref(),
        cursor,
    )?;
    let mut normalized_case_insensitive_without_left_boundary =
        next_literal_candidate_with_mapping(
            &shard.entity,
            shard
                .normalized_ascii_case_insensitive_literals
                .without_left_boundary
                .as_ref(),
            haystack,
            haystack_text,
            normalized_case_insensitive_haystack.as_ref(),
            cursor,
        )?;
    let mut normalized_case_insensitive_with_left_boundary = next_literal_candidate_with_mapping(
        &shard.entity,
        shard
            .normalized_ascii_case_insensitive_literals
            .with_left_boundary
            .as_ref(),
        haystack,
        haystack_text,
        normalized_case_insensitive_haystack.as_ref(),
        cursor,
    )?;
    let mut residual_candidates = shard
        .residual_regex_layers
        .iter()
        .map(|layer| next_regex_candidate(&shard.entity, Some(layer), haystack, cursor, scan_slot))
        .collect::<Result<Vec<_>>>()?;

    loop {
        // Each layer applies its own leftmost-first semantics. Merging the
        // layers by start and then original pattern order reconstructs the
        // same winner as one leftmost-first regex over every entity pattern.
        let Some(winner) = [
            case_sensitive_without_left_boundary,
            case_sensitive_with_left_boundary,
            case_insensitive_without_left_boundary,
            case_insensitive_with_left_boundary,
            normalized_case_sensitive_without_left_boundary,
            normalized_case_sensitive_with_left_boundary,
            normalized_case_insensitive_without_left_boundary,
            normalized_case_insensitive_with_left_boundary,
        ]
        .into_iter()
        .flatten()
        .chain(residual_candidates.iter().flatten().copied())
        .min_by_key(|candidate| (candidate.start, candidate.pattern_order)) else {
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
        if candidate_precedes_cursor(case_sensitive_without_left_boundary, cursor) {
            case_sensitive_without_left_boundary = next_literal_candidate(
                &shard.entity,
                shard.case_sensitive_literals.without_left_boundary.as_ref(),
                haystack,
                haystack_text,
                cursor,
            )?;
        }
        if candidate_precedes_cursor(case_sensitive_with_left_boundary, cursor) {
            case_sensitive_with_left_boundary = next_literal_candidate(
                &shard.entity,
                shard.case_sensitive_literals.with_left_boundary.as_ref(),
                haystack,
                haystack_text,
                cursor,
            )?;
        }
        if candidate_precedes_cursor(case_insensitive_without_left_boundary, cursor) {
            case_insensitive_without_left_boundary = next_literal_candidate_with_mapping(
                &shard.entity,
                shard
                    .ascii_case_insensitive_literals
                    .without_left_boundary
                    .as_ref(),
                haystack,
                haystack_text,
                casefold_haystack.as_ref(),
                cursor,
            )?;
        }
        if candidate_precedes_cursor(case_insensitive_with_left_boundary, cursor) {
            case_insensitive_with_left_boundary = next_literal_candidate_with_mapping(
                &shard.entity,
                shard
                    .ascii_case_insensitive_literals
                    .with_left_boundary
                    .as_ref(),
                haystack,
                haystack_text,
                casefold_haystack.as_ref(),
                cursor,
            )?;
        }
        if candidate_precedes_cursor(normalized_case_sensitive_without_left_boundary, cursor) {
            normalized_case_sensitive_without_left_boundary = next_literal_candidate_with_mapping(
                &shard.entity,
                shard
                    .normalized_case_sensitive_literals
                    .without_left_boundary
                    .as_ref(),
                haystack,
                haystack_text,
                normalized_case_sensitive_haystack.as_ref(),
                cursor,
            )?;
        }
        if candidate_precedes_cursor(normalized_case_sensitive_with_left_boundary, cursor) {
            normalized_case_sensitive_with_left_boundary = next_literal_candidate_with_mapping(
                &shard.entity,
                shard
                    .normalized_case_sensitive_literals
                    .with_left_boundary
                    .as_ref(),
                haystack,
                haystack_text,
                normalized_case_sensitive_haystack.as_ref(),
                cursor,
            )?;
        }
        if candidate_precedes_cursor(normalized_case_insensitive_without_left_boundary, cursor) {
            normalized_case_insensitive_without_left_boundary =
                next_literal_candidate_with_mapping(
                    &shard.entity,
                    shard
                        .normalized_ascii_case_insensitive_literals
                        .without_left_boundary
                        .as_ref(),
                    haystack,
                    haystack_text,
                    normalized_case_insensitive_haystack.as_ref(),
                    cursor,
                )?;
        }
        if candidate_precedes_cursor(normalized_case_insensitive_with_left_boundary, cursor) {
            normalized_case_insensitive_with_left_boundary = next_literal_candidate_with_mapping(
                &shard.entity,
                shard
                    .normalized_ascii_case_insensitive_literals
                    .with_left_boundary
                    .as_ref(),
                haystack,
                haystack_text,
                normalized_case_insensitive_haystack.as_ref(),
                cursor,
            )?;
        }
        for (layer, candidate) in shard
            .residual_regex_layers
            .iter()
            .zip(&mut residual_candidates)
        {
            if candidate_precedes_cursor(*candidate, cursor) {
                *candidate =
                    next_regex_candidate(&shard.entity, Some(layer), haystack, cursor, scan_slot)?;
            }
        }
    }
    Ok(())
}

impl LiteralMatcherLayers {
    fn is_empty(&self) -> bool {
        self.without_left_boundary.is_none() && self.with_left_boundary.is_none()
    }
}

fn candidate_precedes_cursor(candidate: Option<LayerCandidate>, cursor: usize) -> bool {
    candidate
        .map(|candidate| candidate.start < cursor)
        .unwrap_or(false)
}

fn map_haystack(
    haystack: &str,
    normalize_whitespace: bool,
    ascii_casefold: bool,
) -> MappedHaystack {
    let mut bytes = Vec::with_capacity(haystack.len());
    let mut checkpoints = Vec::new();
    let mut characters = haystack.char_indices().peekable();
    while let Some((start, character)) = characters.next() {
        if normalize_whitespace && is_regex_unicode_whitespace(character) {
            let mut end = start + character.len_utf8();
            while let Some(&(next_start, next_character)) = characters.peek() {
                if !is_regex_unicode_whitespace(next_character) {
                    break;
                }
                characters.next();
                end = next_start + next_character.len_utf8();
            }
            bytes.push(b' ');
            let mapped_after = bytes.len();
            let previous_delta = checkpoints
                .last()
                .map(|&(mapped, original)| original - mapped)
                .unwrap_or(0);
            if end - mapped_after != previous_delta {
                checkpoints.push((mapped_after, end));
            }
            continue;
        }
        if ascii_casefold {
            if let Some(folded) = ascii_casefold_equivalent(character) {
                bytes.push(folded);
                checkpoints.push((bytes.len(), start + character.len_utf8()));
                continue;
            }
        }
        let mut encoded_buffer = [0; 4];
        let encoded = character.encode_utf8(&mut encoded_buffer).as_bytes();
        bytes.extend_from_slice(encoded);
    }
    let mapped = MappedHaystack { bytes, checkpoints };
    debug_assert_eq!(
        mapped.original_boundary(mapped.bytes.len()),
        Some(haystack.len())
    );
    mapped
}

fn is_regex_unicode_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

fn requires_whitespace_mapping(haystack: &str) -> bool {
    let mut previous_was_whitespace = false;
    for character in haystack.chars() {
        let is_whitespace = is_regex_unicode_whitespace(character);
        if is_whitespace && (character != ' ' || previous_was_whitespace) {
            return true;
        }
        previous_was_whitespace = is_whitespace;
    }
    false
}

fn requires_ascii_casefold_mapping(haystack: &str) -> bool {
    haystack
        .chars()
        .any(|character| ascii_casefold_equivalent(character).is_some())
}

fn ascii_casefold_equivalent(character: char) -> Option<u8> {
    // regex-syntax 0.8.10's Unicode 16 simple-fold table has exactly these
    // two non-ASCII equivalences for ASCII letters. Rust's general-purpose
    // to_uppercase/to_lowercase mappings are broader (for example dotless ı)
    // and would overmatch the regex contract here.
    match character {
        '\u{017F}' => Some(b's'),
        '\u{212A}' => Some(b'k'),
        _ => None,
    }
}

fn next_mapped_literal_candidate(
    entity: &str,
    layer: Option<&LiteralMatcherLayer>,
    mapped: &MappedHaystack,
    cursor: usize,
) -> Result<Option<LayerCandidate>> {
    let Some(layer) = layer else {
        return Ok(None);
    };
    let mapped_cursor = mapped.mapped_boundary_at_or_after(cursor);
    let mapped_text =
        std::str::from_utf8(&mapped.bytes).expect("literal haystack mapping preserves valid UTF-8");
    let Some(candidate) = next_literal_candidate(
        entity,
        Some(layer),
        &mapped.bytes,
        mapped_text,
        mapped_cursor,
    )?
    else {
        return Ok(None);
    };
    let Some(start) = mapped.original_boundary(candidate.start) else {
        return Err(validation(
            format!("/engine/shards/{entity}/mapped_literal/start"),
            "mapped literal start is outside the offset map",
        ));
    };
    let Some(end) = mapped.original_boundary(candidate.end) else {
        return Err(validation(
            format!("/engine/shards/{entity}/mapped_literal/end"),
            "mapped literal end is outside the offset map",
        ));
    };
    Ok(Some(LayerCandidate {
        start,
        end,
        ..candidate
    }))
}

fn next_literal_candidate_with_mapping(
    entity: &str,
    layer: Option<&LiteralMatcherLayer>,
    haystack: &[u8],
    haystack_text: &str,
    mapped: Option<&MappedHaystack>,
    cursor: usize,
) -> Result<Option<LayerCandidate>> {
    match mapped {
        Some(mapped) => next_mapped_literal_candidate(entity, layer, mapped, cursor),
        None => next_literal_candidate(entity, layer, haystack, haystack_text, cursor),
    }
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
    if !layer.requires_left_unicode_word_boundary {
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
    scan_slot: usize,
) -> Result<Option<LayerCandidate>> {
    let Some(layer) = layer else {
        return Ok(None);
    };
    let mut cache = layer.regex.cache(scan_slot);
    let input = Input::new(haystack).span(cursor..haystack.len());
    let Some(raw_match) = layer.regex.regex.search_with(&mut cache, &input) else {
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

fn scan_regex_layers_leftmost(
    entity: &str,
    layers: &[RegexMatcherLayer],
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
    scan_slot: usize,
) -> Result<()> {
    if layers.is_empty() {
        return Err(validation(
            format!("/engine/shards/{entity}/regex_layers"),
            "bounded regex matcher has no physical layers",
        ));
    }
    let mut cursor = 0;
    let mut candidates = layers
        .iter()
        .map(|layer| next_regex_candidate(entity, Some(layer), haystack, cursor, scan_slot))
        .collect::<Result<Vec<_>>>()?;

    loop {
        let Some(winner) = candidates
            .iter()
            .flatten()
            .copied()
            .min_by_key(|candidate| (candidate.start, candidate.pattern_order))
        else {
            break;
        };
        push_utf8_match(
            buffer,
            haystack,
            winner.detector_index,
            winner.start as u64,
            winner.end as u64,
        )?;
        cursor = winner.end;

        for (layer, candidate) in layers.iter().zip(&mut candidates) {
            if candidate_precedes_cursor(*candidate, cursor) {
                *candidate =
                    next_regex_candidate(entity, Some(layer), haystack, cursor, scan_slot)?;
            }
        }
    }
    Ok(())
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
    regex: &CachedRegex,
    local_to_detector: &[u32],
    haystack: &[u8],
    buffer: &mut NativeMatchBuffer,
    scan_slot: usize,
) -> Result<()> {
    let mut cache = regex.cache(scan_slot);
    let mut searcher = Searcher::new(Input::new(haystack));
    while let Some(raw_match) =
        searcher.advance(|input| Ok::<_, MatchError>(regex.regex.search_with(&mut cache, input)))
    {
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
    scan_slot: usize,
) -> Result<()> {
    let mut cache = matcher.regex.cache(scan_slot);
    let mut searcher = Searcher::new(Input::new(haystack));
    while let Some(raw_match) = searcher
        .advance(|input| Ok::<_, MatchError>(matcher.regex.regex.search_with(&mut cache, input)))
    {
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
                .cache_capacity(INTERNAL_MODE_HYBRID_CACHE_CAPACITY),
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
                .cache_capacity(INTERNAL_MODE_HYBRID_CACHE_CAPACITY),
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
                .which_captures(WhichCaptures::Implicit)
                .onepass(false)
                .backtrack(false)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT))
                .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                .hybrid_cache_capacity(INTERNAL_MODE_HYBRID_CACHE_CAPACITY)
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
        regex: CachedRegex::new(regex),
        local_to_detector,
    })
}

fn compile_entity_independent(
    canonical: &CanonicalBank,
) -> Result<(Vec<MatcherShard>, RegexResourceProfile)> {
    let mut shards = Vec::with_capacity(canonical.entities.len());
    let mut next_detector_index = 0u32;
    let mut regex_budget = RegexResourceBudget::default();
    for entity in &canonical.entities {
        regex_budget.start_entity();
        let mut patterns = Vec::with_capacity(entity.patterns.len());
        let mut literal_patterns = Vec::with_capacity(entity.patterns.len());
        let mut normalized_whitespace_patterns = Vec::with_capacity(entity.patterns.len());
        let mut local_to_detector = Vec::with_capacity(entity.patterns.len());
        for (pattern_index, pattern) in entity.patterns.iter().enumerate() {
            let hir = parse_pattern_with_flags(
                &entity.name,
                pattern_index,
                &pattern.regex,
                &pattern.flags,
            )?;
            let literal = layer_literal_pattern(pattern, &hir);
            normalized_whitespace_patterns.push(
                literal
                    .is_none()
                    .then(|| normalized_whitespace_literal_pattern(pattern, &hir))
                    .flatten(),
            );
            literal_patterns.push(literal);
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
            .zip(&normalized_whitespace_patterns)
            .filter(|(literal, normalized)| literal.is_some() || normalized.is_some())
            .count();
        let first_literal_case = literal_patterns
            .iter()
            .zip(&normalized_whitespace_patterns)
            .find_map(|(literal, normalized)| literal.as_ref().or(normalized.as_ref()))
            .map(|literal| literal.case_insensitive);

        let shard = if !all_patterns_non_empty {
            let regex = compile_entity_regex(&entity.name, &patterns)?;
            regex_budget.record(
                &entity.name,
                &regex,
                &patterns,
                ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
            )?;
            MatcherShard::Regex(RegexMatcherShard {
                entity: entity.name.clone(),
                matcher: RegexShardMatcher::Monolithic {
                    regex: CachedRegex::new(regex),
                    local_to_detector,
                },
            })
        } else if literal_count == 0 {
            let pattern_orders = (0..patterns.len()).collect::<Vec<_>>();
            MatcherShard::Regex(RegexMatcherShard {
                entity: entity.name.clone(),
                matcher: RegexShardMatcher::Bounded {
                    layers: compile_bounded_regex_layers(
                        &entity.name,
                        &patterns,
                        &local_to_detector,
                        &pattern_orders,
                        &mut regex_budget,
                    )?,
                },
            })
        } else if literal_count == patterns.len()
            && normalized_whitespace_patterns.iter().all(Option::is_none)
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
            )?)
        } else {
            MatcherShard::Layered(compile_layered_shard(
                &entity.name,
                patterns,
                literal_patterns,
                normalized_whitespace_patterns,
                local_to_detector,
                &mut regex_budget,
            )?)
        };

        shards.push(shard);
    }
    Ok((shards, regex_budget.profile()))
}

fn compile_layered_shard(
    entity_name: &str,
    patterns: Vec<Hir>,
    literal_patterns: Vec<Option<SimpleLiteralPattern>>,
    normalized_whitespace_patterns: Vec<Option<SimpleLiteralPattern>>,
    local_to_detector: Vec<u32>,
    regex_budget: &mut RegexResourceBudget,
) -> Result<LayeredMatcherShard> {
    let mut case_sensitive_patterns = Vec::new();
    let mut case_insensitive_patterns = Vec::new();
    let mut normalized_case_sensitive_patterns = Vec::new();
    let mut normalized_case_insensitive_patterns = Vec::new();
    let mut residual_patterns = Vec::new();
    let mut residual_detectors = Vec::new();
    let mut residual_orders = Vec::new();
    for (pattern_order, (((hir, literal), normalized), detector_index)) in patterns
        .into_iter()
        .zip(literal_patterns)
        .zip(normalized_whitespace_patterns)
        .zip(local_to_detector.iter().copied())
        .enumerate()
    {
        match (literal, normalized) {
            (Some(literal), None) if literal.case_insensitive => {
                case_insensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            (Some(literal), None) => {
                case_sensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            (None, Some(literal)) if literal.case_insensitive => {
                normalized_case_insensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            (None, Some(literal)) => {
                normalized_case_sensitive_patterns.push(LayerLiteralPattern {
                    literal,
                    detector_index,
                    pattern_order,
                });
            }
            (None, None) => {
                residual_patterns.push(hir);
                residual_detectors.push(detector_index);
                residual_orders.push(pattern_order);
            }
            (Some(_), Some(_)) => unreachable!("literal classifiers are mutually exclusive"),
        }
    }

    Ok(LayeredMatcherShard {
        entity: entity_name.to_string(),
        case_sensitive_literals: compile_literal_layers(
            entity_name,
            case_sensitive_patterns,
            false,
        )?,
        ascii_case_insensitive_literals: compile_literal_layers(
            entity_name,
            case_insensitive_patterns,
            true,
        )?,
        normalized_case_sensitive_literals: compile_literal_layers(
            entity_name,
            normalized_case_sensitive_patterns,
            false,
        )?,
        normalized_ascii_case_insensitive_literals: compile_literal_layers(
            entity_name,
            normalized_case_insensitive_patterns,
            true,
        )?,
        residual_regex_layers: if residual_patterns.is_empty() {
            Vec::new()
        } else {
            compile_bounded_regex_layers(
                entity_name,
                &residual_patterns,
                &residual_detectors,
                &residual_orders,
                regex_budget,
            )?
        },
    })
}

fn compile_literal_layers(
    entity_name: &str,
    patterns: Vec<LayerLiteralPattern>,
    case_insensitive: bool,
) -> Result<LiteralMatcherLayers> {
    let mut without_left_boundary = Vec::new();
    let mut with_left_boundary = Vec::new();
    for pattern in patterns {
        if pattern.literal.left_unicode_word_boundary {
            with_left_boundary.push(pattern);
        } else {
            without_left_boundary.push(pattern);
        }
    }
    Ok(LiteralMatcherLayers {
        without_left_boundary: compile_literal_layer(
            entity_name,
            without_left_boundary,
            case_insensitive,
            false,
        )?,
        with_left_boundary: compile_literal_layer(
            entity_name,
            with_left_boundary,
            case_insensitive,
            true,
        )?,
    })
}

fn compile_literal_layer(
    entity_name: &str,
    patterns: Vec<LayerLiteralPattern>,
    case_insensitive: bool,
    requires_left_unicode_word_boundary: bool,
) -> Result<Option<LiteralMatcherLayer>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    debug_assert!(patterns.iter().all(|pattern| {
        pattern.literal.left_unicode_word_boundary == requires_left_unicode_word_boundary
    }));
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
        requires_left_unicode_word_boundary,
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
    build_entity_regex(patterns)
        .map_err(|error| entity_regex_build_error(entity_name, pattern_orders, error))
}

fn build_entity_regex(patterns: &[Hir]) -> std::result::Result<Regex, RegexBuildError> {
    build_entity_regex_with_cache(patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
}

fn build_entity_regex_with_cache(
    patterns: &[Hir],
    hybrid_cache_capacity: usize,
) -> std::result::Result<Regex, RegexBuildError> {
    Regex::builder()
        .configure(
            Regex::config()
                .match_kind(RegexMatchKind::LeftmostFirst)
                .which_captures(WhichCaptures::Implicit)
                .onepass(false)
                .backtrack(false)
                .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT))
                .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                .hybrid_cache_capacity(hybrid_cache_capacity)
                .dfa_size_limit(Some(ENTITY_INDEPENDENT_DFA_SIZE_LIMIT))
                .dfa_state_limit(Some(ENTITY_INDEPENDENT_DFA_STATE_LIMIT)),
        )
        .build_many_from_hir(patterns)
}

fn entity_regex_build_error(
    entity_name: &str,
    pattern_orders: Option<&[usize]>,
    error: RegexBuildError,
) -> crate::error::BankError {
    let path = match error.pattern() {
        Some(pattern_id) => {
            let local_index = pattern_id.as_usize();
            let pattern_index = pattern_orders
                .and_then(|orders| orders.get(local_index))
                .copied()
                .unwrap_or(local_index);
            pattern_path_by_index(entity_name, pattern_index)
        }
        None => pattern_orders
            .and_then(|orders| (orders.len() == 1).then(|| orders[0]))
            .map(|pattern_index| pattern_path_by_index(entity_name, pattern_index))
            .unwrap_or_else(|| format!("/entities/{entity_name}/patterns")),
    };
    validation(
        path,
        format!(
            "could not compile entity-independent regex matcher for entity {entity_name:?}: {error}"
        ),
    )
}

fn compile_bounded_regex_layers(
    entity_name: &str,
    patterns: &[Hir],
    local_to_detector: &[u32],
    pattern_orders: &[usize],
    regex_budget: &mut RegexResourceBudget,
) -> Result<Vec<RegexMatcherLayer>> {
    if patterns.len() != local_to_detector.len()
        || patterns.len() != pattern_orders.len()
        || patterns.is_empty()
    {
        return Err(validation(
            format!("/engine/shards/{entity_name}/regex_layers"),
            "bounded regex pattern and detector maps are inconsistent",
        ));
    }
    if patterns
        .iter()
        .any(|hir| !matches!(hir.properties().minimum_len(), Some(minimum) if minimum > 0))
    {
        return Err(validation(
            format!("/engine/shards/{entity_name}/regex_layers"),
            "bounded regex shards require every pattern to advance the shared cursor",
        ));
    }
    let mut layers = Vec::new();
    let mut start = 0;
    while start < patterns.len() {
        let mut end = start;
        let mut minimum_bytes = 0usize;
        while end < patterns.len() && end - start < MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER {
            let pattern_minimum = patterns[end]
                .properties()
                .minimum_len()
                .expect("bounded regex layers reject unknown minimum lengths");
            if end > start
                && minimum_bytes.saturating_add(pattern_minimum)
                    > BOUNDED_REGEX_INITIAL_MAX_MINIMUM_BYTES
            {
                break;
            }
            minimum_bytes = minimum_bytes.saturating_add(pattern_minimum);
            end += 1;
        }
        compile_bounded_regex_shard(
            entity_name,
            &patterns[start..end],
            &local_to_detector[start..end],
            &pattern_orders[start..end],
            regex_budget,
            &mut layers,
        )?;
        start = end;
    }
    Ok(layers)
}

fn compile_bounded_regex_shard(
    entity_name: &str,
    patterns: &[Hir],
    local_to_detector: &[u32],
    pattern_orders: &[usize],
    regex_budget: &mut RegexResourceBudget,
    layers: &mut Vec<RegexMatcherLayer>,
) -> Result<()> {
    match build_entity_regex_with_cache(patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY) {
        Ok(regex) => {
            let record = regex_budget.record(
                entity_name,
                &regex,
                patterns,
                ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
            );
            if let Err(error) = record {
                if patterns.len() == 1 {
                    return Err(error);
                }
                regex_budget.resource_limit_bisections = regex_budget
                    .resource_limit_bisections
                    .checked_add(1)
                    .ok_or_else(|| {
                        memory(
                            format!("/engine/shards/{entity_name}/regex_resource_budget"),
                            "compiled regex resource-limit bisection count overflowed",
                        )
                    })?;
                let middle = patterns.len() / 2;
                compile_bounded_regex_shard(
                    entity_name,
                    &patterns[..middle],
                    &local_to_detector[..middle],
                    &pattern_orders[..middle],
                    regex_budget,
                    layers,
                )?;
                return compile_bounded_regex_shard(
                    entity_name,
                    &patterns[middle..],
                    &local_to_detector[middle..],
                    &pattern_orders[middle..],
                    regex_budget,
                    layers,
                );
            }
            layers.push(RegexMatcherLayer {
                regex: CachedRegex::new(regex),
                local_to_detector: local_to_detector.to_vec(),
                local_to_pattern_order: pattern_orders.to_vec(),
            });
            Ok(())
        }
        Err(error) if error.size_limit().is_some() && patterns.len() > 1 => {
            regex_budget.size_limit_bisections = regex_budget
                .size_limit_bisections
                .checked_add(1)
                .ok_or_else(|| {
                    memory(
                        format!("/engine/shards/{entity_name}/regex_resource_budget"),
                        "compiled regex size-limit bisection count overflowed",
                    )
                })?;
            let middle = patterns.len() / 2;
            compile_bounded_regex_shard(
                entity_name,
                &patterns[..middle],
                &local_to_detector[..middle],
                &pattern_orders[..middle],
                regex_budget,
                layers,
            )?;
            compile_bounded_regex_shard(
                entity_name,
                &patterns[middle..],
                &local_to_detector[middle..],
                &pattern_orders[middle..],
                regex_budget,
                layers,
            )
        }
        Err(error) => Err(entity_regex_build_error(
            entity_name,
            Some(pattern_orders),
            error,
        )),
    }
}

fn compile_literal_shard(
    entity_name: &str,
    literal_patterns: Vec<String>,
    case_insensitive: bool,
    local_to_detector: Vec<u32>,
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
    let literal = simple_literal_pattern(pattern)
        .or_else(|| bounded_simple_literal_pattern(pattern, hir))
        .or_else(|| exact_hir_literal_pattern(hir))?;

    // A right-boundary-only literal may have to reject every overlapping
    // occurrence before the one ending at the next word boundary. A
    // leftmost-first Aho-Corasick layer cannot advance past those starts
    // without changing semantics, and rechecking a long prefix at each one
    // makes a word-length run quadratic. Keep this shape in the linear-time
    // residual regex layer. Left-bounded and fully unbounded literals retain
    // the optimized Aho-Corasick paths.
    (!literal.right_unicode_word_boundary || literal.left_unicode_word_boundary).then_some(literal)
}

fn normalized_whitespace_literal_pattern(
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
    let case_insensitive = match pattern.flags.as_slice() {
        [] => false,
        [flag] if flag == "IGNORECASE" => true,
        _ => return None,
    };
    let raw_parts = regex.split(r"\s+").collect::<Vec<_>>();
    if raw_parts.len() < 2 || raw_parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    let value = raw_parts
        .into_iter()
        .map(unescape_simple_literal_regex)
        .collect::<Option<Vec<_>>>()?
        .join(" ");
    if value.is_empty() || (case_insensitive && !value.is_ascii()) {
        return None;
    }
    Some(SimpleLiteralPattern {
        value,
        case_insensitive,
        left_unicode_word_boundary: raw_left_boundary,
        right_unicode_word_boundary: raw_right_boundary,
    })
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
        NativeEngine::compile(
            &canonical_for_patterns(patterns),
            MatchMode::EntityIndependent,
        )
        .unwrap()
    }

    fn canonical_for_patterns(patterns: Vec<CanonicalPattern>) -> CanonicalBank {
        CanonicalBank {
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
        }
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
        let regex = CachedRegex::new(compile_entity_regex("entity", &hirs).unwrap());
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
            0,
        )
        .unwrap();
        buffer.sort();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    fn unbounded_monolithic_raw_matches(
        patterns: &[CanonicalPattern],
        text: &str,
    ) -> Vec<(u32, u64, u64)> {
        let hirs = patterns
            .iter()
            .enumerate()
            .map(|(pattern_index, pattern)| {
                parse_pattern_with_flags("entity", pattern_index, &pattern.regex, &pattern.flags)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let regex = Regex::builder()
            .configure(
                Regex::config()
                    .match_kind(RegexMatchKind::LeftmostFirst)
                    .which_captures(WhichCaptures::Implicit)
                    .onepass(false)
                    .backtrack(false)
                    .nfa_size_limit(None)
                    .onepass_size_limit(Some(ENTITY_INDEPENDENT_ONEPASS_SIZE_LIMIT))
                    .hybrid_cache_capacity(INTERNAL_MODE_HYBRID_CACHE_CAPACITY)
                    .dfa_size_limit(Some(ENTITY_INDEPENDENT_DFA_SIZE_LIMIT))
                    .dfa_state_limit(Some(ENTITY_INDEPENDENT_DFA_STATE_LIMIT)),
            )
            .build_many_from_hir(&hirs)
            .unwrap();
        let regex = CachedRegex::new(regex);
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
            0,
        )
        .unwrap();
        buffer.sort();
        (0..buffer.len())
            .map(|index| buffer.get(index).unwrap().as_tuple())
            .collect()
    }

    fn assert_layered_matches_monolithic(patterns: Vec<CanonicalPattern>, text: &str) {
        let expected = monolithic_raw_matches(&patterns, text);
        let engine = engine_for_patterns(patterns.clone());
        assert!(matches!(
            engine.shards.as_slice(),
            [MatcherShard::Layered(_)]
        ));
        assert_eq!(engine_raw_matches(&engine, text), expected);
    }

    fn large_regex_pattern_fixture(
        first: CanonicalPattern,
        second_half: CanonicalPattern,
    ) -> Vec<CanonicalPattern> {
        const PATTERN_COUNT: usize = 160;
        const SECOND_HALF_INDEX: usize = PATTERN_COUNT / 2;
        let padding = "a".repeat(112);
        let mut patterns = vec![first];
        patterns.extend((1..SECOND_HALF_INDEX).map(|index| {
            canonical_pattern(
                &format!(r"(?:NERB_UNUSED_{index:08}{padding})[aA]"),
                &["IGNORECASE"],
            )
        }));
        patterns.push(second_half);
        patterns.extend(((SECOND_HALF_INDEX + 1)..PATTERN_COUNT).map(|index| {
            canonical_pattern(
                &format!(r"(?:NERB_UNUSED_{index:08}{padding})[aA]"),
                &["IGNORECASE"],
            )
        }));
        patterns
    }

    fn regex_layer_pattern_orders(layers: &[RegexMatcherLayer]) -> Vec<usize> {
        layers
            .iter()
            .flat_map(|layer| layer.local_to_pattern_order.iter().copied())
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
    fn literal_shard_maps_only_regex_simple_unicode_folds() {
        let patterns = vec![
            canonical_pattern("k", &["IGNORECASE"]),
            canonical_pattern("s", &["IGNORECASE"]),
            canonical_pattern("i", &["IGNORECASE"]),
        ];
        let engine = engine_for_patterns(patterns.clone());

        let [MatcherShard::Literal(_)] = engine.shards.as_slice() else {
            panic!("case-insensitive exact literals should use a literal shard");
        };
        for text in ["K S I", "K ſ ı", "Kſi"] {
            assert_eq!(
                engine_raw_matches(&engine, text),
                monolithic_raw_matches(&patterns, text)
            );
        }
        assert!(!engine_raw_matches(&engine, "ı")
            .iter()
            .any(|&(detector, _, _)| detector == 2));
    }

    #[test]
    fn mapped_unicode_fold_and_whitespace_tables_match_monolithic_exhaustively() {
        let fold_patterns = ('a'..='z')
            .map(|character| canonical_pattern(&character.to_string(), &["IGNORECASE"]))
            .collect::<Vec<_>>();
        let mut all_scalars = String::new();
        let mut whitespace_segments = String::new();
        for codepoint in 0..=0x10FFFF {
            let Some(character) = char::from_u32(codepoint) else {
                continue;
            };
            all_scalars.push(character);
            all_scalars.push('|');
            whitespace_segments.push('a');
            whitespace_segments.push(character);
            whitespace_segments.push('b');
            whitespace_segments.push('|');
        }
        let fold_engine = engine_for_patterns(fold_patterns.clone());
        assert_eq!(
            engine_raw_matches(&fold_engine, &all_scalars),
            monolithic_raw_matches(&fold_patterns, &all_scalars)
        );

        let whitespace_patterns = vec![canonical_pattern(r"\b(?:a\s+b)\b", &[])];
        let whitespace_engine = engine_for_patterns(whitespace_patterns.clone());
        let [MatcherShard::Layered(whitespace_shard)] = whitespace_engine.shards.as_slice() else {
            panic!("the exhaustive whitespace fixture must exercise the mapped Aho layer");
        };
        assert_eq!(
            whitespace_shard
                .normalized_case_sensitive_literals
                .with_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .len(),
            1
        );
        assert!(whitespace_shard.residual_regex_layers.is_empty());
        assert_eq!(
            engine_raw_matches(&whitespace_engine, &whitespace_segments),
            monolithic_raw_matches(&whitespace_patterns, &whitespace_segments)
        );
    }

    #[test]
    fn large_case_insensitive_literal_entity_needs_only_true_residual_regex_layers() {
        const LITERAL_COUNT: usize = 1_500;
        const LITERAL_LENGTH: usize = 128;
        let padding = "a".repeat(LITERAL_LENGTH - 16);
        let mut patterns = (0..LITERAL_COUNT)
            .map(|index| canonical_pattern(&format!("contact{index:08}{padding}"), &["IGNORECASE"]))
            .collect::<Vec<_>>();
        patterns.push(canonical_pattern(r"\d+", &[]));

        // Exact ASCII-CI literals fit the mapped Aho-Corasick layer. Only the
        // true residual regex consumes the regex resource budget.
        let literal_layers = compile_literal_layers(
            "entity",
            patterns[..LITERAL_COUNT]
                .iter()
                .enumerate()
                .map(|(pattern_order, pattern)| LayerLiteralPattern {
                    literal: simple_literal_pattern(pattern)
                        .expect("the fixture must remain an optimized exact literal"),
                    detector_index: u32::try_from(pattern_order).unwrap(),
                    pattern_order,
                })
                .collect(),
            true,
        )
        .expect("the literal layer should compile independently");
        assert_eq!(
            literal_layers
                .without_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .len(),
            LITERAL_COUNT
        );
        assert!(literal_layers.with_left_boundary.is_none());
        let residual = parse_pattern_with_flags(
            "entity",
            LITERAL_COUNT,
            &patterns[LITERAL_COUNT].regex,
            &patterns[LITERAL_COUNT].flags,
        )
        .unwrap();
        compile_entity_regex_with_pattern_orders("entity", &[residual], Some(&[LITERAL_COUNT]))
            .expect("the residual regex layer should compile independently");

        let canonical = canonical_for_patterns(patterns);
        let engine = NativeEngine::compile(&canonical, MatchMode::EntityIndependent)
            .expect("mapped literals and the residual should compile");
        let replayed = NativeEngine::compile(&canonical, MatchMode::EntityIndependent)
            .expect("mapped literals and the residual should compile deterministically");
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("the mixed fixture should use a layered matcher");
        };
        assert_eq!(shard.residual_regex_layers.len(), 1);
        assert_eq!(
            engine.regex_resource_profile(),
            replayed.regex_resource_profile()
        );
        assert_eq!(
            engine
                .regex_resource_profile()
                .unwrap()
                .physical_regex_layers,
            1
        );
        let text = format!("CONTACT00000042{padding} 123");
        let matches = engine_raw_matches(&engine, &text);
        assert!(matches.iter().any(|&(detector, _, _)| detector == 42));
        assert!(matches
            .iter()
            .any(|&(detector, _, _)| detector == LITERAL_COUNT as u32));
    }

    #[test]
    fn bounded_regex_singleton_size_error_preserves_original_pattern_index() {
        let pattern = canonical_pattern(r"[a-z]{1000000}", &["IGNORECASE"]);
        let hir = parse_pattern_with_flags("entity", 37, &pattern.regex, &pattern.flags).unwrap();
        let mut budget = RegexResourceBudget::default();
        let error =
            compile_bounded_regex_layers("entity", &[hir], &[11], &[37], &mut budget).unwrap_err();

        assert!(error.to_string().contains("/entities/entity/patterns/37"));
        assert!(error
            .to_string()
            .contains("could not compile entity-independent regex matcher"));
    }

    #[test]
    fn pikevm_fixed_cache_projection_is_accounted_above_hybrid_capacity() {
        const PATTERN_COUNT: usize = 8;
        let patterns = (0..PATTERN_COUNT)
            .map(|index| {
                let pattern = canonical_pattern(
                    &format!(
                        r"(?:\p{{Letter}}|\p{{Number}}){{{minimum},{maximum}}}",
                        minimum = index + 1,
                        maximum = index + 2,
                    ),
                    &["IGNORECASE"],
                );
                parse_pattern_with_flags("cache-shape", index, &pattern.regex, &pattern.flags)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let regex =
            build_entity_regex_with_cache(&patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
                .unwrap();
        let mut budget = RegexResourceBudget::default();
        budget.start_entity();
        budget
            .record(
                "cache-shape",
                &regex,
                &patterns,
                ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
            )
            .unwrap();
        let profile = budget.profile();

        assert_eq!(profile.physical_regex_layers, 1);
        assert!(profile.eager_cache_bytes_per_scan > 0);
        assert!(
            profile.pikevm_cache_projection_bytes_per_scan
                > ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
            "complex regex PikeVM fixed cache was only {} bytes",
            profile.pikevm_cache_projection_bytes_per_scan
        );
        assert!(profile.pikevm_stack_growth_allowance_bytes_per_scan > 0);
        assert_eq!(
            profile.lazy_dfa_growth_allowance_bytes_per_scan,
            ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY * MAX_LAZY_DFA_CACHES_PER_META_REGEX
        );
        assert_eq!(
            profile.regex_cache_allowance_bytes,
            (profile.eager_cache_bytes_per_scan
                + profile.pikevm_cache_projection_bytes_per_scan
                + profile.pikevm_stack_growth_allowance_bytes_per_scan
                + profile.lazy_dfa_growth_allowance_bytes_per_scan)
                * MAX_CONCURRENT_SCANS_PER_ENGINE
        );
    }

    #[test]
    fn pikevm_fixed_cache_projection_bounds_actual_cache_and_fails_closed_on_overflow() {
        use regex_automata::nfa::thompson::pikevm::PikeVM;

        let fixtures = [
            vec![parse_pattern_with_flags("projection", 0, r"\d+", &[]).unwrap()],
            (0..8)
                .map(|index| {
                    parse_pattern_with_flags(
                        "projection",
                        index,
                        &format!(
                            r"(?:\p{{Letter}}|\p{{Number}}){{{minimum},{maximum}}}",
                            minimum = index + 1,
                            maximum = index + 2,
                        ),
                        &["IGNORECASE".to_string()],
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>(),
        ];

        for patterns in fixtures {
            let nfa = thompson::NFA::compiler()
                .configure(
                    thompson::Config::new()
                        .which_captures(WhichCaptures::Implicit)
                        .nfa_size_limit(Some(ENTITY_INDEPENDENT_NFA_SIZE_LIMIT)),
                )
                .build_many_from_hir(&patterns)
                .unwrap();
            let projection = project_pikevm_cache_bytes(&nfa).unwrap();
            let actual = PikeVM::new_from_nfa(nfa)
                .unwrap()
                .create_cache()
                .memory_usage();
            assert!(
                projection >= actual,
                "PikeVM cache projection {projection} did not bound {actual} actual bytes"
            );
        }

        assert_eq!(
            project_pikevm_cache_bytes_from_counts(usize::MAX, usize::MAX, usize::MAX),
            None
        );
        assert_eq!(
            project_pikevm_cache_bytes_from_counts(1, 1, usize::MAX),
            None
        );
    }

    #[test]
    fn bounded_regex_layer_envelope_partitions_deterministically() {
        let canonical_patterns = large_regex_pattern_fixture(
            canonical_pattern(r"(?:NERB_FIRST)[aA]", &["IGNORECASE"]),
            canonical_pattern(r"(?:NERB_MIDDLE)[aA]", &["IGNORECASE"]),
        );
        let patterns = canonical_patterns
            .iter()
            .enumerate()
            .map(|(index, pattern)| {
                parse_pattern_with_flags("entity", index, &pattern.regex, &pattern.flags).unwrap()
            })
            .collect::<Vec<_>>();
        let detectors = (0..patterns.len())
            .map(|index| u32::try_from(index).unwrap())
            .collect::<Vec<_>>();
        let orders = (0..patterns.len()).collect::<Vec<_>>();

        let compile = || {
            let mut budget = RegexResourceBudget::default();
            budget.start_entity();
            let layers =
                compile_bounded_regex_layers("entity", &patterns, &detectors, &orders, &mut budget)
                    .unwrap();
            (budget.profile(), layers)
        };
        let (first_profile, first_layers) = compile();
        let (second_profile, second_layers) = compile();
        let first_partition = first_layers
            .iter()
            .map(|layer| layer.local_to_pattern_order.len())
            .collect::<Vec<_>>();
        let second_partition = second_layers
            .iter()
            .map(|layer| layer.local_to_pattern_order.len())
            .collect::<Vec<_>>();

        assert_eq!(first_profile.size_limit_bisections, 0);
        assert_eq!(first_profile.resource_limit_bisections, 0);
        assert_eq!(
            first_profile.physical_regex_layers,
            (canonical_patterns.len() + MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER - 1)
                / MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER
        );
        assert!(first_partition
            .iter()
            .all(|&count| count <= MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER));
        assert_eq!(first_profile, second_profile);
        assert_eq!(first_partition, second_partition);
        assert_eq!(regex_layer_pattern_orders(&first_layers), orders);
    }

    #[test]
    fn resource_budget_bisection_succeeds_and_is_deterministic() {
        let canonical_patterns = large_regex_pattern_fixture(
            canonical_pattern(r"(?:NERB_FIRST)[aA]", &["IGNORECASE"]),
            canonical_pattern(r"(?:NERB_MIDDLE)[aA]", &["IGNORECASE"]),
        );
        let patterns = canonical_patterns
            .iter()
            .take(MAX_PATTERNS_PER_BOUNDED_REGEX_LAYER)
            .enumerate()
            .map(|(index, pattern)| {
                parse_pattern_with_flags("resource-split", index, &pattern.regex, &pattern.flags)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let detectors = (0..patterns.len())
            .map(|index| u32::try_from(index).unwrap())
            .collect::<Vec<_>>();
        let orders = (0..patterns.len()).collect::<Vec<_>>();
        let middle = patterns.len() / 2;

        let whole_regex =
            build_entity_regex_with_cache(&patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
                .unwrap();
        let mut whole_budget = RegexResourceBudget::default();
        whole_budget.start_entity();
        whole_budget
            .record(
                "resource-split",
                &whole_regex,
                &patterns,
                ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
            )
            .unwrap();
        let whole_profile = whole_budget.profile();
        let whole_bytes =
            whole_profile.compiled_regex_static_bytes + whole_profile.regex_cache_allowance_bytes;

        let mut split_budget = RegexResourceBudget::default();
        split_budget.start_entity();
        for half in [&patterns[..middle], &patterns[middle..]] {
            let regex =
                build_entity_regex_with_cache(half, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
                    .unwrap();
            split_budget
                .record(
                    "resource-split",
                    &regex,
                    half,
                    ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY,
                )
                .unwrap();
        }
        let split_profile = split_budget.profile();
        let split_bytes =
            split_profile.compiled_regex_static_bytes + split_profile.regex_cache_allowance_bytes;
        assert!(
            split_bytes < whole_bytes,
            "split regex accounting {split_bytes} should be below monolithic accounting {whole_bytes}"
        );
        let maximum_accounted_bytes = split_bytes + (whole_bytes.saturating_sub(split_bytes) / 2);
        assert!(maximum_accounted_bytes < whole_bytes);

        let compile = || {
            let mut budget = RegexResourceBudget {
                maximum_accounted_bytes,
                ..RegexResourceBudget::default()
            };
            budget.start_entity();
            let mut layers = Vec::new();
            compile_bounded_regex_shard(
                "resource-split",
                &patterns,
                &detectors,
                &orders,
                &mut budget,
                &mut layers,
            )
            .unwrap();
            (budget.profile(), layers)
        };
        let (first_profile, first_layers) = compile();
        let (second_profile, second_layers) = compile();
        let first_partition = first_layers
            .iter()
            .map(|layer| layer.local_to_pattern_order.len())
            .collect::<Vec<_>>();
        let second_partition = second_layers
            .iter()
            .map(|layer| layer.local_to_pattern_order.len())
            .collect::<Vec<_>>();

        assert_eq!(first_profile.resource_limit_bisections, 1);
        assert_eq!(first_profile.physical_regex_layers, 2);
        assert!(
            first_profile.compiled_regex_static_bytes + first_profile.regex_cache_allowance_bytes
                <= maximum_accounted_bytes
        );
        assert_eq!(first_profile, second_profile);
        assert_eq!(first_partition, vec![middle, patterns.len() - middle]);
        assert_eq!(first_partition, second_partition);
        assert_eq!(regex_layer_pattern_orders(&first_layers), orders);
    }

    #[test]
    fn aggregate_regex_resource_budget_fails_closed_before_layer_commit() {
        let pattern = canonical_pattern("bounded", &["IGNORECASE"]);
        let hir = parse_pattern_with_flags("capacity", 0, &pattern.regex, &pattern.flags).unwrap();
        let mut layer_exhausted = RegexResourceBudget {
            entity_layers: MAX_ENTITY_INDEPENDENT_REGEX_LAYERS_PER_ENTITY,
            ..RegexResourceBudget::default()
        };
        let layer_error = compile_bounded_regex_layers(
            "capacity",
            std::slice::from_ref(&hir),
            &[0],
            &[0],
            &mut layer_exhausted,
        )
        .unwrap_err();
        assert!(layer_error
            .to_string()
            .contains("/engine/shards/capacity/regex_resource_budget"));
        assert!(layer_error
            .to_string()
            .contains("compiled regex resource budget exceeded"));

        let mut bytes_exhausted = RegexResourceBudget {
            static_bytes: MAX_ENTITY_INDEPENDENT_REGEX_ACCOUNTED_BYTES,
            ..RegexResourceBudget::default()
        };
        let bytes_error =
            compile_bounded_regex_layers("capacity", &[hir], &[0], &[0], &mut bytes_exhausted)
                .unwrap_err();
        assert!(bytes_error
            .to_string()
            .contains("/engine/shards/capacity/regex_resource_budget"));
        assert!(bytes_error.to_string().contains("accounted bytes"));
    }

    #[test]
    fn bounded_regex_shards_preserve_global_ties_overlaps_order_and_folding() {
        let fixtures = [
            (
                large_regex_pattern_fixture(
                    canonical_pattern("(?i:tail)", &[]),
                    canonical_pattern(r"\p{Letter}+", &[]),
                ),
                "K head tail",
            ),
            (
                large_regex_pattern_fixture(
                    canonical_pattern("(?i:k)", &[]),
                    canonical_pattern(r"\p{Letter}+", &[]),
                ),
                "KX K",
            ),
            (
                large_regex_pattern_fixture(
                    canonical_pattern(r"(?i:\b(?:k|kx)\b)", &[]),
                    canonical_pattern(r"(?i:\b(?:kx)\b)", &[]),
                ),
                "(KX) K",
            ),
            (
                large_regex_pattern_fixture(
                    canonical_pattern("(?i:k)", &[]),
                    canonical_pattern("(?i:k)", &[]),
                ),
                "K K",
            ),
        ];

        for (patterns, text) in fixtures {
            let expected = unbounded_monolithic_raw_matches(&patterns, text);
            let engine = engine_for_patterns(patterns);
            let [MatcherShard::Regex(shard)] = engine.shards.as_slice() else {
                panic!("regex fixture should use bounded regex layers");
            };
            let RegexShardMatcher::Bounded { layers } = &shard.matcher else {
                panic!("nonempty regex fixture should use bounded layers");
            };
            assert!(layers.len() > 1);
            assert_eq!(engine_raw_matches(&engine, text), expected);
        }
    }

    #[test]
    fn sharded_regex_is_cross_entity_bounded_and_parallel_deterministic() {
        let first_entity_patterns = large_regex_pattern_fixture(
            canonical_pattern("(?i:k)", &[]),
            canonical_pattern("(?i:k)", &[]),
        );
        let second_detector = u32::try_from(first_entity_patterns.len()).unwrap();
        let canonical = CanonicalBank {
            schema: 1,
            defaults: CanonicalDefaults {
                engine: "rust-regex-meta".to_string(),
                unicode: true,
                case_insensitive: false,
                word_boundaries: false,
                normalization: "none".to_string(),
            },
            entities: vec![
                CanonicalEntity {
                    stable_id: "first".to_string(),
                    name: "first".to_string(),
                    patterns: first_entity_patterns,
                },
                CanonicalEntity {
                    stable_id: "second".to_string(),
                    name: "second".to_string(),
                    patterns: vec![canonical_pattern("(?i:k)", &[])],
                },
            ],
        };
        let engine = NativeEngine::compile(&canonical, MatchMode::EntityIndependent).unwrap();
        let expected = vec![
            (0, 0, 3),
            (second_detector, 0, 3),
            (0, 4, 7),
            (second_detector, 4, 7),
        ];

        for _ in 0..3 {
            assert_eq!(engine_raw_matches(&engine, "K K"), expected);
        }
        let mut bounded = NativeMatchBuffer::with_match_limit(2).unwrap();
        let error = engine
            .scan_bytes_into("K K".as_bytes(), &mut bounded)
            .unwrap_err();
        assert!(error.to_string().contains("configured match limit 2"));
        assert!(bounded.is_empty());

        std::thread::scope(|scope| {
            let handles = (0..4)
                .map(|_| scope.spawn(|| engine_raw_matches(&engine, "K K")))
                .collect::<Vec<_>>();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), expected);
            }
        });
    }

    #[test]
    fn normalized_whitespace_literals_preserve_mapped_casefold_arbitration() {
        const PATTERN_COUNT: usize = 1_500;
        let padding = "a".repeat(112);
        let patterns = (0..PATTERN_COUNT)
            .map(|index| {
                canonical_pattern(
                    &format!(r"\b(?:person{index:08}{padding}\s+alias)\b"),
                    &["IGNORECASE"],
                )
            })
            .collect::<Vec<_>>();
        let text = format!("K PERSON00000042{padding}   ALIAS PERSON00001234{padding} ALIAS");
        let expected = unbounded_monolithic_raw_matches(&patterns, &text);
        let engine = engine_for_patterns(patterns);
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("normalized whitespace fixture should use a layered matcher");
        };

        assert_eq!(
            shard
                .normalized_ascii_case_insensitive_literals
                .with_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .len(),
            PATTERN_COUNT
        );
        assert!(shard.residual_regex_layers.is_empty());
        assert_eq!(
            engine
                .regex_resource_profile()
                .unwrap()
                .physical_regex_layers,
            0
        );
        assert_eq!(engine_raw_matches(&engine, &text), expected);
    }

    #[test]
    fn regex_like_entity_stays_on_regex_shard() {
        let engine = engine_for_patterns(vec![canonical_pattern(r"\d+", &[])]);

        assert!(matches!(engine.shards.as_slice(), [MatcherShard::Regex(_)]));
        assert_eq!(engine_raw_matches(&engine, "123"), [(0, 0, 3)]);
        let profile = engine.regex_resource_profile().unwrap();
        assert_eq!(profile.physical_regex_layers, 1);
        assert!(profile.eager_cache_bytes_per_scan > 0);
        assert!(profile.pikevm_cache_projection_bytes_per_scan > 0);
        assert!(profile.pikevm_stack_growth_allowance_bytes_per_scan > 0);
        assert_eq!(
            profile.lazy_dfa_growth_allowance_bytes_per_scan,
            ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY * MAX_LAZY_DFA_CACHES_PER_META_REGEX
        );
        assert_eq!(
            profile.regex_cache_allowance_bytes,
            (profile.eager_cache_bytes_per_scan
                + profile.pikevm_cache_projection_bytes_per_scan
                + profile.pikevm_stack_growth_allowance_bytes_per_scan
                + profile.lazy_dfa_growth_allowance_bytes_per_scan)
                * MAX_CONCURRENT_SCANS_PER_ENGINE
        );
    }

    #[test]
    fn many_single_regex_entities_are_accounted_and_fail_at_the_aggregate_ceiling() {
        const ACCEPTED_ENTITY_COUNT: usize = 512;
        let defaults = CanonicalDefaults {
            engine: "rust-regex-meta".to_string(),
            unicode: true,
            case_insensitive: false,
            word_boundaries: false,
            normalization: "none".to_string(),
        };
        let nonempty = CanonicalBank {
            schema: 1,
            defaults: defaults.clone(),
            entities: (0..ACCEPTED_ENTITY_COUNT)
                .map(|index| CanonicalEntity {
                    stable_id: format!("entity-{index:04}"),
                    name: format!("entity-{index:04}"),
                    patterns: vec![canonical_pattern(&format!(r"ENTITY{index:04}[0-9]+"), &[])],
                })
                .collect(),
        };
        let nonempty_engine =
            NativeEngine::compile(&nonempty, MatchMode::EntityIndependent).unwrap();
        let nonempty_profile = nonempty_engine.regex_resource_profile().unwrap();
        assert_eq!(
            nonempty_profile.physical_regex_layers,
            ACCEPTED_ENTITY_COUNT
        );
        assert_eq!(
            nonempty_profile.lazy_dfa_growth_allowance_bytes_per_scan,
            ACCEPTED_ENTITY_COUNT
                * ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY
                * MAX_LAZY_DFA_CACHES_PER_META_REGEX
        );
        assert_eq!(
            nonempty_profile.regex_cache_allowance_bytes,
            (nonempty_profile.eager_cache_bytes_per_scan
                + nonempty_profile.pikevm_cache_projection_bytes_per_scan
                + nonempty_profile.pikevm_stack_growth_allowance_bytes_per_scan
                + nonempty_profile.lazy_dfa_growth_allowance_bytes_per_scan)
                * MAX_CONCURRENT_SCANS_PER_ENGINE
        );
        assert_eq!(
            engine_raw_matches(&nonempty_engine, "ENTITY0511123"),
            [(511, 0, 13)]
        );

        let possibly_empty = CanonicalBank {
            schema: 1,
            defaults: defaults.clone(),
            entities: (0..ACCEPTED_ENTITY_COUNT)
                .map(|index| CanonicalEntity {
                    stable_id: format!("empty-{index:04}"),
                    name: format!("empty-{index:04}"),
                    patterns: vec![canonical_pattern("z?", &[])],
                })
                .collect(),
        };
        let possibly_empty_engine =
            NativeEngine::compile(&possibly_empty, MatchMode::EntityIndependent).unwrap();
        let possibly_empty_profile = possibly_empty_engine.regex_resource_profile().unwrap();
        assert_eq!(
            possibly_empty_profile.physical_regex_layers,
            ACCEPTED_ENTITY_COUNT
        );
        assert_eq!(
            possibly_empty_profile.lazy_dfa_growth_allowance_bytes_per_scan,
            ACCEPTED_ENTITY_COUNT
                * ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY
                * MAX_LAZY_DFA_CACHES_PER_META_REGEX
        );
        assert_eq!(
            possibly_empty_profile.regex_cache_allowance_bytes,
            (possibly_empty_profile.eager_cache_bytes_per_scan
                + possibly_empty_profile.pikevm_cache_projection_bytes_per_scan
                + possibly_empty_profile.pikevm_stack_growth_allowance_bytes_per_scan
                + possibly_empty_profile.lazy_dfa_growth_allowance_bytes_per_scan)
                * MAX_CONCURRENT_SCANS_PER_ENGINE
        );
        assert_eq!(
            engine_raw_matches(&possibly_empty_engine, "").len(),
            ACCEPTED_ENTITY_COUNT
        );

        let exhausted = CanonicalBank {
            schema: 1,
            defaults,
            entities: (0..1_000)
                .map(|index| CanonicalEntity {
                    stable_id: format!("exhausted-{index:04}"),
                    name: format!("exhausted-{index:04}"),
                    patterns: vec![canonical_pattern(
                        &format!(r"EXHAUSTED{index:04}[0-9]+"),
                        &[],
                    )],
                })
                .collect(),
        };
        let error = NativeEngine::compile(&exhausted, MatchMode::EntityIndependent).unwrap_err();
        assert!(error.to_string().contains("regex resource budget exceeded"));
        assert!(error
            .to_string()
            .contains("PikeVM fixed cache projection bytes"));
        assert!(error.to_string().contains("lazy-DFA growth allowance"));
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
    fn layered_matcher_maps_unicode_simple_case_folding() {
        let patterns = vec![
            canonical_pattern("k", &["IGNORECASE"]),
            canonical_pattern(r"\p{Letter}+", &[]),
            canonical_pattern("done", &[]),
        ];
        let expected = monolithic_raw_matches(&patterns, "K done");
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed case-folding entity should use a layered matcher");
        };

        assert!(!shard.ascii_case_insensitive_literals.is_empty());
        assert_eq!(engine_raw_matches(&engine, "K done"), expected);
        assert_eq!(
            engine_raw_matches(&engine, "K K"),
            monolithic_raw_matches(&patterns, "K K")
        );
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
        let layer = shard
            .case_sensitive_literals
            .with_left_boundary
            .as_ref()
            .unwrap();
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
        let bounded_layer = shard
            .case_sensitive_literals
            .with_left_boundary
            .as_ref()
            .unwrap();
        let unbounded_layer = shard
            .case_sensitive_literals
            .without_left_boundary
            .as_ref()
            .unwrap();
        let residual_orders = regex_layer_pattern_orders(&shard.residual_regex_layers);
        let text = "tokenx";
        let bounded_lookup =
            indexed_valid_literal_at_start(bounded_layer, text.as_bytes(), text, 0);
        let unbounded_lookup =
            indexed_valid_literal_at_start(unbounded_layer, text.as_bytes(), text, 0);

        assert_eq!(bounded_layer.patterns.len(), 2_048);
        assert_eq!(unbounded_layer.patterns.len(), 1_024);
        assert_eq!(residual_orders.len(), 1_024);
        assert!(residual_orders
            .iter()
            .all(|pattern_order| pattern_order % 4 == 1));
        assert_eq!(bounded_layer.prefix_index.sorted_pattern_indices.len(), 2);
        assert_eq!(unbounded_layer.prefix_index.sorted_pattern_indices.len(), 1);
        assert!(bounded_lookup.terminal_candidates_examined <= 2);
        assert!(unbounded_lookup.terminal_candidates_examined <= 2);
        assert_eq!(bounded_lookup.candidate.unwrap().pattern_order, 2);
        assert_eq!(unbounded_lookup.candidate.unwrap().pattern_order, 3);
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
        let layer = shard
            .case_sensitive_literals
            .with_left_boundary
            .as_ref()
            .unwrap();
        let text = "aaaaaaaaaaaaaaaaa";

        assert!(layer.requires_left_unicode_word_boundary);
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
    fn unbounded_peer_cannot_disable_long_bounded_literal_skip() {
        let literal = "a".repeat(8_192);
        let patterns = vec![
            canonical_pattern(&format!(r"\b(?:{literal})\b"), &[]),
            canonical_pattern("needle", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed boundary signatures should use the layered matcher");
        };
        let bounded_layer = shard
            .case_sensitive_literals
            .with_left_boundary
            .as_ref()
            .unwrap();
        let unbounded_layer = shard
            .case_sensitive_literals
            .without_left_boundary
            .as_ref()
            .unwrap();
        let text = "a".repeat(literal.len() + 1);
        let lookup = indexed_valid_literal_at_start(bounded_layer, text.as_bytes(), &text, 0);

        assert_eq!(bounded_layer.patterns.len(), 1);
        assert_eq!(unbounded_layer.patterns.len(), 1);
        assert!(bounded_layer.requires_left_unicode_word_boundary);
        assert!(!unbounded_layer.requires_left_unicode_word_boundary);
        assert!(lookup.candidate.is_none());
        assert_eq!(lookup.prefix_bytes_examined, text.len());
        assert_eq!(
            next_literal_search_start(bounded_layer, &text, 0),
            text.len()
        );
        assert_eq!(
            engine_raw_matches(&engine, &text),
            monolithic_raw_matches(&patterns, &text)
        );
    }

    #[test]
    fn right_boundary_only_long_literal_stays_in_residual_regex_layer() {
        let literal = "a".repeat(512);
        let patterns = vec![
            canonical_pattern(&format!(r"(?:{literal})\b"), &[]),
            canonical_pattern("needle", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed right-boundary and unbounded literals should use the layered matcher");
        };
        let unbounded_layer = shard
            .case_sensitive_literals
            .without_left_boundary
            .as_ref()
            .unwrap();
        let residual_orders = regex_layer_pattern_orders(&shard.residual_regex_layers);

        assert_eq!(
            unbounded_layer
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [1]
        );
        assert_eq!(residual_orders, [0]);

        let text = "a".repeat(literal.len() * 2);
        let actual = engine_raw_matches(&engine, &text);
        assert_eq!(actual, monolithic_raw_matches(&patterns, &text));
        assert_eq!(actual, [(0, literal.len() as u64, text.len() as u64)]);
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
                .with_left_boundary
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
    fn normalized_whitespace_literal_uses_mapped_literal_layer() {
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
                .with_left_boundary
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
                .normalized_case_sensitive_literals
                .with_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [1]
        );
        assert!(shard.residual_regex_layers.is_empty());
        assert_eq!(
            engine_raw_matches(&engine, "alpha John   Doe"),
            monolithic_raw_matches(&patterns, "alpha John   Doe")
        );
        let unicode_whitespace = "x John\u{2003}\tDoe y";
        assert_eq!(
            engine_raw_matches(&engine, unicode_whitespace),
            monolithic_raw_matches(&patterns, unicode_whitespace)
        );
    }

    #[test]
    fn mapped_whitespace_layers_match_monolithic_across_offsets_priority_and_failures() {
        let patterns = vec![
            canonical_pattern(r"\b(?:John\s+Doe)\b", &["IGNORECASE"]),
            canonical_pattern(r"\b(?:John Doe)\b", &["IGNORECASE"]),
            canonical_pattern(r"(?i:\bJohn\s+Doe\b)", &[]),
            canonical_pattern(r"\b(?:Case\s+Name)\b", &[]),
            canonical_pattern(r"(?:\s+Leading)", &[]),
            canonical_pattern(r"(?:Trailing\s+)", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("mixed whitespace patterns should use layered matching");
        };
        assert_eq!(
            regex_layer_pattern_orders(&shard.residual_regex_layers),
            [2, 4, 5]
        );

        for text in [
            "John Doe Case Name",
            "John\tDoe Case\r\nName",
            "John\u{00A0}Doe Case\u{2003}Name",
            "é John   Doe      Case Name",
            "John Doe John\t\tDoe Trailing   END",
            "  Leading John Doe",
        ] {
            assert_eq!(
                engine_raw_matches(&engine, text),
                monolithic_raw_matches(&patterns, text),
                "mapped mismatch for {text:?}"
            );
        }

        let repeated = "John\tDoe John\u{2003}Doe";
        let mut bounded = NativeMatchBuffer::with_match_limit(1).unwrap();
        let error = engine
            .scan_bytes_into(repeated.as_bytes(), &mut bounded)
            .unwrap_err();
        assert!(error.to_string().contains("configured match limit 1"));
        assert!(bounded.is_empty());
        let expected = monolithic_raw_matches(&patterns, repeated);
        std::thread::scope(|scope| {
            let handles = (0..4)
                .map(|_| scope.spawn(|| engine_raw_matches(&engine, repeated)))
                .collect::<Vec<_>>();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), expected);
            }
        });

        // The first residual match ends after only the first tab, leaving the
        // shared cursor inside a whitespace run collapsed by the mapped Aho
        // layer. Refresh must reject that overlapping mapped candidate and
        // still discover the later normalized occurrence.
        let interior_patterns = vec![
            canonical_pattern(r"\AJohn[ \t]", &[]),
            canonical_pattern(r"John\s+Doe", &[]),
        ];
        let interior_text = "John\t\tDoe / John\t\tDoe";
        let interior_engine = engine_for_patterns(interior_patterns.clone());
        assert_eq!(
            engine_raw_matches(&interior_engine, interior_text),
            monolithic_raw_matches(&interior_patterns, interior_text)
        );
        assert_eq!(
            engine_raw_matches(&interior_engine, interior_text),
            [(0, 0, 5), (1, 12, 21)]
        );
    }

    #[test]
    fn max_document_mapped_layers_are_deterministic_at_cache_concurrency_budget() {
        let patterns = vec![
            canonical_pattern(r"\b(?:John\s+Doe)\b", &["IGNORECASE"]),
            canonical_pattern(r"\b(?:k)\b", &["IGNORECASE"]),
            canonical_pattern(r"\b(?:s)\b", &["IGNORECASE"]),
        ];
        let engine = engine_for_patterns(patterns);
        let mut document = vec![b'.'; MAX_SCAN_INPUT_BYTES];
        let fixtures = [
            (101, "John\u{2003}\tDoe"),
            (MAX_SCAN_INPUT_BYTES / 3, "K"),
            (MAX_SCAN_INPUT_BYTES * 2 / 3, "ſ"),
            (MAX_SCAN_INPUT_BYTES - 101, "JOHN  DOE"),
        ];
        for (offset, value) in fixtures {
            document[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        }
        let expected = vec![
            (0, 101, 112),
            (
                1,
                (MAX_SCAN_INPUT_BYTES / 3) as u64,
                (MAX_SCAN_INPUT_BYTES / 3 + 3) as u64,
            ),
            (
                2,
                (MAX_SCAN_INPUT_BYTES * 2 / 3) as u64,
                (MAX_SCAN_INPUT_BYTES * 2 / 3 + 2) as u64,
            ),
            (
                0,
                (MAX_SCAN_INPUT_BYTES - 101) as u64,
                (MAX_SCAN_INPUT_BYTES - 92) as u64,
            ),
        ];
        assert_eq!(
            engine_raw_matches(&engine, std::str::from_utf8(&document).unwrap()),
            expected
        );

        std::thread::scope(|scope| {
            let handles = (0..MAX_CONCURRENT_SCANS_PER_ENGINE)
                .map(|_| {
                    let document = &document;
                    let engine = &engine;
                    scope.spawn(move || {
                        engine_raw_matches(engine, std::str::from_utf8(document).unwrap())
                    })
                })
                .collect::<Vec<_>>();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), expected);
            }
        });
    }

    #[test]
    fn shared_engine_limiter_admits_eight_and_releases_all_sixteen_waiters() {
        use std::sync::{Arc, Barrier};

        let engine = engine_for_patterns(vec![canonical_pattern("literal", &[])]);
        let ready = Arc::new(Barrier::new(MAX_CONCURRENT_SCANS_PER_ENGINE + 1));
        let release = Arc::new(Barrier::new(MAX_CONCURRENT_SCANS_PER_ENGINE + 1));
        std::thread::scope(|scope| {
            let handles = (0..MAX_CONCURRENT_SCANS_PER_ENGINE * 2)
                .map(|_| {
                    let ready = Arc::clone(&ready);
                    let release = Arc::clone(&release);
                    let limiter = &engine.scan_limiter;
                    scope.spawn(move || {
                        let _permit = limiter.acquire();
                        ready.wait();
                        release.wait();
                    })
                })
                .collect::<Vec<_>>();

            for _ in 0..2 {
                ready.wait();
                assert_eq!(
                    engine.scan_limiter.observed_concurrency(),
                    (
                        MAX_CONCURRENT_SCANS_PER_ENGINE,
                        MAX_CONCURRENT_SCANS_PER_ENGINE
                    )
                );
                release.wait();
            }
            for handle in handles {
                handle.join().unwrap();
            }
        });
        assert_eq!(
            engine.scan_limiter.observed_concurrency(),
            (0, MAX_CONCURRENT_SCANS_PER_ENGINE)
        );
    }

    #[test]
    fn sixteen_concurrent_mapped_scans_complete_within_the_shared_engine_ceiling() {
        use std::sync::{Arc, Barrier};

        let engine = engine_for_patterns(vec![canonical_pattern("k", &["IGNORECASE"])]);
        let text = format!("K{}", ".".repeat(1024 * 1024));
        let start = Arc::new(Barrier::new(MAX_CONCURRENT_SCANS_PER_ENGINE * 2 + 1));
        std::thread::scope(|scope| {
            let handles = (0..MAX_CONCURRENT_SCANS_PER_ENGINE * 2)
                .map(|_| {
                    let start = Arc::clone(&start);
                    let engine = &engine;
                    let text = &text;
                    scope.spawn(move || {
                        start.wait();
                        engine_raw_matches(engine, text)
                    })
                })
                .collect::<Vec<_>>();
            start.wait();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), [(0, 0, 3)]);
            }
        });

        let (active, maximum_observed) = engine.scan_limiter.observed_concurrency();
        assert_eq!(active, 0);
        assert!((1..=MAX_CONCURRENT_SCANS_PER_ENGINE).contains(&maximum_observed));
    }

    #[test]
    fn scan_entry_waits_for_a_shared_engine_permit_and_then_progresses() {
        use std::sync::mpsc;
        use std::time::Duration;

        let engine = engine_for_patterns(vec![canonical_pattern("literal", &[])]);
        let permits = (0..MAX_CONCURRENT_SCANS_PER_ENGINE)
            .map(|_| engine.scan_limiter.acquire())
            .collect::<Vec<_>>();
        let mut slots = permits.iter().map(ScanPermit::slot).collect::<Vec<_>>();
        slots.sort_unstable();
        assert_eq!(
            slots,
            (0..MAX_CONCURRENT_SCANS_PER_ENGINE).collect::<Vec<_>>()
        );
        std::thread::scope(|scope| {
            let (started_tx, started_rx) = mpsc::channel();
            let (complete_tx, complete_rx) = mpsc::channel();
            let engine = &engine;
            let handle = scope.spawn(move || {
                started_tx.send(()).unwrap();
                let result = engine_raw_matches(engine, "literal");
                complete_tx.send(result).unwrap();
            });

            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(complete_rx.recv_timeout(Duration::from_millis(50)).is_err());
            drop(permits);
            assert_eq!(
                complete_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                [(0, 0, 7)]
            );
            handle.join().unwrap();
        });
    }

    #[test]
    fn poisoned_limiter_state_is_recovered_without_a_scan_panic() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let limiter = ScanLimiter::default();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _state = limiter.state.lock().unwrap();
            panic!("poison the limiter for the regression fixture");
        }));
        assert!(poisoned.is_err());

        let permit = limiter.acquire();
        assert_eq!(limiter.observed_concurrency(), (1, 1));
        drop(permit);
        assert_eq!(limiter.observed_concurrency(), (0, 1));
    }

    #[test]
    fn poisoned_explicit_regex_cache_is_reset_before_reuse() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let patterns = [parse_pattern_with_flags("cache", 0, r"[0-9]+", &[]).unwrap()];
        let other_patterns = [parse_pattern_with_flags("other", 0, r"[A-Z]+", &[]).unwrap()];
        let cached = CachedRegex::new(
            build_entity_regex_with_cache(&patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
                .unwrap(),
        );
        let other =
            build_entity_regex_with_cache(&other_patterns, ENTITY_INDEPENDENT_REGEX_CACHE_CAPACITY)
                .unwrap();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let mut cache = cached.caches[0].lock().unwrap();
            cache.reset(&other);
            panic!("poison a cache reset to the wrong regex");
        }));
        assert!(poisoned.is_err());

        let mut cache = cached.cache(0);
        assert!(!cached.caches[0].is_poisoned());
        assert_eq!(
            cached.regex.search_with(&mut cache, &Input::new("123")),
            Some(regex_automata::Match::must(0, 0..3))
        );
    }

    #[test]
    fn scale_character_class_shape_remains_in_residual_regex_layer() {
        let patterns = vec![
            canonical_pattern("anchor", &[]),
            canonical_pattern(r"NERB00079[6X]", &[]),
        ];
        let engine = engine_for_patterns(patterns.clone());
        let [MatcherShard::Layered(shard)] = engine.shards.as_slice() else {
            panic!("an exact literal plus a character class should use the layered matcher");
        };

        assert_eq!(
            shard
                .case_sensitive_literals
                .without_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .iter()
                .map(|pattern| pattern.pattern_order)
                .collect::<Vec<_>>(),
            [0]
        );
        assert_eq!(
            regex_layer_pattern_orders(&shard.residual_regex_layers),
            [1]
        );
        assert_eq!(
            engine_raw_matches(&engine, "anchor NERB000796 NERB00079X"),
            monolithic_raw_matches(&patterns, "anchor NERB000796 NERB00079X")
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
                .without_left_boundary
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
    fn every_inline_scan_entry_rejects_mapped_unicode_over_the_byte_limit() {
        let canonical = canonical_for_patterns(vec![canonical_pattern("k", &["IGNORECASE"])]);
        let engine = NativeEngine::compile(&canonical, MatchMode::EntityIndependent).unwrap();
        let overlap_engine = NativeEngine::compile(&canonical, MatchMode::AllOverlaps).unwrap();
        let mut oversized = vec![b'.'; MAX_SCAN_INPUT_BYTES - 2];
        oversized.extend_from_slice("K".as_bytes());
        assert_eq!(oversized.len(), MAX_SCAN_INPUT_BYTES + 1);

        let mut reusable = NativeMatchBuffer::new();
        reusable.push(RawMatch::new(99, 0, 0).unwrap()).unwrap();
        let error = engine
            .scan_bytes_into(&oversized, &mut reusable)
            .unwrap_err();
        assert!(error.to_string().contains("configured limit"));
        assert!(error
            .to_string()
            .contains(&MAX_SCAN_INPUT_BYTES.to_string()));
        assert!(reusable.is_empty());

        assert!(engine
            .scan_bytes(&oversized)
            .unwrap_err()
            .to_string()
            .contains("configured limit"));
        assert!(engine
            .scan_bytes_bounded(&oversized, 1)
            .unwrap_err()
            .to_string()
            .contains("configured limit"));

        let mut leftmost = NativeMatchBuffer::new();
        leftmost.push(RawMatch::new(99, 0, 0).unwrap()).unwrap();
        assert!(overlap_engine
            .scan_bytes_leftmost_from_all_overlaps(&oversized, &mut leftmost)
            .unwrap_err()
            .to_string()
            .contains("configured limit"));
        assert!(leftmost.is_empty());
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
                .with_left_boundary
                .as_ref()
                .unwrap()
                .patterns
                .len(),
            500
        );
        assert_eq!(
            regex_layer_pattern_orders(&shard.residual_regex_layers).len(),
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
