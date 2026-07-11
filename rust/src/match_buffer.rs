use crate::error::{memory, validation, Result};

const MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawMatch {
    pub detector_index: u32,
    pub start_byte: u64,
    pub end_byte: u64,
}

impl RawMatch {
    pub fn new(detector_index: u32, start_byte: u64, end_byte: u64) -> Result<Self> {
        if end_byte < start_byte {
            return Err(validation(
                "/match",
                format!("raw match end_byte {end_byte} is before start_byte {start_byte}"),
            ));
        }
        Ok(Self {
            detector_index,
            start_byte,
            end_byte,
        })
    }

    pub fn as_tuple(&self) -> (u32, u64, u64) {
        (self.detector_index, self.start_byte, self.end_byte)
    }
}

#[derive(Clone, Debug)]
pub struct NativeMatchBuffer {
    matches: Vec<RawMatch>,
    max_matches: usize,
}

impl Default for NativeMatchBuffer {
    fn default() -> Self {
        Self {
            matches: Vec::new(),
            max_matches: MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY,
        }
    }
}

impl NativeMatchBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Result<Self> {
        validate_capacity(capacity)?;
        let mut matches = Vec::new();
        try_reserve_exact(&mut matches, capacity)?;
        Ok(Self {
            matches,
            max_matches: MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY,
        })
    }

    pub fn with_match_limit(max_matches: usize) -> Result<Self> {
        validate_capacity(max_matches)?;
        Ok(Self {
            matches: Vec::new(),
            max_matches,
        })
    }

    pub fn len(&self) -> usize {
        self.matches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.matches.capacity()
    }

    pub fn clear(&mut self) {
        self.matches.clear();
    }

    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        let requested = self.matches.len().checked_add(additional).ok_or_else(|| {
            memory(
                "/match_buffer",
                "requested match buffer capacity overflowed usize",
            )
        })?;
        validate_capacity(requested)?;
        self.validate_match_limit(requested)?;
        try_reserve_exact(&mut self.matches, additional)
    }

    pub fn push(&mut self, raw_match: RawMatch) -> Result<()> {
        let requested = self.matches.len().checked_add(1).ok_or_else(|| {
            memory(
                "/match_buffer",
                "requested match buffer capacity overflowed usize",
            )
        })?;
        validate_capacity(requested)?;
        self.validate_match_limit(requested)?;
        if self.matches.len() == self.matches.capacity() {
            let additional = next_growth(self.matches.capacity(), requested, self.max_matches)?;
            try_reserve_exact(&mut self.matches, additional)?;
        }
        self.matches.push(raw_match);
        Ok(())
    }

    pub fn sort(&mut self) {
        self.matches.sort_by_key(|raw_match| {
            (
                raw_match.start_byte,
                raw_match.end_byte,
                raw_match.detector_index,
            )
        });
    }

    pub fn get(&self, index: usize) -> Option<RawMatch> {
        self.matches.get(index).copied()
    }

    fn validate_match_limit(&self, requested: usize) -> Result<()> {
        if requested > self.max_matches {
            return Err(memory(
                "/match_buffer",
                format!(
                    "requested match count {requested} exceeds configured match limit {}",
                    self.max_matches
                ),
            ));
        }
        Ok(())
    }
}

fn validate_capacity(capacity: usize) -> Result<()> {
    if capacity > MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY {
        return Err(memory(
            "/match_buffer",
            format!(
                "requested match buffer capacity {capacity} exceeds pre-scan limit {MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY}"
            ),
        ));
    }
    Ok(())
}

fn try_reserve_exact(matches: &mut Vec<RawMatch>, additional: usize) -> Result<()> {
    matches.try_reserve_exact(additional).map_err(|error| {
        memory(
            "/match_buffer",
            format!("could not reserve match buffer capacity: {error}"),
        )
    })
}

fn next_growth(current_capacity: usize, requested: usize, max_matches: usize) -> Result<usize> {
    let doubled = current_capacity.saturating_mul(2).max(1);
    let target = doubled
        .max(requested)
        .min(MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY)
        .min(max_matches);
    target.checked_sub(current_capacity).ok_or_else(|| {
        memory(
            "/match_buffer",
            "requested match buffer capacity overflowed usize",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_buffer_stores_and_clears_raw_matches() {
        let mut buffer = NativeMatchBuffer::with_capacity(4).unwrap();
        buffer.push(RawMatch::new(7, 10, 12).unwrap()).unwrap();

        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.get(0).unwrap().as_tuple(), (7, 10, 12));
        assert!(buffer.capacity() >= 4);

        buffer.clear();

        assert!(buffer.is_empty());
        assert!(buffer.capacity() >= 4);
    }

    #[test]
    fn raw_match_rejects_inverted_spans() {
        let error = RawMatch::new(1, 5, 4).unwrap_err();

        assert!(error.to_string().contains("before start_byte"));
    }

    #[test]
    fn match_buffer_rejects_oversized_capacity() {
        let error =
            NativeMatchBuffer::with_capacity(MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY + 1).unwrap_err();

        assert!(error.to_string().contains("exceeds pre-scan limit"));
    }

    #[test]
    fn match_buffer_push_rejects_past_pre_scan_limit() {
        let mut buffer =
            NativeMatchBuffer::with_capacity(MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY).unwrap();
        buffer.matches.resize(
            MAX_PRE_SCAN_MATCH_BUFFER_CAPACITY,
            RawMatch::new(0, 0, 0).unwrap(),
        );

        let error = buffer.push(RawMatch::new(0, 0, 0).unwrap()).unwrap_err();

        assert!(error.to_string().contains("exceeds pre-scan limit"));
    }

    #[test]
    fn match_buffer_sorts_by_offsets_and_detector_index() {
        let mut buffer = NativeMatchBuffer::new();
        buffer.push(RawMatch::new(2, 5, 6).unwrap()).unwrap();
        buffer.push(RawMatch::new(1, 0, 5).unwrap()).unwrap();
        buffer.push(RawMatch::new(0, 0, 3).unwrap()).unwrap();
        buffer.push(RawMatch::new(3, 0, 3).unwrap()).unwrap();

        buffer.sort();

        assert_eq!(
            (0..buffer.len())
                .map(|index| buffer.get(index).unwrap().as_tuple())
                .collect::<Vec<_>>(),
            [(0, 0, 3), (3, 0, 3), (1, 0, 5), (2, 5, 6)]
        );
    }

    #[test]
    fn match_buffer_push_grows_amortized_within_pre_scan_limit() {
        let mut buffer = NativeMatchBuffer::new();
        buffer.push(RawMatch::new(0, 0, 0).unwrap()).unwrap();
        let first_capacity = buffer.capacity();
        buffer.push(RawMatch::new(0, 1, 1).unwrap()).unwrap();

        assert!(first_capacity >= 1);
        assert!(buffer.capacity() >= 2);
    }

    #[test]
    fn match_buffer_enforces_configured_match_limit_while_collecting() {
        let mut buffer = NativeMatchBuffer::with_match_limit(2).unwrap();
        buffer.push(RawMatch::new(0, 0, 1).unwrap()).unwrap();
        buffer.push(RawMatch::new(0, 1, 2).unwrap()).unwrap();

        let error = buffer.push(RawMatch::new(0, 2, 3).unwrap()).unwrap_err();

        assert!(error.to_string().contains("configured match limit 2"));
        assert!(buffer.capacity() <= 2);
    }
}
