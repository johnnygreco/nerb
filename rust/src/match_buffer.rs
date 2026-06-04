use crate::error::{validation, Result};

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

#[derive(Clone, Debug, Default)]
pub struct NativeMatchBuffer {
    matches: Vec<RawMatch>,
}

impl NativeMatchBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            matches: Vec::with_capacity(capacity),
        }
    }

    pub fn from_raw_matches(raw_matches: &[(u32, u64, u64)]) -> Result<Self> {
        let mut buffer = Self::with_capacity(raw_matches.len());
        for (detector_index, start_byte, end_byte) in raw_matches {
            buffer.push(RawMatch::new(*detector_index, *start_byte, *end_byte)?);
        }
        Ok(buffer)
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

    pub fn reserve(&mut self, additional: usize) {
        self.matches.reserve(additional);
    }

    pub fn push(&mut self, raw_match: RawMatch) {
        self.matches.push(raw_match);
    }

    pub fn get(&self, index: usize) -> Option<RawMatch> {
        self.matches.get(index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_buffer_stores_and_clears_raw_matches() {
        let mut buffer = NativeMatchBuffer::with_capacity(4);
        buffer.push(RawMatch::new(7, 10, 12).unwrap());

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
}
