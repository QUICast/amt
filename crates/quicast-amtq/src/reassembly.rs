use crate::datagram::Fragment;
use crate::{MAX_AMT_DATA_MESSAGE, MAX_FRAGMENT_RANGES, MAX_INCOMPLETE_MESSAGES, WireError};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyConfig {
    pub max_incomplete_messages: usize,
    pub max_ranges_per_message: usize,
    pub timeout: Duration,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_incomplete_messages: MAX_INCOMPLETE_MESSAGES,
            max_ranges_per_message: MAX_FRAGMENT_RANGES,
            timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyError {
    InvalidFragment(WireError),
    Disabled,
    InconsistentTotalLength,
    ConflictingOverlap,
    TooManyRanges,
}

impl fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFragment(error) => error.fmt(f),
            Self::Disabled => f.write_str("AMTQ fragment reassembly is disabled"),
            Self::InconsistentTotalLength => {
                f.write_str("AMTQ fragments have inconsistent Total Length values")
            }
            Self::ConflictingOverlap => {
                f.write_str("overlapping AMTQ fragments contain different bytes")
            }
            Self::TooManyRanges => f.write_str("AMTQ fragmented message has too many ranges"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

#[derive(Debug)]
pub struct Reassembler {
    config: ReassemblyConfig,
    messages: BTreeMap<(u64, u64), IncompleteMessage>,
}

impl Reassembler {
    pub fn new(mut config: ReassemblyConfig) -> Self {
        config.max_incomplete_messages =
            config.max_incomplete_messages.min(MAX_INCOMPLETE_MESSAGES);
        config.max_ranges_per_message = config.max_ranges_per_message.min(MAX_FRAGMENT_RANGES);
        Self {
            config,
            messages: BTreeMap::new(),
        }
    }

    pub fn incomplete_count(&self) -> usize {
        self.messages.len()
    }

    pub fn push(
        &mut self,
        fragment: Fragment<'_>,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        validate_fragment(fragment).map_err(ReassemblyError::InvalidFragment)?;
        self.expire(now);
        let key = (fragment.context_id, fragment.packet_id);
        if !self.messages.contains_key(&key) {
            if self.config.max_incomplete_messages == 0 {
                return Err(ReassemblyError::Disabled);
            }
            if self.messages.len() >= self.config.max_incomplete_messages {
                self.evict_oldest();
            }
            self.messages
                .insert(key, IncompleteMessage::new(fragment.total_len, now));
        }

        let end = fragment.offset + fragment.data.len();
        let range_key = (fragment.offset, end);
        let state = self.messages.get(&key).expect("message inserted above");
        if state.total_len != fragment.total_len {
            self.messages.remove(&key);
            return Err(ReassemblyError::InconsistentTotalLength);
        }
        if state.has_conflicting_overlap(fragment.offset, fragment.data) {
            self.messages.remove(&key);
            return Err(ReassemblyError::ConflictingOverlap);
        }
        if state.seen_ranges.contains(&range_key) {
            self.messages
                .get_mut(&key)
                .expect("message still present")
                .updated = now;
            return Ok(None);
        }
        if state.seen_ranges.len() >= self.config.max_ranges_per_message {
            self.messages.remove(&key);
            return Err(ReassemblyError::TooManyRanges);
        }

        let state = self.messages.get_mut(&key).expect("message still present");
        state.data[fragment.offset..end].copy_from_slice(fragment.data);
        state.seen_ranges.insert(range_key);
        state.add_coverage(fragment.offset..end);
        state.updated = now;
        if !state.is_complete() {
            return Ok(None);
        }

        Ok(self.messages.remove(&key).map(|message| message.data))
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let before = self.messages.len();
        let timeout = self.config.timeout;
        self.messages
            .retain(|_, message| now.saturating_duration_since(message.updated) < timeout);
        before - self.messages.len()
    }

    pub fn discard_context(&mut self, context_id: u64) -> usize {
        let before = self.messages.len();
        self.messages
            .retain(|(message_context, _), _| *message_context != context_id);
        before - self.messages.len()
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .messages
            .iter()
            .min_by_key(|(key, message)| (message.updated, **key))
            .map(|(key, _)| *key);
        if let Some(oldest) = oldest {
            self.messages.remove(&oldest);
        }
    }
}

#[derive(Debug)]
struct IncompleteMessage {
    total_len: usize,
    data: Vec<u8>,
    seen_ranges: BTreeSet<(usize, usize)>,
    coverage: Vec<Range<usize>>,
    updated: Instant,
}

impl IncompleteMessage {
    fn new(total_len: usize, now: Instant) -> Self {
        Self {
            total_len,
            data: vec![0; total_len],
            seen_ranges: BTreeSet::new(),
            coverage: Vec::new(),
            updated: now,
        }
    }

    fn has_conflicting_overlap(&self, offset: usize, data: &[u8]) -> bool {
        let end = offset + data.len();
        self.coverage.iter().any(|range| {
            let overlap_start = range.start.max(offset);
            let overlap_end = range.end.min(end);
            (overlap_start..overlap_end).any(|index| self.data[index] != data[index - offset])
        })
    }

    fn add_coverage(&mut self, range: Range<usize>) {
        self.coverage.push(range);
        self.coverage.sort_unstable_by_key(|range| range.start);
        let mut merged = Vec::<Range<usize>>::with_capacity(self.coverage.len());
        for range in self.coverage.drain(..) {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
                continue;
            }
            merged.push(range);
        }
        self.coverage = merged;
    }

    fn is_complete(&self) -> bool {
        matches!(
            self.coverage.as_slice(),
            [range] if range.start == 0 && range.end == self.total_len
        )
    }
}

fn validate_fragment(fragment: Fragment<'_>) -> Result<(), WireError> {
    if fragment.total_len == 0 {
        return Err(WireError::Malformed(
            "AMTQ fragment Total Length must be non-zero",
        ));
    }
    if fragment.total_len > MAX_AMT_DATA_MESSAGE {
        return Err(WireError::LimitExceeded {
            resource: "AMTQ fragment Total Length",
            value: fragment.total_len,
            limit: MAX_AMT_DATA_MESSAGE,
        });
    }
    if fragment.data.is_empty() {
        return Err(WireError::Malformed(
            "AMTQ FRAGMENT must contain at least one byte",
        ));
    }
    let end = fragment
        .offset
        .checked_add(fragment.data.len())
        .ok_or(WireError::LengthOverflow)?;
    if end > fragment.total_len {
        return Err(WireError::Malformed(
            "AMTQ fragment range exceeds Total Length",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragment<'a>(
        packet_id: u64,
        total_len: usize,
        offset: usize,
        data: &'a [u8],
    ) -> Fragment<'a> {
        Fragment {
            context_id: 3,
            packet_id,
            total_len,
            offset,
            data,
        }
    }

    #[test]
    fn reassembles_out_of_order_and_identical_overlap() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig::default());
        assert_eq!(reassembler.push(fragment(1, 6, 3, b"def"), now), Ok(None));
        assert_eq!(reassembler.push(fragment(1, 6, 2, b"cde"), now), Ok(None));
        assert_eq!(
            reassembler.push(fragment(1, 6, 0, b"abc"), now),
            Ok(Some(b"abcdef".to_vec()))
        );
        assert_eq!(reassembler.incomplete_count(), 0);
    }

    #[test]
    fn conflicting_overlap_discards_the_message() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig::default());
        reassembler.push(fragment(1, 6, 0, b"abcd"), now).unwrap();
        assert_eq!(
            reassembler.push(fragment(1, 6, 2, b"XX"), now),
            Err(ReassemblyError::ConflictingOverlap)
        );
        assert_eq!(reassembler.incomplete_count(), 0);
    }

    #[test]
    fn capacity_evicts_least_recently_updated_message() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            max_incomplete_messages: 2,
            ..ReassemblyConfig::default()
        });
        reassembler.push(fragment(1, 2, 0, b"a"), now).unwrap();
        reassembler
            .push(fragment(2, 2, 0, b"b"), now + Duration::from_millis(1))
            .unwrap();
        reassembler
            .push(fragment(3, 2, 0, b"c"), now + Duration::from_millis(2))
            .unwrap();

        assert_eq!(reassembler.incomplete_count(), 2);
        assert_eq!(
            reassembler.push(fragment(1, 2, 1, b"z"), now + Duration::from_millis(3)),
            Ok(None)
        );
    }

    #[test]
    fn expiry_and_context_close_release_state() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            timeout: Duration::from_secs(1),
            ..ReassemblyConfig::default()
        });
        reassembler.push(fragment(1, 2, 0, b"a"), now).unwrap();
        assert_eq!(reassembler.expire(now + Duration::from_secs(1)), 1);

        reassembler.push(fragment(2, 2, 0, b"a"), now).unwrap();
        assert_eq!(reassembler.discard_context(3), 1);
    }

    #[test]
    fn absolute_protocol_limits_cannot_be_configured_away() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(ReassemblyConfig {
            max_incomplete_messages: usize::MAX,
            max_ranges_per_message: usize::MAX,
            ..ReassemblyConfig::default()
        });
        assert_eq!(
            reassembler.push(fragment(1, MAX_AMT_DATA_MESSAGE + 1, 0, b"a"), now),
            Err(ReassemblyError::InvalidFragment(WireError::LimitExceeded {
                resource: "AMTQ fragment Total Length",
                value: MAX_AMT_DATA_MESSAGE + 1,
                limit: MAX_AMT_DATA_MESSAGE,
            }))
        );
    }
}
