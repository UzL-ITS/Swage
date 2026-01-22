use crate::memory::keyed_cache::KeyedCache;
use crate::memory::mem_configuration::MemConfiguration;
use std::cell::RefCell;

type CacheKey = (MemConfiguration, u64);
type CacheValue = Option<usize>;

/// Physical frame number (PFN) offset configuration.
///
/// Represents either a fixed offset or a dynamically calculated offset
/// that is cached for performance. Fixed offsets disable runtime calculation.
#[derive(Clone, Debug)]
pub enum PfnOffset {
    /// A constant offset that never changes
    Fixed(usize),
    /// A dynamically calculated offset with caching
    ///
    /// Stores the cached value and the configuration key used to compute it
    Dynamic(Box<RefCell<Option<(CacheValue, CacheKey)>>>),
}

/// Trait for types that provide cached PFN offset access.
pub trait CachedPfnOffset {
    /// Returns a reference to the PFN offset.
    fn cached_offset(&self) -> &PfnOffset;
}

/// A cache for the PFN offset keyed by memory configuration and conflict threshold.
/// This allows the implementation to store a fixed PFN offset, effectively disabling logic around PFN offset calculation.
impl<T> KeyedCache<usize, (MemConfiguration, u64)> for T
where
    T: CachedPfnOffset,
{
    fn get_cached(&self, key: (MemConfiguration, u64)) -> Option<usize> {
        match self.cached_offset() {
            PfnOffset::Fixed(offset) => Some(*offset),
            PfnOffset::Dynamic(pfn_offset) => {
                let state = pfn_offset.borrow();
                match state.as_ref() {
                    Some((offset, cfg)) if offset.is_some() && *cfg == key => Some(offset.unwrap()),
                    _ => None,
                }
            }
        }
    }
    fn put(&self, state: Option<usize>, key: (MemConfiguration, u64)) -> Option<usize> {
        match self.cached_offset() {
            PfnOffset::Fixed(_) => panic!("Fixed offset should not be set"),
            PfnOffset::Dynamic(cell) => {
                let mut cell = cell.borrow_mut();
                *cell = Some((state, key));
                state
            }
        }
    }
}
