use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use pagemap2::{MapsEntry, PageMapEntry, PageMapError};

use crate::util::PAGE_SIZE;

/// Pagemap information indexed by memory region.
///
/// Provides access to physical page mappings organized by virtual memory area.
pub(crate) struct PageMapInfo(pub HashMap<ByMemoryRegion, Vec<(u64, PageMapEntry)>>);

impl PageMapInfo {
    /// Loads pagemap information for a process.
    ///
    /// Reads `/proc/pid/pagemap` and `/proc/pid/maps` to build a complete
    /// mapping of virtual to physical addresses.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID to load pagemap for
    ///
    /// # Errors
    ///
    /// Returns an error if reading pagemap fails.
    pub fn load(pid: u64) -> Result<Self, PageMapError> {
        let mut pagemap = pagemap2::PageMap::new(pid)?;

        let mut ret = HashMap::new();

        let maps = pagemap.maps()?;
        for map in &maps {
            let start_addr = map.vma().start_address();
            let k = ByMemoryRegion(map.clone());
            let mut v1 = vec![];
            if map.path() == Some("[vsyscall]") {
                // vsyscall is not resolvable on modern linux systems
                ret.insert(k, v1);
                continue;
            }
            let pmap = pagemap.pagemap_vma(&map.vma())?;
            for (idx, pmap) in pmap.iter().enumerate() {
                v1.push((start_addr + idx as u64 * PAGE_SIZE as u64, *pmap));
            }
            ret.insert(k, v1);
        }
        Ok(Self(ret))
    }
}

pub struct ByMemoryRegion(pub MapsEntry);

impl Hash for ByMemoryRegion {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let r = self.0.vma();
        (r.start_address(), r.last_address()).hash(state)
    }
}

impl PartialEq for ByMemoryRegion {
    fn eq(&self, other: &Self) -> bool {
        let r = self.0.vma();
        let r1 = other.0.vma();
        r.start_address() == r1.start_address() && r.last_address() == r1.last_address()
    }
}

impl Eq for ByMemoryRegion {}
