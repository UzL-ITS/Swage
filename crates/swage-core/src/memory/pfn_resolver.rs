use crate::memory::{LinuxPageMap, VirtToPhysResolver};

use super::virt_to_phys::{LinuxPageMapError, PhysAddr};

/// Result type for PFN resolution operations.
pub type Result<T> = std::result::Result<T, LinuxPageMapError>;

/// Resolves virtual addresses to physical frame numbers.
pub trait PfnResolver {
    /// Returns the physical frame number for this address.
    ///
    /// # Errors
    ///
    /// Returns error if physical address cannot be resolved
    fn pfn(&self) -> Result<PhysAddr>;
}

/// implementation for PfnResolver trait for raw pointers
impl<T> PfnResolver for *mut T {
    fn pfn(&self) -> Result<PhysAddr> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(*self as u64)
    }
}

/// implementation for PfnResolver trait for raw pointers
impl<T> PfnResolver for *const T {
    fn pfn(&self) -> Result<PhysAddr> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(*self as u64)
    }
}
