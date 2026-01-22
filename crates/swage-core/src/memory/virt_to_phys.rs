use std::fmt::{Debug, Formatter};
use std::ops::{Add, Sub};

use crate::util::PAGE_SHIFT;
use itertools::Itertools;
use log::warn;
use pagemap2::{MapsEntry, PageMapEntry, PageMapError, VirtualMemoryArea};
use serde::Serialize;
use thiserror::Error;

#[repr(transparent)]
#[derive(Clone, Copy, Default, Serialize, PartialEq, Eq)]
/// Physical memory address.
///
/// A newtype wrapper around a physical address value.
pub struct PhysAddr(usize);

impl Debug for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("PhysAddr(0x{:02x})", self.0))
    }
}

impl PhysAddr {
    /// Creates a new physical address.
    pub fn new(addr: usize) -> Self {
        PhysAddr(addr)
    }

    /// Returns the address as a usize.
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

/// Trait for resolving virtual addresses to physical addresses.
///
/// Implementors provide methods to translate virtual memory addresses
/// to physical addresses using system interfaces like `/proc/{pid}/pagemap`.
pub trait VirtToPhysResolver {
    /// Errors that can occur during phsical address resolution
    type Error;
    /// Translates a virtual address to a physical address.
    ///
    /// # Errors
    ///
    /// Returns an error if address translation fails.
    fn get_phys(&mut self, virt: u64) -> Result<PhysAddr, Self::Error>;

    /// Translates a range of virtual addresses to physical addresses.
    ///
    /// # Errors
    ///
    /// Returns an error if address translation fails.
    fn get_phys_range(&mut self, region: VirtualMemoryArea) -> Result<Vec<PhysAddr>, Self::Error>;
}

/// Errors that can happen during PageMap operations
#[derive(Debug, Error)]
#[error(transparent)]
pub struct LinuxPageMapError(#[from] PageMapError);

/// Virtual to physical address translator using Linux pagemap.
///
/// Uses `/proc/{pid}/pagemap` to translate virtual to physical addresses.
/// Requires root privileges to access pagemap.
pub struct LinuxPageMap {
    pagemap_wrapper: pagemap2::PageMap,
}

impl LinuxPageMap {
    /// Creates a new pagemap for the current process.
    ///
    /// # Errors
    ///
    /// Returns an error if opening `/proc/self/pagemap` fails.
    pub fn new() -> Result<LinuxPageMap, LinuxPageMapError> {
        Self::for_process(std::process::id())
    }

    /// Creates a new pagemap for a specific process.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID to open pagemap for
    ///
    /// # Errors
    ///
    /// Returns an error if opening the process pagemap fails.
    pub fn for_process(pid: u32) -> Result<LinuxPageMap, LinuxPageMapError> {
        let res = LinuxPageMap {
            pagemap_wrapper: pagemap2::PageMap::new(pid as u64)?,
        };
        Ok(res)
    }
}

pub struct PageMap(pub Vec<(MapsEntry, Vec<PageMapEntry>)>);

impl LinuxPageMap {
    /// Get pagemap
    pub fn pagemap(&mut self) -> Result<PageMap, LinuxPageMapError> {
        self.pagemap_wrapper
            .pagemap()
            .map(PageMap)
            .map_err(|e| e.into())
    }
}

impl VirtToPhysResolver for LinuxPageMap {
    type Error = LinuxPageMapError;
    fn get_phys(&mut self, virt: u64) -> Result<PhysAddr, Self::Error> {
        //calc virtual address of page containing ptr_to_start
        let vaddr_start_page = virt & !0xFFF;
        let vaddr_end_page = vaddr_start_page + 4095;

        //query pagemap
        let memory_region = VirtualMemoryArea::from((vaddr_start_page, vaddr_end_page));
        let entry = self.pagemap_wrapper.pagemap_vma(&memory_region)?;
        assert_eq!(
            entry.len(),
            1,
            "Got {} pagemap entries for virtual address 0x{:x}, expected exactly one",
            entry.len(),
            virt
        );
        let pfn = entry[0].pfn()?;
        if pfn == 0 {
            warn!(
                "Got invalid PFN 0 for virtual address 0x{:x}. Are we root?",
                virt
            );
        }

        let phys_addr = ((pfn << PAGE_SHIFT) | (virt & 0xFFF)) as usize;

        Ok(PhysAddr(phys_addr))
    }
    fn get_phys_range(
        &mut self,
        memory_region: VirtualMemoryArea,
    ) -> Result<Vec<PhysAddr>, Self::Error> {
        let entry = self.pagemap_wrapper.pagemap_vma(&memory_region)?;
        Ok(entry
            .into_iter()
            .map(|e| e.pfn().map(|p| p << PAGE_SHIFT).map_err(|e| e.into()))
            .collect::<Result<Vec<u64>, Self::Error>>()?
            .iter()
            .map(|p| PhysAddr(*p as usize))
            .collect_vec())
    }
}

impl From<PhysAddr> for usize {
    fn from(addr: PhysAddr) -> usize {
        addr.0
    }
}

impl From<PhysAddr> for *const u8 {
    fn from(addr: PhysAddr) -> *const u8 {
        addr.0 as *const u8
    }
}

impl std::fmt::Pointer for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:p}", self.0 as *const u8)
    }
}

impl Add<PhysAddr> for PhysAddr {
    type Output = PhysAddr;

    fn add(self, rhs: PhysAddr) -> Self::Output {
        PhysAddr(self.0 + rhs.0)
    }
}

impl Sub<PhysAddr> for PhysAddr {
    type Output = PhysAddr;

    fn sub(self, rhs: PhysAddr) -> Self::Output {
        assert!(self.0 >= rhs.0);
        PhysAddr(self.0 - rhs.0)
    }
}

impl Add<usize> for PhysAddr {
    type Output = PhysAddr;

    fn add(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 + rhs)
    }
}

impl Sub<usize> for PhysAddr {
    type Output = PhysAddr;

    fn sub(self, rhs: usize) -> Self::Output {
        assert!(self.0 >= rhs);
        PhysAddr(self.0 - rhs)
    }
}
