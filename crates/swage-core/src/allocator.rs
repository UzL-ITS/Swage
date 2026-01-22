//! Memory allocation strategies for Rowhammer attacks.
//!
//! This module defines the [`ConsecAllocator`] trait and the main [`alloc_memory`] function
//! for allocating physically consecutive memory blocks required for effective Rowhammer attacks.

use crate::memory::{ConsecBlocks, GetConsecPfns};
use crate::util::Size;
use crate::util::compact_mem;
use log::warn;

/// Trait for memory allocation strategies that provide consecutive physical memory blocks.
///
/// Implementors of this trait define different strategies for allocating physically
/// consecutive memory regions, which are required for effective Rowhammer attacks.
/// Different allocators may use different underlying mechanisms such as hugepages,
/// transparent huge pages (THP), timing side channels, operating system bugs, or custom kernel modules.
///
/// # Associated Types
///
/// * `Error` - The error type returned by allocation operations. Must implement [`std::error::Error`].
///
/// # Required Methods
///
/// Implementors must provide:
/// * [`block_size()`](ConsecAllocator::block_size) - Returns the size of individual memory blocks
/// * [`alloc_consec_blocks()`](ConsecAllocator::alloc_consec_blocks) - Allocates consecutive memory blocks
///
/// # Examples
///
/// See individual allocator implementations such as `swage-hugepage`, `swage-spoiler`,
/// or `swage-pfn` for concrete usage examples.
pub trait ConsecAllocator {
    /// The error type returned by allocation operations.
    type Error: std::error::Error;

    /// Returns the size of individual memory blocks managed by this allocator.
    ///
    /// The block size typically corresponds to the underlying memory page size
    /// (e.g., 1GB for hugepages, 2MB for THP).
    fn block_size(&self) -> Size;

    /// Allocates consecutive physical memory blocks of the specified size.
    ///
    /// # Arguments
    ///
    /// * `size` - The total size of memory to allocate. Must be a multiple of [`block_size()`](ConsecAllocator::block_size).
    ///
    /// # Returns
    ///
    /// Returns [`ConsecBlocks`] containing the allocated memory regions on success,
    /// or an error if allocation fails.
    ///
    /// # Errors
    ///
    /// May return an error if:
    /// * The requested size is not a multiple of the block size
    /// * Physical memory allocation fails
    /// * Required kernel interfaces are unavailable
    /// * Insufficient physical memory is available
    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error>;
}

/// Allocate memory using an allocation strategy.
///
/// This is the main entry point for users who simply want to allocate some consecutive memory.
///
/// # Safety
///
/// This function is unsafe because it involves raw memory allocations
/// that are not managed by Rust's ownership or borrowing rules. The caller
/// must ensure that the memory is correctly deallocated and not accessed
/// concurrently from multiple threads.
///
/// # Arguments
///
/// * `allocator` - A mutable allocator object that implements the `ConsecAllocator` trait.
///   This strategy will be used to allocate the consecutive memory blocks.
/// * `mem_config` - The memory configuration specifying parameters like memory size and
///   alignment requirements.
/// * `mapping` - A reference to a `PatternAddressMapper`, which assists in determining the
///   aggressor sets for the given memory configuration.
///
/// # Errors
///
/// This function returns an `anyhow::Result` which is:
/// - `Ok(ConsecBlocks)` containing the allocated memory blocks.
/// - `Err(Error)` if there is any failure during allocation.
pub fn alloc_memory<E: std::error::Error>(
    allocator: &mut dyn ConsecAllocator<Error = E>,
    size: Size,
) -> Result<ConsecBlocks, E> {
    assert_eq!(
        size.bytes() % allocator.block_size().bytes(),
        0,
        "Size {} must be a multiple of block size {}",
        size,
        allocator.block_size()
    );
    assert!(size.bytes() > 0, "Size must be greater than 0");

    let compacted = compact_mem();
    match compacted {
        Ok(_) => {}
        Err(e) => warn!("Memory compaction failed: {:?}", e),
    }
    let memory = allocator.alloc_consec_blocks(size)?;
    memory.log_pfns(log::Level::Info);
    Ok(memory)
}
