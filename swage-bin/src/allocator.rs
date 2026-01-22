//! Memory allocation strategies for allocating consecutive memory blocks.
//!
//! This module provides different memory allocation strategies for allocating consecutive memory blocks. The strategies include buddy allocation, CoCo, hugepage allocation, mmap, and spoiler.
//!
//! To add a new memory allocation strategy, implement the `ConsecAllocator` trait for the new strategy and add a new variant to the `ConsecAlloc` enum.

use swage_blacksmith::hammerer::PatternAddressMapper;
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{ConsecBlocks, GetConsecPfns, MemConfiguration};
use swage_core::util::alloc_util::compact_mem;

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
/// * `alloc_strategy` - A mutable allocator object that implements the `ConsecAllocator` trait.
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
///
pub fn alloc_memory(
    alloc_strategy: &mut dyn ConsecAllocator,
    mem_config: MemConfiguration,
    mapping: &PatternAddressMapper,
) -> anyhow::Result<ConsecBlocks> {
    let block_size = alloc_strategy.block_size();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = mapping.aggressor_sets(mem_config, block_shift).len();

    let compacted = compact_mem();
    match compacted {
        Ok(_) => {}
        Err(e) => warn!("Memory compaction failed: {:?}", e),
    }
    let memory = alloc_strategy.alloc_consec_blocks(num_sets * block_size)?;
    memory.log_pfns(log::Level::Info);
    Ok(memory)
}
