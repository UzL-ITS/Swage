/// Page shift value (12 bits) for 4KB pages
pub const PAGE_SHIFT: usize = 12;
/// Standard page size (4096 bytes)
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
/// Mask for extracting page offset
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

/// Row shift value (13 bits) for 8KB rows
pub const ROW_SHIFT: usize = 13;
/// Standard DRAM row size (8192 bytes)
pub const ROW_SIZE: usize = 1 << ROW_SHIFT;
/// Mask for extracting row offset
pub const ROW_MASK: usize = ROW_SIZE - 1;

/// Cache line size (64 bytes) for x86_64
pub const CL_SIZE: usize = 64;

/// Number of rounds for timer calibration
pub const TIMER_ROUNDS: usize = 100_000;

/// Base address for hugepage memory allocations
pub const BASE_MSB: *mut libc::c_void = 0x2000000000 as *mut libc::c_void;
