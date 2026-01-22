//! The `memory` module provides abstractions for memory management, initialization, and checking for bitflips.
//!
//! The `memory` module provides the following abstractions:
//! - `Memory`: A managed memory region that is allocated using HugepageAllocator.
//! - `VictimMemory`: A trait that combines the `BytePointer`, `Initializable`, and `Checkable` traits.
//! - `BytePointer`: A trait for accessing memory as a byte pointer.
//! - `Initializable`: A trait for initializing memory with (random) values.
//! - `Checkable`: A trait for checking memory for bitflips.
//! - `PfnResolver`: A trait for resolving the physical frame number (PFN) of a `self`.
//! - `LinuxPageMap`: A struct that provides a mapping from virtual to physical addresses.
//! - `VirtToPhysResolver`: A trait for resolving the physical address of a provided virtual address.
//!
//! The `memory` module also provides the following helper structs:
//! - `ConsecBlocks`: A struct that represents a collection of consecutive memory blocks.
//! - `MemBlock`: A struct that represents a memory block.
//! - `PfnOffset`: A struct that represents a physical frame number (PFN) offset.
//! - `PfnOffsetResolver`: A struct that resolves the physical frame number (PFN) offset of a provided virtual address.
//! - `Timer`: A struct that provides a timer for measuring memory access times.
//!
//! The `memory` module also provides the following helper functions:
//! - `construct_memory_tuple_timer`: A function that constructs a memory tuple timer.
mod consec_blocks;
mod dram_addr;
mod flippy_page;
mod keyed_cache;
mod mem_configuration;
mod memblock;
mod pagemap_info;
mod pfn_offset;
mod pfn_offset_resolver;
mod pfn_resolver;
mod timer;
mod virt_to_phys;

pub use self::consec_blocks::ConsecBlocks;
pub use self::dram_addr::DRAMAddr;
pub use self::flippy_page::{FlippyPage, find_flippy_page};
pub use self::mem_configuration::{MTX_SIZE, MemConfiguration};
pub use self::memblock::{Error as ConsecPfnsError, FormatPfns, GetConsecPfns, Memory};
pub use self::pfn_offset::PfnOffset;
pub use self::pfn_offset_resolver::PfnOffsetResolver;
pub use self::pfn_resolver::PfnResolver;
pub use self::timer::{MemoryTupleTimer, TimerError, construct_memory_tuple_timer};
pub use self::virt_to_phys::PhysAddr;
pub use self::virt_to_phys::{LinuxPageMap, LinuxPageMapError, VirtToPhysResolver};
use rand::Rng as _;
use serde::Serialize;
use std::arch::x86_64::_mm_clflush;
use std::fmt::Debug;
use std::io::BufWriter;

use crate::util::{CL_SIZE, PAGE_MASK, PAGE_SIZE, ROW_MASK, ROW_SIZE, Rng};

use libc::{c_void, memcmp};
use log::{debug, info, trace};
use std::{arch::x86_64::_mm_mfence, fmt};

/// Pointer type for aggressor row addresses.
///
/// Used to identify memory rows that are hammered to induce bit flips
/// in adjacent victim rows.
pub type AggressorPtr = *const u8;

/// Errors that can occur during memory operations.
#[derive(Debug)]
pub enum MemoryError {
    /// Memory allocation failed
    AllocFailed,
    /// Attempted to create a zero-size memory layout
    ZeroSizeLayout,
}

impl std::error::Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryError::AllocFailed => write!(f, "Allocation failed"),
            MemoryError::ZeroSizeLayout => write!(f, "Zero size layout"),
        }
    }
}

/// Combined trait for victim memory regions.
///
/// This trait combines [`BytePointer`], [`Initializable`], and [`Checkable`] to provide
/// a complete interface for managing victim memory in Rowhammer attacks.
pub trait VictimMemory: BytePointer + Initializable + Checkable {}

/// Trait for accessing memory as a byte pointer.
///
/// Provides low-level access to memory regions with byte-level addressing.
#[allow(clippy::len_without_is_empty)]
pub trait BytePointer {
    /// Returns a mutable pointer to the byte at the given offset.
    ///
    /// # Safety
    ///
    /// The returned pointer is valid only while the memory region exists.
    /// Dereferencing requires unsafe code and proper synchronization.
    fn addr(&self, offset: usize) -> *mut u8;

    /// Returns a mutable pointer to the start of the memory region.
    fn ptr(&self) -> *mut u8;

    /// Returns the total length of the memory region in bytes.
    fn len(&self) -> usize;

    /// Dumps memory contents to a file in hexadecimal format.
    ///
    /// Writes each row (8KB) as a line of hexadecimal bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if file creation or writing fails.
    fn dump(&self, file: &str) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;
        let file = File::create(file)?;
        let mut writer = BufWriter::new(file);
        for offset in (0..self.len()).step_by(ROW_SIZE) {
            for byte_offset in 0..ROW_SIZE {
                write!(writer, "{:02x}", unsafe {
                    *self.addr(offset + byte_offset)
                })?;
            }
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        Ok(())
    }
}

/// Memory initialization patterns for Rowhammer attacks.
///
/// Different patterns can be used to maximize the probability of inducing bit flips.
/// Stripe patterns alternate between aggressor rows (ones/zeros) and victim rows
/// (opposite values) to create charge transfer between adjacent DRAM rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DataPattern {
    /// Random data pattern using a seeded RNG
    Random(Box<Rng>),
    /// Stripe pattern with zeros at aggressor rows, ones elsewhere
    StripeZero {
        /// The rows to contain 0x00
        #[serde(skip_serializing)]
        zeroes: Vec<AggressorPtr>,
    },
    /// All zeros (0x00)
    Zero,
    /// Stripe pattern with ones at aggressor rows, zeros elsewhere
    StripeOne {
        /// The rows to contain 0xFF
        #[serde(skip_serializing)]
        ones: Vec<AggressorPtr>,
    },
    /// All ones (0xFF)
    One,
}

impl DataPattern {
    fn get(&mut self, addr: *const u8) -> [u8; PAGE_SIZE] {
        match self {
            DataPattern::Random(rng) => {
                let mut arr = [0u8; PAGE_SIZE];
                for byte in arr.iter_mut() {
                    *byte = rng.random();
                }
                arr
            }
            DataPattern::StripeZero { zeroes } => {
                for &row in zeroes.iter() {
                    if (row as usize) == addr as usize & !ROW_MASK {
                        trace!("setting aggressor page to 0x00 at addr {:p}", addr);
                        return [0x00; PAGE_SIZE];
                    }
                }
                [0xFF; PAGE_SIZE]
            }
            DataPattern::Zero => [0x00; PAGE_SIZE],
            DataPattern::StripeOne { ones } => {
                for &row in ones.iter() {
                    if (row as usize) == addr as usize & !ROW_MASK {
                        trace!("setting aggressor page to 0xFF at addr {:p}", addr);
                        return [0xFF; PAGE_SIZE];
                    }
                }
                [0x00; PAGE_SIZE]
            }
            DataPattern::One => [0xFF; PAGE_SIZE],
        }
    }
}

/// Trait for initializing memory with specific patterns.
///
/// Provides methods to write data patterns to memory, either for all pages
/// or excluding specific pages.
pub trait Initializable {
    /// Initializes memory with the given data pattern.
    fn initialize(&self, pattern: DataPattern);

    /// Initializes memory excluding specific pages.
    fn initialize_excluding(&self, pattern: DataPattern, pages: &[*const u8]);

    /// Initializes memory using a callback function.
    ///
    /// The callback receives an offset and returns optional page data.
    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> Option<[u8; PAGE_SIZE]>);
}

/// Represents a bit flip detected in memory.
///
/// A bit flip is a change in memory where one or more bits differ from their
/// expected value. This is the primary indicator of a successful Rowhammer attack.
#[derive(Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub struct BitFlip {
    /// Virtual address where the bit flip occurred
    pub addr: usize,
    /// Bitmask indicating which bits flipped (1 = bit flipped)
    pub bitmask: u8,
    /// The expected data value (before the flip)
    pub data: u8,
}

/// Direction of bit flip transitions.
///
/// Indicates whether bits flipped from 0→1, 1→0, or multiple directions.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub enum FlipDirection {
    /// Bit flipped from 0 to 1
    ZeroToOne,
    /// Bit flipped from 1 to 0
    OneToZero,
    /// Multiple bits flipped in (potentially) different directions
    Multiple(Vec<FlipDirection>),
    /// No bit flip occurred
    None,
    /// Any flip direction is acceptable
    Any,
}

impl core::fmt::Debug for BitFlip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitFlip")
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bitmask", &format_args!("{:#x}", self.bitmask))
            .field("data", &format_args!("{:#x}", self.data))
            .finish()
    }
}

impl BitFlip {
    /// Constructor for BitFlip
    pub fn new(addr: *const u8, bitmask: u8, data: u8) -> Self {
        BitFlip {
            addr: addr as usize,
            bitmask,
            data,
        }
    }
}

impl BitFlip {
    /// Calculate the FlipDirection (1->0 or 0->1 or Multiple) observed in this BitFlip
    pub fn flip_direction(&self) -> FlipDirection {
        match self.bitmask.count_ones() {
            0 => FlipDirection::None,
            1 => {
                let flipped = self.bitmask & self.data;
                match flipped {
                    0 => FlipDirection::ZeroToOne,
                    _ => FlipDirection::OneToZero,
                }
            }
            2.. => FlipDirection::Multiple(
                (0..8)
                    .filter_map(|i| {
                        if self.bitmask & (1 << i) != 0 {
                            Some(if self.data & (1 << i) != 0 {
                                FlipDirection::OneToZero
                            } else {
                                FlipDirection::ZeroToOne
                            })
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
        }
    }
}

/// Trait for checking memory regions for bit flips.
///
/// Implementors provide methods to compare memory contents against expected patterns
/// and identify locations where bit flips have occurred.
pub trait Checkable {
    /// Checks memory against a pattern and returns detected bit flips.
    fn check(&self, pattern: DataPattern) -> Vec<BitFlip>;

    /// Checks memory excluding specific pages.
    fn check_excluding(&self, pattern: DataPattern, pages: &[*const u8]) -> Vec<BitFlip>;

    /// Checks memory using a callback function to generate expected values.
    fn check_cb(&self, f: &mut dyn FnMut(usize) -> Option<[u8; PAGE_SIZE]>) -> Vec<BitFlip>;
}

/// Blanket implementations for Initializable trait for VictimMemory
impl<T> Initializable for T
where
    T: VictimMemory,
{
    fn initialize(&self, pattern: DataPattern) {
        self.initialize_excluding(pattern, &[]);
    }

    fn initialize_excluding(&self, mut pattern: DataPattern, pages: &[*const u8]) {
        info!(
            "initialize buffer with pattern {}",
            match &pattern {
                DataPattern::Random(rng) => format!("random ({:?})", rng),
                DataPattern::StripeZero { .. } => "stripe zero".into(),
                DataPattern::Zero => "zero".into(),
                DataPattern::StripeOne { .. } => "stripe one".into(),
                DataPattern::One => "one".into(),
            }
        );
        self.initialize_cb(&mut |offset: usize| {
            let addr = self.addr(offset);
            let val = pattern.get(addr); // we must call "get" on addr, even if we don't use it, because pattern RNG is stateful
            if pages
                .iter()
                .any(|&page| page as usize & !PAGE_MASK == addr as usize & !PAGE_MASK)
            {
                return None;
            }
            Some(val)
        });
    }

    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> Option<[u8; PAGE_SIZE]>) {
        let len = self.len();
        if !len.is_multiple_of(8) {
            panic!("memory len must be divisible by 8");
        }
        if !len.is_multiple_of(PAGE_SIZE) {
            panic!(
                "memory len ({}) must be divisible by PAGE_SIZE ({})",
                len, PAGE_SIZE
            );
        }

        debug!("initialize {} bytes", len);

        for offset in (0..len).step_by(PAGE_SIZE) {
            if let Some(value) = f(offset) {
                unsafe {
                    std::ptr::write_volatile(self.addr(offset) as *mut [u8; PAGE_SIZE], value);
                }
            }
        }
        debug!("memory init done");
    }
}

/// Blanket implementation for PfnResolver trait for BytePointer
impl<T: BytePointer> PfnResolver for T {
    fn pfn(&self) -> Result<PhysAddr, LinuxPageMapError> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(self.ptr() as u64)
    }
}

/// Blanket implementation for Checkable trait for VictimMemory
impl<T> Checkable for T
where
    T: VictimMemory,
{
    fn check(&self, pattern: DataPattern) -> Vec<BitFlip> {
        self.check_excluding(pattern, &[])
    }

    fn check_excluding(&self, mut pattern: DataPattern, pages: &[*const u8]) -> Vec<BitFlip> {
        self.check_cb(&mut |offset: usize| {
            let addr = self.addr(offset);
            let val = pattern.get(addr); // we must call "get" on addr, even if we don't use it, because pattern RNG is stateful
            if pages
                .iter()
                .any(|&page| page as usize & !PAGE_MASK == addr as usize & !PAGE_MASK)
            {
                return None;
            }
            Some(val)
        })
    }

    fn check_cb(&self, f: &mut dyn FnMut(usize) -> Option<[u8; PAGE_SIZE]>) -> Vec<BitFlip> {
        let len = self.len();
        if !len.is_multiple_of(PAGE_SIZE) {
            panic!(
                "memory len ({}) must be divisible by PAGE_SIZE ({})",
                len, PAGE_SIZE
            );
        }

        let mut ret = vec![];
        for offset in (0..len).step_by(PAGE_SIZE) {
            if let Some(expected) = f(offset) {
                unsafe {
                    for byte_offset in (0..PAGE_SIZE).step_by(CL_SIZE) {
                        _mm_clflush(self.addr(offset + byte_offset));
                    }
                    _mm_mfence();
                    let cmp = memcmp(
                        self.addr(offset) as *const c_void,
                        expected.as_ptr() as *const c_void,
                        PAGE_SIZE,
                    );
                    if cmp == 0 {
                        continue;
                    }
                    debug!(
                        "Found bitflip in page {}. Determining exact flip position",
                        offset
                    );
                    for (i, &expected) in expected.iter().enumerate() {
                        let addr = self.addr(offset + i);
                        _mm_clflush(addr);
                        _mm_mfence();
                        if *addr != expected {
                            ret.push(BitFlip::new(addr, *addr ^ expected, expected));
                        }
                    }
                }
            } else {
                debug!("skipping page {} due to exclusion", offset);
            }
        }
        ret
    }
}

#[test]
fn test_pattern_random_clone() {
    let pattern = DataPattern::Random(Box::new(Rng::from_seed(rand::random())));
    let a = pattern.clone().get(std::ptr::null());
    let b = pattern.clone().get(std::ptr::null());
    assert_eq!(a, b);
}

#[test]
fn test_bitflip_direction() {
    let flip = BitFlip::new(std::ptr::null(), 0b0000_0000, 0xFF);
    assert_eq!(flip.flip_direction(), FlipDirection::None);
    let flip = BitFlip::new(std::ptr::null(), 0b0000_0001, 0b0000_0001);
    assert_eq!(flip.flip_direction(), FlipDirection::OneToZero);

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0001, 0b1111_1110);
    assert_eq!(flip.flip_direction(), FlipDirection::ZeroToOne);

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0010);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::ZeroToOne, FlipDirection::OneToZero])
    );

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0000);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::ZeroToOne, FlipDirection::ZeroToOne])
    );

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0011);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::OneToZero, FlipDirection::OneToZero])
    );
}
