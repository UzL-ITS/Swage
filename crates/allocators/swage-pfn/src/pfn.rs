use log::debug;
use lpfs::ProcErr;
use lpfs::proc::buddyinfo::buddyinfo;
use std::ffi::c_void;
use swage_core::util::Size;
use thiserror::Error;

use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{
    ConsecBlocks, DRAMAddr, GetConsecPfns, LinuxPageMapError, MemConfiguration, Memory, PfnResolver,
};
use swage_core::util::{PAGE_SIZE, Size::MB};
use swage_core::util::{mmap, mmap_shm, munmap};

/// Shared memory configuration for PFN allocator.
///
/// Optionally specifies a shared memory name to use with `shm_open`.
#[derive(Clone)]
pub struct SharedMem(Option<String>);

/// PFN-based memory allocator.
///
/// Allocates memory and checks `/proc/self/pagemap` to find consecutive
/// physical frame numbers (PFNs). Optionally uses shared memory mapping.
///
/// # Implementation
///
/// Implements [`swage_core::allocator::ConsecAllocator`] with 4MB block size.
///
/// This allocator repeatedly allocates memory and checks physical contiguity
/// until enough consecutive blocks are found. Primarily useful for testing.
pub struct Pfn {
    mem_config: MemConfiguration,
    shared_mem: SharedMem,
}

/// Pfn allocator. This finds consecutive PFNs by allocating memory (optionally using shared memory mapping with shm_open, if `shared_mem` is provided) and checking the page map.
/// Useful for testing purposes.
impl Pfn {
    /// Constructor for the Pfn allocator
    pub fn new(mem_config: MemConfiguration, shared_mem: SharedMem) -> Self {
        Self {
            mem_config,
            shared_mem,
        }
    }
}

/// Wrapper for ProcErr, which does not implement Error.
#[derive(Debug)]
pub struct ProcErrWrap(ProcErr);

impl std::fmt::Display for ProcErrWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl std::error::Error for ProcErrWrap {}

impl From<ProcErr> for ProcErrWrap {
    fn from(value: ProcErr) -> Self {
        Self(value)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    ProcErr(#[from] ProcErrWrap),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ConsecPfns(#[from] swage_core::memory::ConsecPfnsError),
    #[error(transparent)]
    LinuxPageMapError(#[from] LinuxPageMapError),
}

const BASE_ADDR: *mut c_void = 0x2000000000 as *mut c_void;

impl ConsecAllocator for Pfn {
    type Error = Error;
    fn block_size(&self) -> Size {
        MB(4)
    }

    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        assert!(size.bytes().is_multiple_of(self.block_size().bytes()));
        let block_count = size.bytes() / self.block_size().bytes();
        // allocate low-order pages
        let blocks = get_normal_page_nums().map_err(ProcErrWrap::from)?;
        let blocks: [i64; 11] = blocks.map(|x| x as i64);
        let low_order_bytes = low_order_bytes(&blocks, 9);
        let buf: *mut c_void = mmap(std::ptr::null_mut(), low_order_bytes);
        const BUFSIZE: usize = MB(1024).bytes();
        let mut blocks = vec![];
        'outer: while blocks.len() < block_count {
            let x: *mut u8 = match &self.shared_mem.0 {
                Some(shared_mem) => mmap_shm(BASE_ADDR, BUFSIZE, shared_mem.into()),
                None => mmap(BASE_ADDR, BUFSIZE),
            };
            if x.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            debug!("phys(x) = {:p}", x.pfn()?);
            let pfns = (x, BUFSIZE).consec_pfns()?;
            (x, BUFSIZE).log_pfns(log::Level::Trace);
            let consecs = pfns.iter().enumerate().filter(|(_, range)| {
                (range.end - range.start).as_usize() == self.block_size().bytes()
            });
            let mut unmap_ranges = vec![];
            let mut prev_end = x;
            for (idx, _) in consecs {
                if blocks.len() >= block_count {
                    unmap_ranges.push((prev_end, unsafe { x.byte_add(BUFSIZE) }));
                    break;
                }
                let offset: usize = pfns
                    .iter()
                    .take(idx)
                    .map(|range| (range.end - range.start).as_usize())
                    .sum();
                let bank = DRAMAddr::from_virt(pfns[idx].start.into(), &self.mem_config).bank;
                //assert_eq!(bank, 0, "Base bank of 0x{:x} is not zero. The PFN allocation strategy only supports allocation of up to 4 MB (22 bit address alignment), but apparently, some bank bits are above bit 22 (or you found a bug).", pfns[idx].start);
                if bank != 0 {
                    debug!("Bank {} != 0, retrying...", bank);
                    unmap_ranges.push((prev_end, unsafe { x.byte_add(offset) }));
                    continue;
                }
                let start_ptr = unsafe { x.byte_add(offset as usize) };
                blocks.push(Memory::new(start_ptr, self.block_size().bytes()));
                unmap_ranges.push((prev_end, start_ptr));
                prev_end = unsafe { start_ptr.byte_add(self.block_size().bytes()) };
            }
            if blocks.len() < block_count {
                debug!("Not enough consecutive PFNs found, unmapping...");
                unsafe { munmap(x, BUFSIZE) };
                continue 'outer;
            }
            for unmap_range in unmap_ranges {
                unsafe {
                    libc::munmap(
                        unmap_range.0 as *mut c_void,
                        unmap_range.1 as usize - unmap_range.0 as usize,
                    );
                }
            }
        }
        unsafe { munmap(buf, low_order_bytes) };
        Ok(ConsecBlocks::new(blocks))
    }
}

fn get_normal_page_nums() -> Result<[u64; 11], ProcErr> {
    let zones = buddyinfo()?;
    let zone = zones
        .iter()
        .find(|z| z.zone().eq("Normal"))
        .expect("Zone 'Normal' not found in buddyinfo");
    Ok(*zone.free_areas())
}

fn low_order_bytes(blocks: &[i64; 11], max_order: usize) -> usize {
    if max_order > 10 {
        panic!("Invalid order");
    }
    let mut bytes = 0;
    for (i, block) in blocks.iter().enumerate().take(max_order + 1) {
        bytes += *block as usize * (1 << i) * PAGE_SIZE;
    }
    bytes
}

impl From<Option<String>> for SharedMem {
    fn from(value: Option<String>) -> Self {
        SharedMem(value)
    }
}
