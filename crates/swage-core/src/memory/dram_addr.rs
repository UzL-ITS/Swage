use crate::memory::AggressorPtr;
use crate::memory::MemConfiguration;
use serde::Deserialize;
use std::fmt::{self, Display, Formatter};

/// DRAM address with bank, row, and column components.
///
/// Represents the physical organization of a memory address in DRAM,
/// decoded from a virtual/physical address using DRAM configuration.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DRAMAddr {
    /// Bank number
    pub bank: usize,
    /// Row number
    pub row: usize,
    /// Column number
    pub col: usize,
}

impl Display for DRAMAddr {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "({}, {}, {})", self.bank, self.row, self.col)
    }
}

impl DRAMAddr {
    /// Creates a new DRAM address.
    ///
    /// # Arguments
    ///
    /// * `bank` - Bank number
    /// * `row` - Row number
    /// * `col` - Column number
    pub fn new(bank: usize, row: usize, col: usize) -> Self {
        DRAMAddr { bank, row, col }
    }

    /// Decodes a virtual address into DRAM components.
    ///
    /// Uses the memory configuration to map from virtual address to
    /// bank/row/column organization.
    ///
    /// # Arguments
    ///
    /// * `addr` - Virtual address pointer
    /// * `mem_config` - DRAM addressing configuration
    pub fn from_virt(addr: AggressorPtr, mem_config: &MemConfiguration) -> DRAMAddr {
        let p = addr as usize;
        let mut res = 0;

        for &i in mem_config.dram_mtx.iter() {
            res <<= 1;
            res |= (p & i).count_ones() as usize & 1;
        }
        let bank = (res >> mem_config.bk_shift) & mem_config.bk_mask;
        let row = (res >> mem_config.row_shift) & mem_config.row_mask;
        let col = (res >> mem_config.col_shift) & mem_config.col_mask;

        DRAMAddr { bank, row, col }
    }

    /// Construct a DRAMAddr from a virtual address with offset.
    ///
    /// # Safety
    /// The same safety consideration as discussed for *const T::offset apply.
    ///
    pub unsafe fn from_virt_offset(
        addr: AggressorPtr,
        offset: isize,
        mem_config: &MemConfiguration,
    ) -> DRAMAddr {
        let p = unsafe { addr.byte_offset(offset) };
        DRAMAddr::from_virt(p, mem_config)
    }
}

impl DRAMAddr {
    /// Linearizes DRAM address components into a single value.
    ///
    /// Combines bank, row, and column into a linearized address
    /// according to the memory configuration.
    pub fn linearize(&self, mem_config: MemConfiguration) -> usize {
        (self.bank << mem_config.bk_shift)
            | (self.row << mem_config.row_shift)
            | (self.col << mem_config.col_shift)
    }

    /// Converts DRAM address back to virtual address, assuming physically contiguous memory starting at `base_msb`
    ///
    /// # Arguments
    ///
    /// * `base_msb` - Base address for MSB bits
    /// * `mem_config` - DRAM addressing configuration
    pub fn to_virt(&self, base_msb: AggressorPtr, mem_config: MemConfiguration) -> AggressorPtr {
        let mut res = 0;
        let l = self.linearize(mem_config);
        for &i in mem_config.addr_mtx.iter() {
            res <<= 1;
            res |= (l & i).count_ones() as usize % 2;
        }
        let base_msb_usize = (base_msb as usize) & !((1 << 30) - 1);
        (base_msb_usize | res) as AggressorPtr
    }
}

impl DRAMAddr {
    /// Adds offsets to each DRAM address component.
    ///
    /// # Arguments
    ///
    /// * `bank` - Bank offset to add
    /// * `row` - Row offset to add
    /// * `col` - Column offset to add
    pub fn add(&self, bank: usize, row: usize, col: usize) -> DRAMAddr {
        DRAMAddr {
            bank: self.bank + bank,
            row: self.row + row,
            col: self.col + col,
        }
    }

    /// Subtracts offsets from each DRAM address component.
    ///
    /// # Arguments
    ///
    /// * `bank` - Bank offset to subtract
    /// * `row` - Row offset to subtract
    /// * `col` - Column offset to subtract
    pub fn sub(&self, bank: usize, row: usize, col: usize) -> DRAMAddr {
        DRAMAddr {
            bank: self.bank - bank,
            row: self.row - row,
            col: self.col - col,
        }
    }
}
