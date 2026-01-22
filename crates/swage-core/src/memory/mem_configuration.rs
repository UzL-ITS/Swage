use crate::util::ROW_SHIFT;
use serde::Deserialize;

/// Size of DRAM addressing matrices
pub const MTX_SIZE: usize = 30;

/// DRAM addressing configuration.
///
/// Defines how virtual addresses map to physical DRAM organization
/// (bank, row, column) using transformation matrices.
#[derive(Deserialize, Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct MemConfiguration {
    /// Bit shift for bank extraction
    pub bk_shift: usize,
    /// Bit mask for bank extraction
    pub bk_mask: usize,
    /// Bit shift for row extraction
    pub row_shift: usize,
    /// Bit mask for row extraction
    pub row_mask: usize,
    /// Bit shift for column extraction
    pub col_shift: usize,
    /// Bit mask for column extraction
    pub col_mask: usize,
    /// DRAM addressing matrix (virtual to DRAM)
    pub dram_mtx: [usize; MTX_SIZE],
    /// Address reconstruction matrix (DRAM to virtual)
    pub addr_mtx: [usize; MTX_SIZE],
    /// Maximum bank bit position
    pub max_bank_bit: u64,
}

impl MemConfiguration {
    /// Returns the periodicity of the bank function in rows.
    ///
    /// Indicates how many rows must be iterated before the bank function repeats.
    pub fn bank_function_period(&self) -> u64 {
        1 << (self.max_bank_bit + 1 - ROW_SHIFT as u64)
    }
}

impl MemConfiguration {
    /// Returns the number of banks in this DRAM configuration.
    pub fn get_bank_count(&self) -> usize {
        (1 << self.bk_mask.count_ones()) as usize
    }

    /// Returns the number of rows in this DRAM configuration.
    pub fn get_row_count(&self) -> usize {
        1_usize << (self.row_mask.count_ones() as usize)
    }
}
