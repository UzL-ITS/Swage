use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Defines which physical address bits are used for DRAM mapping.
///
/// Can specify a single bit or multiple bits for row/column/bank functions.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum BitDef {
    /// Single bit function
    Single(u64),
    // XOR of multiple bits
    Multi(Vec<u64>),
}

impl BitDef {
    /// Converts bit definition to a bitmask.
    ///
    /// # Returns
    ///
    /// Bitmask with bits set at the specified positions
    pub fn to_bitstr(&self) -> usize {
        let mut res: usize = 0;
        match self {
            BitDef::Single(bit) => {
                res |= 1 << bit;
            }
            BitDef::Multi(bits) => {
                bits.iter().for_each(|bit| {
                    res |= 1 << bit;
                });
            }
        }
        res
    }
}

/// Errors that can occur when loading Blacksmith configuration.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
}

/// Result type for BlacksmithConfig constructor.
pub type Result<T> = std::result::Result<T, Error>;

/// Blacksmith configuration specifying DRAM geometry and parameters.
///
/// Loaded from JSON files containing DRAM addressing bit functions.
#[derive(Deserialize)]
pub struct BlacksmithConfig {
    //name: String,
    //channels: u64,
    //dimms: u64,
    //ranks: u64,
    //total_banks: u64,
    //max_rows: u64,
    /// Timing threshold for bank conflict detection (in CPU cycles)
    pub threshold: u64,
    //hammer_rounds: usize,
    //drama_rounds: usize,
    //acts_per_trefi: u64,
    /// Physical address bits used for DRAM row selection
    pub row_bits: Vec<BitDef>,
    /// Physical address bits used for DRAM column selection
    pub col_bits: Vec<BitDef>,
    /// Physical address bits used for DRAM bank selection
    pub bank_bits: Vec<BitDef>,
}

impl BlacksmithConfig {
    /// Loads configuration from a JSON file.
    ///
    /// # Arguments
    ///
    /// * `filepath` - Path to the JSON configuration file
    ///
    /// # Errors
    ///
    /// Returns error if file cannot be read or parsed
    pub fn from_jsonfile(filepath: &str) -> Result<BlacksmithConfig> {
        let mut file = File::open(Path::new(filepath))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: BlacksmithConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_bank_function_period() {
        use crate::FromBitDefs;
        use crate::blacksmith_config::BlacksmithConfig;
        use swage_core::memory::MemConfiguration;
        let config = BlacksmithConfig::from_jsonfile("config/bs-config.json")
            .expect("failed to read config file");
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        assert_eq!(mem_config.bank_function_period(), 512);
    }
}
