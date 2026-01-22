//! Blacksmith fuzzing-based Rowhammer hammerer.
//!
//! This crate implements the Blacksmith hammering framework for systematic Rowhammer
//! attacks. It reads hammering patterns from previous Blacksmith runs and repeats the hammering
//! similar to the original Blacksmith implementation.
//!
//! Implements the [`swage_core::hammerer::Hammering`] trait.
//!
//! # Configuration
//!
//! Requires a JSON configuration file specifying DRAM addressing parameters including
//! row bits, column bits, and bank bits. See [`BlacksmithConfig`] for details.
//!
//! # References
//!
//! Based on: Jattke et al., "Blacksmith: Scalable Rowhammering in the Frequency Domain",
//! IEEE S&P 2022.
//!
//! # Features
//!
//! - `jitter_dump` - Enable jitter measurement dumping for analysis
//! - `iperf` - Enable iPerf performance measurements

#![warn(missing_docs)]

mod blacksmith_config;
mod hammerer;
mod jitter;

pub use blacksmith_config::*;
pub use hammerer::*;

use nalgebra::SMatrix;
use swage_core::memory::{MTX_SIZE, MemConfiguration};

/// Trait to build from a BlacksmithConfig
pub trait FromBlacksmithConfig {
    /// Build from a BlacksmithConfig
    fn from_blacksmith(config: &BlacksmithConfig) -> Self;
}

/// Trait to build from vectors of `BitDefs`
pub trait FromBitDefs {
    /// Build from vectors of `BitDefs`
    fn from_bitdefs(bank_bits: Vec<BitDef>, row_bits: Vec<BitDef>, col_bits: Vec<BitDef>) -> Self;
}

impl FromBlacksmithConfig for MemConfiguration {
    fn from_blacksmith(config: &BlacksmithConfig) -> Self {
        MemConfiguration::from_bitdefs(
            config.bank_bits.clone(),
            config.row_bits.clone(),
            config.col_bits.clone(),
        )
    }
}

impl FromBitDefs for MemConfiguration {
    fn from_bitdefs(bank_bits: Vec<BitDef>, row_bits: Vec<BitDef>, col_bits: Vec<BitDef>) -> Self {
        let mut out = MemConfiguration::default();
        let mut i = 0;

        assert_eq!(MTX_SIZE, bank_bits.len() + col_bits.len() + row_bits.len());

        out.bk_shift = MTX_SIZE - bank_bits.len();
        out.bk_mask = (1 << bank_bits.len()) - 1;
        out.col_shift = MTX_SIZE - bank_bits.len() - col_bits.len();
        out.col_mask = (1 << col_bits.len()) - 1;
        out.row_shift = MTX_SIZE - bank_bits.len() - col_bits.len() - row_bits.len();
        out.row_mask = (1 << row_bits.len()) - 1;
        out.max_bank_bit = bank_bits
            .iter()
            .map(|b| match b {
                BitDef::Single(bit) => *bit,
                BitDef::Multi(bits) => *bits.iter().max().unwrap(),
            })
            .max()
            .unwrap();

        // construct dram matrix
        let mut dram_mtx: [usize; MTX_SIZE] = [0; MTX_SIZE];
        let mut update_dram_mtx = |def: &BitDef| {
            dram_mtx[i] = def.to_bitstr();
            i += 1;
        };
        // bank
        bank_bits.iter().for_each(&mut update_dram_mtx);
        // col
        col_bits.iter().for_each(&mut update_dram_mtx);
        // row
        row_bits.iter().for_each(&mut update_dram_mtx);
        out.dram_mtx = dram_mtx;

        // construct addr matrix
        let mut addr_mtx: [usize; MTX_SIZE] = [0; MTX_SIZE];
        // create dram matrix in nalgebra
        let mut matrix = SMatrix::<u8, 30, 30>::zeros();
        for row in 0..MTX_SIZE {
            for col in 0..MTX_SIZE {
                matrix[(row, col)] = ((dram_mtx[row] >> (MTX_SIZE - col - 1)) & 1) as u8;
            }
        }
        // invert dram matrix, assign addr matrix
        let matrix_inv = matrix
            .cast::<f64>()
            .try_inverse()
            .expect("The matrix defined in the config file is not invertible.")
            .try_cast::<i8>()
            .expect("inverse cast to i8 failed")
            .map(|e| e.abs());

        for row in 0..MTX_SIZE {
            for col in 0..MTX_SIZE {
                if matrix_inv[(row, col)] != 0 && matrix_inv[(row, col)] != 1 {
                    panic!(
                        "expected element to be 0 or 1, got {}",
                        matrix_inv[(row, col)]
                    );
                }
                addr_mtx[row] |= (matrix_inv[(row, col)] as usize) << (MTX_SIZE - col - 1);
            }
        }
        out.addr_mtx = addr_mtx;
        out
    }
}
