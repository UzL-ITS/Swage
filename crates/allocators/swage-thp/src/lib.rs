//! Transparent Huge Pages (THP) memory allocator.
//!
//! This crate provides a memory allocator that uses Linux Transparent Huge Pages
//! to obtain 2MB physically contiguous memory blocks. THP must be enabled in the
//! kernel configuration.
//!
//! Implements the [`swage_core::allocator::ConsecAllocator`] trait.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux with THP support enabled
//! - THP should be set to "always" or "madvise" mode

#![warn(missing_docs)]

use std::ptr::null_mut;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::max;
use log::{debug, log_enabled, warn};
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{
    ConsecBlocks, GetConsecPfns, PfnResolver, TimerError, construct_memory_tuple_timer,
};
use swage_core::util::Size::MB;
use swage_core::util::{NamedProgress, Size};
use swage_core::{memory::Memory, util::PAGE_SIZE};
use thiserror::Error;

/// THP allocator. This allocator uses Linux Transparent Huge Pages to obtain 2MB physically contiguous memory blocks.
pub struct THP {
    conflict_threshold: u64,
    progress: Option<MultiProgress>,
}

impl THP {
    /// Constructor for THP allocator
    pub fn new(conflict_threshold: u64, progress: Option<MultiProgress>) -> Self {
        THP {
            conflict_threshold,
            progress,
        }
    }
}

const ALIGN_SIZE: Size = MB(2);

impl THP {
    /// allocate a 2 MB physically aligned memory block.
    fn allocate_2m_aligned(size: Size) -> Result<Memory, std::io::Error> {
        let aligned = unsafe {
            libc::mmap(
                null_mut(),
                size.bytes(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if aligned == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::memset(aligned, 0, size.bytes()) };
        if unsafe { libc::madvise(aligned, size.bytes(), libc::MADV_COLLAPSE) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { libc::mlock(aligned, PAGE_SIZE) };
        if log_enabled!(log::Level::Debug)
            && let Ok(consecs) = (aligned, size.bytes()).consec_pfns()
        {
            debug!("Aligned PFNs: {:?}", consecs);
        }
        assert_eq!(aligned as usize & (ALIGN_SIZE.bytes() - 1), 0);
        assert_eq!(
            aligned.pfn().unwrap_or_default().as_usize() & (ALIGN_SIZE.bytes() - 1),
            0
        );
        Ok(Memory::new(aligned as *mut u8, size.bytes()))
    }
}

/// Errors that can happen during THP allocation
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    TimerError(#[from] TimerError),
    #[error("Size must be a multiple of {0}")]
    SizeError(Size),
}

impl ConsecAllocator for THP {
    type Error = Error;

    fn block_size(&self) -> swage_core::util::Size {
        Size::GB(1)
    }

    fn alloc_consec_blocks(
        &mut self,
        size: swage_core::util::Size,
    ) -> Result<swage_core::memory::ConsecBlocks, Self::Error> {
        if size.bytes() == 0 || !size.bytes().is_multiple_of(ALIGN_SIZE.bytes()) {
            return Err(Error::SizeError(ALIGN_SIZE));
        }
        let mut blocks: Vec<Memory> = vec![];
        let required_blocks =
            max([size.bytes() / self.block_size().bytes(), 1]).expect("empty iter");
        let timer = construct_memory_tuple_timer()?;
        let p = self.progress.as_ref().map(|p| {
            p.add(
                ProgressBar::new(required_blocks as u64)
                    .with_style(ProgressStyle::named_bar("Allocating blocks")),
            )
        });
        let mut garbage = vec![];
        while blocks.len() < required_blocks {
            let block = Self::allocate_2m_aligned(size)?;

            // check for same bank
            if let Some(last_block) = blocks.last() {
                let timing = unsafe {
                    timer.time_subsequent_access_from_ram(block.ptr, last_block.ptr, 10000)
                };
                let same_bank = timing >= self.conflict_threshold;
                if !same_bank {
                    warn!(
                        "Bank check failed: {} < {} for blocks {:?} and {:?}",
                        timing, self.conflict_threshold, block, last_block
                    );
                    block.log_pfns(log::Level::Warn);
                    last_block.log_pfns(log::Level::Warn);
                    garbage.push(block);
                    continue;
                }
            }
            if let Some(p) = &p {
                p.inc(1);
            }
            blocks.push(block);
        }
        for block in garbage {
            block.dealloc();
        }
        Ok(ConsecBlocks::new(blocks))
    }
}
