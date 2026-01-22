//! Hugepage-based memory allocator for Rowhammer attacks.
//!
//! This crate provides allocators that use Linux hugepages (1GB pages) to obtain
//! physically consecutive memory blocks. Hugepages must be configured at boot time
//! via kernel parameters.
//!
//! Implements the [`swage_core::allocator::ConsecAllocator`] trait.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux with 1GB hugepage support
//! - Hugepages must be pre-allocated via kernel boot parameters or runtime configuration
//! - Mounted hugepagefs at `/dev/hugepages`

#![warn(missing_docs)]

mod hugepage;
mod hugepage_rnd;

pub use hugepage::*;
pub use hugepage_rnd::*;
