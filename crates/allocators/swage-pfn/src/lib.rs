//! PFN-based memory allocator.
//!
//! This crate provides a memory allocator that obtains consecutive physical frame
//! numbers (PFNs) by allocating memory and checking `/proc/self/pagemap` to verify
//! physical contiguity. Optionally uses shared memory for allocation.
//!
//! Implements the [`swage_core::allocator::ConsecAllocator`] trait.
//!
//! # Use Cases
//!
//! Primarily useful for testing and development where other allocators are unavailable.

#![warn(missing_docs)]

mod pfn;

pub use pfn::Pfn;
pub use pfn::SharedMem;
