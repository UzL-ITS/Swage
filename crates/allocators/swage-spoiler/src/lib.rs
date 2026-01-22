//! SPOILER attack-based memory allocator.
//!
//! This crate implements memory allocation using the SPOILER attack technique,
//! which leverages timing side-channels to infer physical address information
//! and obtain consecutive physical memory blocks.
//!
//! Implements the [`swage_core::allocator::ConsecAllocator`] trait.
//!
//! # References
//!
//! Based on the SPOILER attack: <https://arxiv.org/abs/1903.00446>
//!
//! # Features
//!
//! - `spoiler_dump` - Enable memory dump functionality for debugging

#![warn(missing_docs)]

mod spoiler;

pub use spoiler::ConflictThreshold;
pub use spoiler::Spoiler;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
