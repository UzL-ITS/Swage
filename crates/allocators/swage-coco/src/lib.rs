//! CoCo memory allocator.
//!
//! This crate provides a memory allocator that uses a custom kernel module
//! for obtaining consecutive physical memory.
//!
//! Implements the [`swage_core::allocator::ConsecAllocator`] trait.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux
//! - Custom `/dev/coco_dec_mem` kernel module must be loaded

#![warn(missing_docs)]

mod coco;

pub use coco::CoCo;
