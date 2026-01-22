//! /dev/mem-based victim for bit flip verification.
//!
//! This crate provides a victim implementation that uses `/dev/mem` to directly
//! check physical memory locations for bit flips. It verifies whether specific
//! target addresses have been flipped during a Rowhammer attack. Requires root privileges.
//!
//! Implements the [`swage_core::victim::VictimOrchestrator`] trait.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux
//! - Root privileges for `/dev/mem` access
//! - Kernel must allow `/dev/mem` access
//!
//! # Use Cases
//!
//! - Precise verification of bit flips at known physical addresses
//! - Validation of Rowhammer attacks with specific targets
//! - Research requiring direct physical memory observation

#![warn(missing_docs)]

mod dev_mem_check;

pub use dev_mem_check::DevMemCheck;
