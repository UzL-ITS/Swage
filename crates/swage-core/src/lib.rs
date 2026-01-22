//! # Swage Core
//!
//! `swage-core` is the foundational library for the Swage Rowhammer attack framework.
//! It provides a modular, trait-based architecture that enables composable implementations
//! of memory allocation strategies, hammering techniques, and victim orchestration.
//!
//! ## Architecture Overview
//!
//! The framework is built around three core traits that define the interface for
//! each component:
//!
//! - [`allocator::ConsecAllocator`] - Defines memory allocation strategies for obtaining
//!   consecutive physical memory blocks required for Rowhammer attacks.
//!
//! - [`hammerer::Hammering`] - Defines the interface for different hammering implementations
//!   that perform the actual memory access patterns to trigger bit flips.
//!
//! - [`victim::VictimOrchestrator`] - Defines the interface for victim applications or
//!   memory regions that are targeted by the attack and checked for bit flips.
//!
//! ## Main Components
//!
//! - [`Swage`] - The main orchestrator that combines an allocator, hammerer, and victim
//!   to execute complete Rowhammer experiments with profiling and reproducibility checks.
//!
//! - [`memory`] module - Provides memory management abstractions including [`memory::Memory`],
//!   [`memory::ConsecBlocks`], and various traits for memory initialization and checking.
//!
//! - [`util`] module - Contains utility types and functions including [`util::Size`]
//!   for memory size representations and various helper traits.
//!
//! ## Platform Support
//!
//! This framework is designed for x86_64 Linux systems with access to physical memory
//! information through `/proc/self/pagemap` and related interfaces. Some operations and modules
//! require elevated privileges (root access) or custom kernel modules.

#![warn(missing_docs)]

pub mod allocator;
pub mod hammerer;
mod mem_check;
pub mod memory;
pub mod page_inject;
mod swage;
pub mod util;
pub mod victim;

pub use crate::mem_check::HammerVictimTargetCheck;
pub use crate::mem_check::{ExcludeFromInit, MemCheck};

pub use swage::{DataPatternKind, ExperimentData, RoundProfile, Swage, SwageConfig};
