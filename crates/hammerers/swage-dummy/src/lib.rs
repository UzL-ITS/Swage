//! Dummy hammerer for testing.
//!
//! This crate provides a simple hammerer implementation that flips bits at specified
//! addresses without performing actual Rowhammer attacks. Useful for testing the
//! framework pipeline.
//!
//! Implements the [`swage_core::hammerer::Hammering`] trait.
//!
//! # Use Cases
//!
//! - Integration testing of the Swage framework
//! - Simulating bit flips without hardware access

#![warn(missing_docs)]

mod dummy;

pub use dummy::{Dummy, FlipAddr};
