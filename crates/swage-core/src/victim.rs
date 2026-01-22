//! Victim orchestration for Rowhammer attacks.
//!
//! This module provides the infrastructure for managing victim applications or memory
//! regions that are targeted by Rowhammer attacks. A victim can be:
//! - A memory region checked for bit flips ([`MemCheck`](crate::MemCheck))
//! - A process or application being attacked
//! - Other custom victim implementations
//!
//! The [`VictimOrchestrator`] trait defines the lifecycle and interface for all victims.

use crate::memory::BitFlip;
use crate::memory::FlippyPage;
use crate::memory::LinuxPageMapError;
use core::panic;
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur during victim operations.
#[derive(Error, Debug)]
pub enum HammerVictimError {
    /// No bit flips were detected during the check operation.
    #[error("No flips detected")]
    NoFlips,
    /// An I/O error occurred during victim operations.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    /// The victim is not currently running.
    #[error("Victim is not running")]
    NotRunning,
    /// Failed to construct the victim with the given configuration.
    #[error("Failed to construct victim: {0}")]
    ConstructionError(Box<dyn std::error::Error>),
    /// The expected flippy page was not found.
    #[error("Flippy page not found")]
    FlippyPageNotFound,
    /// The flippy page offset does not match the expected value.
    #[error("Flippy page offset mismatch: expected {expected}, actual {actual:?}")]
    FlippyPageOffsetMismatch {
        /// Expected page offset
        expected: usize,
        /// Actual flippy page information
        actual: FlippyPage,
    },
    /// An error occurred while accessing Linux pagemap.
    #[error(transparent)]
    LinuxPageMapError(#[from] LinuxPageMapError),
    /// A protocol-level error occurred in victim communication.
    #[error("Protocol Error: {0}")]
    ProtocolError(String),
}

/// Result type returned by victim check operations.
///
/// This enum represents the different types of results that can be returned
/// when checking if a Rowhammer attack was successful.
#[derive(Debug, Serialize)]
pub enum VictimResult {
    /// One or more bit flips were detected at specific memory locations.
    BitFlips(Vec<BitFlip>),
    /// A string result describing the attack outcome.
    String(String),
    /// Multiple string results describing attack outcome.
    Strings(Vec<String>),
    /// No meaningful result to report.
    Nothing,
}

impl VictimResult {
    /// Extracts the bit flips from this result.
    ///
    /// # Panics
    ///
    /// Panics if this result is not the `BitFlips` variant.
    pub fn bit_flips(self) -> Vec<BitFlip> {
        match self {
            VictimResult::BitFlips(flips) => flips,
            _ => panic!("Invalid variant. Expected BitFlips, got {:?}", self),
        }
    }
}

/// Trait for orchestrating victim applications or memory regions targeted by Rowhammer attacks.
///
/// Implementors of this trait define how to initialize, monitor, and check victim
/// memory regions or processes for the effects of Rowhammer attacks (e.g., bit flips).
/// The trait provides a lifecycle for victim management: start, initialize, check, and stop.
///
/// # Lifecycle
///
/// The typical victim lifecycle is:
/// 1. [`start()`](VictimOrchestrator::start) - Initialize victim resources (called once)
/// 2. [`init()`](VictimOrchestrator::init) - Prepare victim state before hammering
/// 3. Hammering occurs (external to victim)
/// 4. [`check()`](VictimOrchestrator::check) - Verify if attack succeeded
/// 5. [`stop()`](VictimOrchestrator::stop) - Clean up victim resources
///
/// Steps 2-4 may be repeated multiple times between start and stop.
///
/// # Examples
///
/// See `swage-victim-dev-memcheck` or the [`MemCheck`](crate::MemCheck) implementation
/// for concrete usage examples.
pub trait VictimOrchestrator {
    /// Starts the victim and allocates required resources.
    ///
    /// This method is called once at the beginning of an experiment to set up
    /// the victim environment. It may involve starting processes, mapping memory,
    /// or establishing communication channels.
    ///
    /// # Errors
    ///
    /// Returns [`HammerVictimError`] if initialization fails.
    fn start(&mut self) -> Result<(), HammerVictimError>;

    /// Initializes the victim state before a hammering round.
    ///
    /// This method is called before each hammering operation to prepare the
    /// victim memory or process to a known state. For memory-based victims,
    /// this typically involves writing specific patterns to memory.
    /// For process-based victims, this might involve triggering an operation
    /// or sending a signal to the victim process.
    fn init(&mut self);

    /// Checks if the hammering attack was successful.
    ///
    /// This method examines the victim to detect any effects of the Rowhammer
    /// attack, typically by checking for bit flips in memory or unexpected
    /// behavior in victim processes.
    ///
    /// # Returns
    ///
    /// Returns `Ok(VictimResult)` with attack results if effects are detected,
    /// or [`HammerVictimError::NoFlips`] if no effects are found.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * No bit flips or effects are detected ([`HammerVictimError::NoFlips`])
    /// * I/O operations fail
    /// * The victim is not in a valid state
    fn check(&mut self) -> Result<VictimResult, HammerVictimError>;

    /// Stops the victim and releases resources.
    ///
    /// This method is called at the end of an experiment to clean up the victim
    /// environment, stop processes, and release any allocated resources.
    fn stop(&mut self);

    /// Optionally serializes victim-specific data to JSON.
    ///
    /// This method allows victims to provide additional metadata or state
    /// information that can be included in experiment results.
    ///
    /// # Returns
    ///
    /// Returns `Some(Value)` with serialized data, or `None` if no additional
    /// data is available.
    fn serialize(&self) -> Option<serde_json::Value> {
        None
    }
}
