use crate::memory::{BitFlip, Checkable, ConsecBlocks, DataPattern, Initializable};
use crate::victim::VictimOrchestrator;
use log::debug;
use serde::Serialize;
use std::arch::x86_64::_mm_clflush;

use crate::victim::{HammerVictimError, VictimResult};

/// List of page addresses to exclude from initialization.
///
/// Used to prevent writing victim pages when initializing memory, which potentially causes
/// segmentation faults.
#[derive(Clone)]
pub struct ExcludeFromInit(Vec<*const u8>);

/// Memory-checking victim implementation.
///
/// Checks memory for bit flips by comparing against an expected data pattern.
/// Implements [`VictimOrchestrator`] to integrate with the Swage framework.
#[derive(Serialize)]
pub struct MemCheck {
    #[serde(skip_serializing)]
    memory: ConsecBlocks,
    /// The expected data pattern to check against
    pub pattern: DataPattern,
    #[serde(skip_serializing)]
    excluding: ExcludeFromInit,
}

impl MemCheck {
    /// Creates a new memory-checking victim.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory region to monitor
    /// * `pattern` - Expected data pattern
    /// * `excluding` - Pages to exclude from initialization
    pub fn new(memory: ConsecBlocks, pattern: DataPattern, excluding: ExcludeFromInit) -> Self {
        Self {
            memory,
            pattern,
            excluding,
        }
    }
}

impl VictimOrchestrator for MemCheck {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        Ok(())
    }

    fn init(&mut self) {
        debug!("initialize victim");
        self.memory
            .initialize_excluding(self.pattern.clone(), &self.excluding.0);
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        debug!("check victim");
        let flips = self
            .memory
            .check_excluding(self.pattern.clone(), &self.excluding.0);
        if !flips.is_empty() {
            Ok(VictimResult::BitFlips(flips.clone()))
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(&mut self) {}
}

/// Target-specific bit flip checker.
///
/// Verifies that specific target bit flips occur at expected locations.
/// Useful for validating attack precision.
#[derive(Serialize)]
pub struct HammerVictimTargetCheck {
    #[serde(skip_serializing)]
    memory: ConsecBlocks,
    pattern: DataPattern,
    targets: Vec<BitFlip>,
}

impl HammerVictimTargetCheck {
    /// Creates a new target-checking victim.
    ///
    /// # Arguments
    ///
    /// * `memory` - The memory region containing targets
    /// * `pattern` - Expected data pattern
    /// * `targets` - Specific bit flips expected to occur
    pub fn new(memory: ConsecBlocks, pattern: DataPattern, targets: Vec<BitFlip>) -> Self {
        HammerVictimTargetCheck {
            memory,
            pattern,
            targets,
        }
    }
}

impl VictimOrchestrator for HammerVictimTargetCheck {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        Ok(())
    }

    fn init(&mut self) {
        debug!("initialize victim");
        self.memory.initialize(self.pattern.clone());
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        debug!("check victim");
        let mut flips = vec![];
        for target in &self.targets {
            let value = unsafe {
                _mm_clflush(target.addr as *const u8);
                std::ptr::read_volatile(target.addr as *const u8)
            };
            if value != target.data {
                let bitmask = target.data ^ value;
                flips.push(BitFlip::new(target.addr as *const u8, bitmask, target.data))
            }
        }
        if !flips.is_empty() {
            Ok(VictimResult::BitFlips(flips))
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(&mut self) {}
}

impl From<Vec<*const u8>> for ExcludeFromInit {
    fn from(value: Vec<*const u8>) -> Self {
        ExcludeFromInit(value)
    }
}
