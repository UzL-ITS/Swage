//! Rowhammer hammering traits.
//!
//! This module defines the [`Hammering`] trait that all hammering implementations must implement
//! to perform memory access patterns that induce bit flips through the Rowhammer effect.

/// Trait for implementing Rowhammer hammering techniques.
///
/// Implementors of this trait define different strategies for performing memory
/// hammering operations that attempt to induce bit flips in adjacent DRAM rows.
/// The hammering pattern, timing, and access strategy are implementation-specific.
///
/// # Associated Types
///
/// * `Error` - The error type returned by hammering operations. Must implement [`std::error::Error`].
///
/// # Required Methods
///
/// Implementors must provide:
/// * [`hammer()`](Hammering::hammer) - Performs the hammering operation
///
/// # Examples
///
/// See individual hammerer implementations such as `swage-blacksmith`, `swage-dev-mem`,
/// or `swage-dummy` for concrete usage examples.
pub trait Hammering {
    /// The error type returned by hammering operations.
    type Error: std::error::Error;

    /// Performs the hammering operation.
    ///
    /// This method executes memory access patterns designed to induce bit flips
    /// in physically adjacent DRAM rows through the Rowhammer effect. The specific
    /// access pattern, number of accesses, and timing are determined by the
    /// implementation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the hammering operation completes successfully,
    /// or an error if the operation fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * Memory access fails
    /// * Required hardware interfaces are unavailable
    /// * The hammering operation is interrupted
    fn hammer(&self) -> Result<(), Self::Error>;
}
