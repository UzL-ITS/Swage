use log::debug;
use std::arch::x86_64::_mm_clflush;
use swage_core::hammerer::Hammering;
use thiserror::Error;

/// A memory address to flip.
#[derive(Clone, Copy)]
pub struct FlipAddr(*mut u8);

/// Dummy hammerer that directly flips bits in virtual addresses for testing.
///
/// Used to simulate bit flips without actual Rowhammer attacks.
pub struct Dummy {
    /// Address where bit should be flipped
    flip_addr: FlipAddr,
}

impl Dummy {
    /// Creates a new dummy hammerer targeting the specified address.
    pub fn new(flip_addr: FlipAddr) -> Self {
        Dummy { flip_addr }
    }
}

/// Error type that can never occur.
#[derive(Debug, Error)]
pub enum Never {}

impl Hammering for Dummy {
    type Error = Never;
    fn hammer(&self) -> Result<(), Self::Error> {
        unsafe {
            debug!(
                "Flip address 0x{:02X} from {} to {}",
                self.flip_addr.0 as usize, *self.flip_addr.0, !*self.flip_addr.0
            );
            *self.flip_addr.0 = !*self.flip_addr.0;
            _mm_clflush(self.flip_addr.0);
        }
        Ok(())
    }
}

impl From<*mut u8> for FlipAddr {
    fn from(value: *mut u8) -> Self {
        FlipAddr(value)
    }
}
