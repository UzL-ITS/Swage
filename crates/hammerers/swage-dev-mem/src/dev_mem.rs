use log::info;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

use rand::Rng;
use std::thread;
use std::time::Duration;
use swage_core::hammerer::Hammering;
use swage_core::memory::{FlipDirection, PhysAddr};

/// A bit position within a byte (0-7).
#[derive(Clone, Copy)]
pub struct Bit(usize);

/// Hammerer that uses /dev/mem to directly flip bits.
///
/// Simulates bit flips by writing to physical memory through /dev/mem.
pub struct DevMem {
    /// Physical address to target
    phys_addr: PhysAddr,
    /// Bit position to flip
    bit: Bit,
    /// Direction of the bit flip
    direction: FlipDirection,
}

impl DevMem {
    /// Creates a new /dev/mem hammerer.
    ///
    /// # Arguments
    ///
    /// * `phys_addr` - Physical address to target
    /// * `bit` - Bit position (0-7) to flip
    /// * `direction` - Flip direction (0→1, 1→0, or any)
    pub fn new(phys_addr: PhysAddr, bit: Bit, direction: FlipDirection) -> Self {
        assert!(bit.0 < 8);
        Self {
            phys_addr,
            bit,
            direction,
        }
    }
}

impl Hammering for DevMem {
    type Error = std::io::Error;
    fn hammer(&self) -> Result<(), Self::Error> {
        let mut dev_mem = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
        let mut value = [0u8; 1];
        dev_mem.seek(SeekFrom::Start(self.phys_addr.as_usize() as u64))?;
        // sleep for a random duration to simulate real hammering conditions
        thread::sleep(Duration::from_millis(rand::rng().random_range(1000..7000)));
        dev_mem.read_exact(&mut value)?;
        let new_value = match self.direction {
            FlipDirection::ZeroToOne => [value[0] | (1 << self.bit.0)],
            FlipDirection::OneToZero => [value[0] & !(1 << self.bit.0)],
            FlipDirection::Any => [value[0] ^ (1 << self.bit.0)],
            FlipDirection::None | FlipDirection::Multiple(_) => {
                unimplemented!("FlipDirection::None and ::Multiple not implemented")
            }
        };
        if new_value != value {
            info!(
                "Flipping address {:p} from {} to {}",
                self.phys_addr, value[0], new_value[0],
            );
            dev_mem.seek(SeekFrom::Current(-1))?;
            dev_mem.write_all(&new_value)?;
            dev_mem.flush()?;
        }
        Ok(())
    }
}

impl From<usize> for Bit {
    fn from(value: usize) -> Self {
        Bit(value)
    }
}
