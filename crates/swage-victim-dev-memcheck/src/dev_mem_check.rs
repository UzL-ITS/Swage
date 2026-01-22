use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE, mmap, munmap,
};
use log::debug;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ptr;
use swage_core::memory::{BitFlip, LinuxPageMapError, PfnResolver, PhysAddr};
use swage_core::util::{PAGE_MASK, PAGE_SIZE};
use swage_core::victim::{HammerVictimError, VictimOrchestrator, VictimResult};
use thiserror::Error;

/// Victim that verifies bit flips using /dev/mem.
///
/// Reads physical memory directly to detect if hammering induced bit flips.
#[derive(Serialize)]
pub struct DevMemCheck {
    #[serde(skip_serializing)]
    targets: Vec<(BitFlip, PhysAddr)>,
}

/// Errors that can occur during /dev/mem victim operations.
#[derive(Debug, Error)]
pub enum DevMemCheckError {
    #[error(transparent)]
    LinuxPageMapError(#[from] LinuxPageMapError),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DevMemCheckError>;

impl DevMemCheck {
    /// Creates a new /dev/mem victim from target bit flips.
    ///
    /// # Arguments
    ///
    /// * `targets` - Expected bit flip locations
    ///
    /// # Errors
    ///
    /// Returns error if physical addresses cannot be resolved
    pub fn new(targets: Vec<BitFlip>) -> Result<Self> {
        Ok(DevMemCheck {
            targets: targets
                .into_iter()
                .map(|target| {
                    (target.addr as *const u8)
                        .pfn()
                        .map(|pfn| (target, pfn))
                        .map_err(|e| e.into())
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn write_dev_mem(addr: PhysAddr, value: u8) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open("/dev/mem")?;
    file.seek(SeekFrom::Start(addr.as_usize() as u64))?;
    file.write_all(&[value])?;
    Ok(())
}

fn read_dev_mem(addr: PhysAddr) -> Result<u8> {
    let mut file = File::open("/dev/mem")?;
    file.seek(SeekFrom::Start(addr.as_usize() as u64))?;
    let mut buffer = [0u8; 1];
    file.read_exact(&mut buffer)?;
    Ok(buffer[0])
}

impl VictimOrchestrator for DevMemCheck {
    fn start(&mut self) -> std::result::Result<(), HammerVictimError> {
        let num_pages = 20;
        let length = PAGE_SIZE * num_pages;

        unsafe {
            let addr = mmap(
                ptr::null_mut(),
                length,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if addr == MAP_FAILED {
                return Err(std::io::Error::last_os_error().into());
            }

            for (target, _) in &self.targets {
                debug!("munmap target: {:?}", target);
                munmap((target.addr & !(PAGE_MASK)) as *mut libc::c_void, PAGE_SIZE);
            }
            if munmap(addr, length) != 0 {
                return Err(HammerVictimError::IoError(std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }

    fn init(&mut self) {
        for (target, phys_addr) in &self.targets {
            write_dev_mem(*phys_addr, target.data).expect("Write failed");
            let byte = read_dev_mem(*phys_addr).expect("Read failed");
            assert_eq!(byte, target.data, "Target byte is not as expected");
        }
    }

    fn check(&mut self) -> std::result::Result<VictimResult, HammerVictimError> {
        let flips = self
            .targets
            .iter()
            .filter_map(|(target, phys_addr)| {
                let byte = match read_dev_mem(*phys_addr) {
                    Ok(byte) => byte,
                    Err(e) => return Some(Err(e.into())),
                };

                if byte != target.data {
                    // if actual value is not equal to the expected value
                    Some(Ok(BitFlip::new(
                        (*phys_addr).into(),
                        byte ^ target.data,
                        target.data,
                    )))
                } else {
                    None
                }
            })
            .collect::<std::result::Result<Vec<_>, HammerVictimError>>()?;
        if flips.is_empty() {
            Err(HammerVictimError::NoFlips)
        } else {
            Ok(VictimResult::BitFlips(flips))
        }
    }

    fn stop(&mut self) {}
}

impl From<DevMemCheckError> for HammerVictimError {
    fn from(value: DevMemCheckError) -> Self {
        match value {
            DevMemCheckError::LinuxPageMapError(e) => e.into(),
            DevMemCheckError::IoError(e) => e.into(),
        }
    }
}
