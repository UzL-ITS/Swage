use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use log::{Level, debug, info, log_enabled, trace};
use pagemap2::{MapsEntry, PageMapError};

use crate::memory::pagemap_info::PageMapInfo;
use crate::util::{PAGE_SHIFT, PAGE_SIZE};

use super::PhysAddr;

/// Information about a page that may have flipped bits.
///
/// Contains mapping information for a physical page that is being
/// targeted or monitored for bit flips.
#[derive(Debug)]
pub struct FlippyPage {
    /// Memory mapping entry from /proc/pid/maps
    #[allow(dead_code)]
    pub maps_entry: MapsEntry,
    /// Page offset within the mapped region
    #[allow(dead_code)]
    pub region_offset: usize,
}

/// Finds a target (flippy) page in a victim process.
///
/// Searches through process memory mappings to locate the virtual address
/// corresponding to a target physical page.
///
/// # Arguments
///
/// * `target_page` - Target physical address
/// * `pid` - Process ID to search
///
/// # Errors
///
/// Returns an error if reading pagemap fails.
pub fn find_flippy_page(
    target_page: PhysAddr,
    pid: u32,
) -> Result<Option<FlippyPage>, PageMapError> {
    let pmap = PageMapInfo::load(pid as u64)?.0;
    let mut flippy_region = None;
    for (map, pagemap) in pmap {
        for (idx, (va, pmap)) in pagemap.iter().enumerate() {
            let pfn = pmap.pfn();
            match pfn {
                Ok(pfn) => {
                    if target_page.as_usize() >> PAGE_SHIFT == pfn as usize {
                        flippy_region = Some(FlippyPage {
                            maps_entry: map.0.clone(),
                            region_offset: idx,
                        });
                        info!("Region: {:?}", map.0);
                        debug!("Region size: {}", map.0.vma().size());
                        info!("[{}]  {:#x}    {:#x} [REUSED TARGET PAGE]", idx, va, pfn);
                        if log_enabled!(Level::Trace)
                            && let Some("[stack]") = map.0.path()
                        {
                            let mut stack_contents = String::new();
                            let contents = read_memory_from_proc(pid, *va, PAGE_SIZE as u64);
                            match contents {
                                Ok(contents) => {
                                    for (i, byte) in contents.iter().enumerate() {
                                        stack_contents += &format!("{:02x}", byte);
                                        if i % 8 == 7 {
                                            stack_contents += " ";
                                        }
                                        if i % 64 == 63 {
                                            stack_contents += "\n";
                                        }
                                    }
                                    trace!("Content:\n{}", stack_contents);
                                }
                                Err(e) => {
                                    info!("Failed to read stack contents: {}", e);
                                }
                            }
                        }
                    } else {
                        //info!("[{}]  {:#x}    {:#x}", idx, va, pfn);
                    }
                }
                Err(e) => match e {
                    PageMapError::PageNotPresent => {
                        //info!("[{}]  {:#x}    ???", idx, va);
                    }
                    _ => return Err(e),
                },
            }
        }
    }
    Ok(flippy_region)
}

fn read_memory_from_proc(pid: u32, va: u64, size: u64) -> std::io::Result<Vec<u8>> {
    // Construct the path to the process's memory file
    let path = format!("/proc/{}/mem", pid);
    let mut file = OpenOptions::new().read(true).open(path)?;

    // Seek to the virtual memory address
    file.seek(SeekFrom::Start(va))?;

    // Read the specified number of bytes into a buffer
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}
