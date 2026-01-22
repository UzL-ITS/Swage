use std::ffi::CString;

use swage_core::memory::{ConsecBlocks, Memory};
use swage_core::util::Size::{self, MB};

use swage_core::allocator::ConsecAllocator;

/// A CoCo kernel memory allocator
/// Requires the coco_dec_mem kernel module
pub struct CoCo {}

impl ConsecAllocator for CoCo {
    type Error = std::io::Error;
    fn block_size(&self) -> Size {
        MB(4)
    }

    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        unsafe {
            const MOD_PATH: &str = "/dev/coco_dec_mem";
            let c_mod_path = CString::new(MOD_PATH)?;
            let fd = libc::open(c_mod_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let block_size = self.block_size();
            let block_count = (size.bytes() as f32 / block_size.bytes() as f32).ceil() as i32;
            let blocks = (0..block_count)
                .map(|_| {
                    let v = libc::mmap(
                        std::ptr::null_mut(),
                        block_size.bytes(),
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_POPULATE,
                        fd,
                        0,
                    );
                    if v == libc::MAP_FAILED {
                        return Err(std::io::Error::last_os_error());
                    }
                    let block = Memory::new(v as *mut u8, MB(4).bytes());
                    libc::memset(block.ptr as *mut libc::c_void, 0, block.len);
                    //consec_checker.check(&block)?;
                    Ok(block)
                })
                .collect::<Result<Vec<_>, _>>()?;
            libc::close(fd);
            Ok(ConsecBlocks::new(blocks))
        }
    }
}
