use lazy_static::lazy_static;
use libc::{MAP_POPULATE, MAP_SHARED, O_CREAT, O_RDWR};
use std::ffi::{CString, c_void};
use std::fs::File;
use std::io::Read;
use swage_core::allocator::ConsecAllocator;
use swage_core::memory::{ConsecBlocks, Memory, PfnOffset};
use swage_core::util::Size::{self, MB};
// https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
//
// The output of "cat /proc/meminfo" will include lines like:
// ...
// HugePages_Total: uuu
// HugePages_Free:  vvv
// HugePages_Rsvd:  www
// HugePages_Surp:  xxx
// Hugepagesize:    yyy kB
// Hugetlb:         zzz kB

// constant.
const MEMINFO_PATH: &str = "/proc/meminfo";
const TOKEN: &str = "Hugepagesize:";

lazy_static! {
    static ref HUGEPAGE_SIZE: isize = {
        let buf = File::open(MEMINFO_PATH).map_or("".to_owned(), |mut f| {
            let mut s = String::new();
            let _ = f.read_to_string(&mut s);
            s
        });
        parse_hugepage_size(&buf)
    };
}

fn parse_hugepage_size(s: &str) -> isize {
    for line in s.lines() {
        if line.starts_with(TOKEN) {
            let mut parts = match line.strip_prefix(TOKEN) {
                Some(line) => line.split_whitespace(),
                None => panic!("Invalid line: {}", line),
            };

            let p = parts.next().unwrap_or("0");
            let mut hugepage_size = p.parse::<isize>().unwrap_or(-1);

            hugepage_size *= parts.next().map_or(1, |x| match x {
                "kB" => 1024,
                _ => 1,
            });

            return hugepage_size;
        }
    }

    -1
}

/// Hugepage-based memory allocator using 1GB pages.
///
/// Allocates memory using Linux hugepages mounted at `/dev/hugepages`.
/// The hugepage size is automatically detected from `/proc/meminfo`.
///
/// # Implementation
///
/// Implements [`swage_core::allocator::ConsecAllocator`] with 1GB block size.
///
/// # Platform Requirements
///
/// - 1GB hugepages must be configured via kernel boot parameters
/// - Hugepagefs must be mounted at `/dev/hugepages`
/// - Currently only supports x86_64 architecture
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default, Copy, Clone)]
pub struct HugepageAllocator {}

/// Supported hugepage sizes.
///
/// Currently only 1GB hugepages are supported.
pub enum HugepageSize {
    //    TWO_MB,  // not supported yet. TODO: Check PFN offset for 2 MB hugepages in docs.
    /// 1 Gigabyte hugepage
    OneGb,
}

impl ConsecAllocator for HugepageAllocator {
    type Error = std::io::Error;
    fn block_size(&self) -> Size {
        Size::B(*HUGEPAGE_SIZE as usize)
    }
    fn alloc_consec_blocks(&mut self, size: Size) -> Result<ConsecBlocks, Self::Error> {
        assert!(
            size.bytes() < self.block_size().bytes(),
            "Only support allocations up to 0x{:x} bytes",
            self.block_size().bytes()
        );
        assert_eq!(self.block_size().bytes(), MB(1024).bytes());
        let block = Memory::hugepage(HugepageSize::OneGb)?;
        unsafe { libc::memset(block.ptr as *mut c_void, 0x00, self.block_size().bytes()) };
        Ok(ConsecBlocks::new(vec![block]))
    }
}

trait Hugepage {
    fn hugepage(size: HugepageSize) -> Result<Self, std::io::Error>
    where
        Self: Sized;
}

impl Hugepage for Memory {
    fn hugepage(size: HugepageSize) -> Result<Self, std::io::Error> {
        const ADDR: usize = 0x2000000000;
        let hp_size = match size {
            HugepageSize::OneGb => MB(1024).bytes(),
        };
        let fd = unsafe {
            libc::open(
                CString::new("/dev/hugepages/hammer_huge")
                    .expect("CString")
                    .as_ptr(),
                O_RDWR | O_CREAT,
                666,
            )
        };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let p = unsafe {
            libc::mmap(
                ADDR as *mut libc::c_void,
                hp_size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Memory::new_with_parts(
            p as *mut u8,
            hp_size,
            PfnOffset::Fixed(0),
        ))
    }
}

#[cfg(target_arch = "x86_64")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::{alloc::Layout, mem, ptr};
    use swage_core::memory::BytePointer;

    #[test]
    fn test_parse_hugepage_size() {
        // correct.
        assert_eq!(parse_hugepage_size("Hugepagesize:1024"), 1024);
        assert_eq!(parse_hugepage_size("Hugepagesize: 2 kB"), 2048);

        // wrong.
        assert_eq!(parse_hugepage_size("Hugepagesize:1kB"), -1);
        assert_eq!(parse_hugepage_size("Hugepagesize: 2kB"), -1);
    }

    #[test]
    fn test_allocator() {
        let mut hugepage_alloc = HugepageAllocator {};

        // u16.
        unsafe {
            let layout = Layout::new::<u16>();
            let mem = hugepage_alloc
                .alloc_consec_blocks(Size::B(layout.size()))
                .expect("allocation failed");
            let p = mem.ptr();
            assert!(!p.is_null(), "allocation failed");
            *p = 20;
            assert_eq!(*p, 20);
            mem.dealloc();
        }

        // array.
        unsafe {
            let layout = Layout::array::<char>(2048).unwrap();
            let mem = hugepage_alloc
                .alloc_consec_blocks(Size::B(layout.size()))
                .expect("allocation failed");
            let dst = mem.ptr();
            assert!(!dst.is_null(), "allocation failed");

            let src = String::from("hello rust");
            let len = src.len();
            ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            let s = String::from_raw_parts(dst, len, len);
            assert_eq!(s, src);
            mem::forget(s);

            mem.dealloc();
        }
    }
}
