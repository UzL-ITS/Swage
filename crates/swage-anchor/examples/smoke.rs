//! Self-contained `/dev/anchor` smoke: pin, transplant, alias-prove,
//! restore, unbind — no victim needed beyond this throwaway process.
//!
//! Build as your user, run as root with the module loaded (sudo has no
//! cargo — and never let sudo write `target/`:
//! root-owned build artifacts poison every later user build):
//!
//! ```sh
//! cargo build -p swage-anchor --example smoke
//! sudo ./target/debug/examples/smoke
//! ```
//!
//! What it proves, in order:
//!
//! 1. `bind` pins an anonymous page and reports its PFN;
//! 2. `query` reads the second page's pre-transplant PFN;
//! 3. `transplant` puts the pinned frame under the second page's PTE
//!    (the module's TLB flush makes the swap visible immediately);
//! 4. **the aliasing law**: a write through the second page's virtual
//!    address is visible through the pinned page's virtual address —
//!    both VAs now back one physical frame;
//! 5. `restore` puts the displaced frame back and its original content
//!    is intact (the 0x77 byte written during the transplant lives on
//!    the *pinned* frame, not the restored one);
//! 6. `unbind` drops the pin.
//!
//! Exit 0 = the facility is sound on this kernel.

use std::ptr;

use swage_anchor::AnchorDev;

const PAGE: usize = 4096;

/// One writable anonymous page (MAP_PRIVATE | MAP_ANONYMOUS).
fn anon_page() -> Result<*mut u8, std::io::Error> {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(p as *mut u8)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dev = AnchorDev::open()?;
    let status = dev.status()?;
    println!(
        "status: {} bound frame(s), {} transplant(s), kernel {:#x}",
        status.bound_frames, status.transplants, status.kernel_version_code
    );

    // THE CAST: this process plays both roles.
    //   flippy — the pinned page (the attacker's profiled frame)
    //   victim — the page whose PTE gets the flippy's frame
    let flippy = anon_page()?;
    let victim = anon_page()?;
    let flippy_va = flippy as u64;
    let victim_va = victim as u64;

    // Fault both pages in and mark them: flippy 0xAA, victim 0x55.
    unsafe {
        ptr::write_bytes(flippy, 0xAA, PAGE);
        ptr::write_bytes(victim, 0x55, PAGE);
    }

    // 1. BIND the flippy frame.
    let frame = dev.bind(None, flippy_va)?;
    println!("bind: flippy va {flippy_va:#x} -> pfn {:#x}", frame.pfn());

    // 2. The victim's pre-transplant identity.
    let pre = dev.query(None, victim_va)?;
    assert!(pre.present, "the victim page must be resident");
    let old_pfn = pre.pfn;
    println!("query: victim va {victim_va:#x} pre-pfn {old_pfn:#x}");
    assert_ne!(old_pfn, frame.pfn(), "two fresh pages must differ");

    // 3. TRANSPLANT: the victim's PTE now points at the pinned frame.
    let t = dev.transplant(&frame, None, victim_va)?;
    println!(
        "transplant: victim va {victim_va:#x}: pfn {:#x} <- pinned pfn {:#x}",
        t.old_pfn, t.frame_pfn
    );
    assert_eq!(t.old_pfn, old_pfn, "the displaced PFN is the queried one");
    let post = dev.query(None, victim_va)?;
    assert_eq!(post.pfn, frame.pfn(), "the module's own QUERY must agree");

    // 4. THE ALIASING LAW: write through the victim's VA, read through
    //    the flippy's VA — one physical frame, two virtual addresses.
    unsafe {
        *victim = 0x77;
        let seen = *flippy;
        assert_eq!(
            seen, 0x77,
            "the write through the victim's VA must land on the pinned frame"
        );
        println!("alias: victim[0] = 0x77 is visible as flippy[0] = {seen:#04x}");
    }

    // 5. RESTORE: the displaced frame returns; its content survived.
    let restored = dev.restore(None, victim_va)?;
    assert_eq!(restored, old_pfn);
    let after = dev.query(None, victim_va)?;
    assert_eq!(after.pfn, old_pfn, "the original frame is back");
    unsafe {
        let back = *victim;
        assert_eq!(
            back, 0x55,
            "the restored frame kept its own content (the 0x77 lives on the pinned frame)"
        );
        println!(
            "restore: victim back on pfn {old_pfn:#x}, content {back:#04x} intact"
        );
    }

    // 6. UNBIND (the ordering law held: restore came first).
    dev.unbind(frame)?;
    println!("unbind: pin dropped");

    unsafe {
        libc::munmap(flippy as *mut libc::c_void, PAGE);
        libc::munmap(victim as *mut libc::c_void, PAGE);
    }

    println!("SMOKE PASSED — /dev/anchor is sound on this kernel");
    Ok(())
}
