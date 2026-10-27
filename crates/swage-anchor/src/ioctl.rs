//! The `/dev/anchor` ioctl ABI — mirrors `kmod/anchor.h` byte for byte.
//!
//! Law: every argument struct is built from `u64` fields only (no
//! pointers, no `usize`), so 32-bit compat callers share the exact
//! layout; the module registers `.compat_ioctl` to the same handler and
//! `BUILD_BUG_ON`s the struct sizes at init. Keep this file and the
//! header in lockstep; [`super::AnchorDev`] is the only consumer.

use core::mem::size_of;

/// The ioctl magic (`ANCHOR_IOCTL_TYPE` in `anchor.h`).
pub const ANCHOR_IOCTL_TYPE: u8 = b'A';

// The asm-generic _IOC encoding, re-derived so the request numbers are
// checked by the unit tests instead of trusted as opaque constants.
// (_IOC_NRSHIFT=0, _IOC_DIRSHIFT=30; dir: _IOC_WRITE=1 | _IOC_READ=2.)
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

/// Re-implementation of the C `_IOC(dir, type, nr, size)` macro.
pub const fn ioc(dir: u32, ty: u8, nr: u8, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)
        | ((ty as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
}

/// The bind argument (`struct anchor_bind_args`).
///
/// Pin one page from `pid`'s address space at `va` (`FOLL_WRITE`, a
/// long-lived GUP pin). The page must be an order-0 anonymous page (the
/// flippy law). `pid == 0` (or [`Option::None`] on the client side)
/// means the calling process itself.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindArgs {
    /// owner pid (0 = current)
    pub pid: u64,
    /// owner virtual address (page-aligned)
    pub va: u64,
    /// out: the frame handle
    pub handle: u64,
    /// out: the pinned frame's PFN
    pub pfn: u64,
}

/// The transplant argument (`struct anchor_transplant_args`).
///
/// Replace the (present, base-page) PTE at `va` in `pid`'s address
/// space with an entry pointing at the pinned frame. The old PTE is
/// saved module-side for [`Ioctl::Restore`]; its PFN is returned.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransplantArgs {
    /// the bind handle
    pub handle: u64,
    /// target pid (0 = current)
    pub pid: u64,
    /// target virtual address (page-aligned)
    pub va: u64,
    /// out: the displaced frame's PFN
    pub old_pfn: u64,
}

/// The query argument (`struct anchor_query_args`).
///
/// Read-only PTE peek at `va` in `pid`'s address space: the PFN and
/// whether the entry is present (the placement-evidence primitive,
/// independent of `/proc/<pid>/pagemap`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryArgs {
    /// target pid (0 = current)
    pub pid: u64,
    /// target virtual address
    pub va: u64,
    /// out: PFN (0 when not present)
    pub pfn: u64,
    /// out: 1 when the PTE maps a present page
    pub present: u64,
}

/// The restore argument (`struct anchor_restore_args`).
///
/// Put the saved pre-transplant PTE back at `(pid, va)` — the exact key
/// of the transplant call (the pid is not resolved again: the restore
/// works even after the target process exited).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreArgs {
    /// the transplant's target pid
    pub pid: u64,
    /// the transplant's target virtual address
    pub va: u64,
    /// out: the PFN put back
    pub restored_pfn: u64,
}

/// The unbind argument (`struct anchor_unbind_args`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnbindArgs {
    /// the bind handle
    pub handle: u64,
}

/// The status argument (`struct anchor_status_args`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusArgs {
    /// out: live bind handles
    pub bound_frames: u64,
    /// out: live transplant records
    pub transplants: u64,
    /// out: `LINUX_VERSION_CODE`
    pub kernel_version: u64,
}

/// The facility's ioctl operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ioctl {
    /// Pin an attacker-owned page and learn its handle + PFN.
    Bind,
    /// Put the pinned frame under a victim page-table entry.
    Transplant,
    /// Read-only PTE peek (the placement-evidence primitive).
    Query,
    /// Put the saved pre-transplant PTE back.
    Restore,
    /// Drop the bind pin (refuses while transplanted).
    Unbind,
    /// Facility counters.
    Status,
}

impl Ioctl {
    /// The argument-struct size this operation marshals.
    pub const fn arg_size(self) -> u32 {
        match self {
            Ioctl::Bind => size_of::<BindArgs>() as u32,
            Ioctl::Transplant => size_of::<TransplantArgs>() as u32,
            Ioctl::Query => size_of::<QueryArgs>() as u32,
            Ioctl::Restore => size_of::<RestoreArgs>() as u32,
            Ioctl::Unbind => size_of::<UnbindArgs>() as u32,
            Ioctl::Status => size_of::<StatusArgs>() as u32,
        }
    }

    /// The ioctl request number (`_IOWR` encoding, all ops are
    /// read-write: every op writes its out-fields back).
    pub const fn request(self) -> u32 {
        let nr: u8 = match self {
            Ioctl::Bind => 0x01,
            Ioctl::Transplant => 0x02,
            Ioctl::Query => 0x03,
            Ioctl::Restore => 0x04,
            Ioctl::Unbind => 0x05,
            Ioctl::Status => 0x06,
        };
        ioc(IOC_WRITE | IOC_READ, ANCHOR_IOCTL_TYPE, nr, self.arg_size())
    }
}

/// Convenience free function: the request number for an [`Ioctl`].
pub const fn ioctl_request(op: Ioctl) -> u32 {
    op.request()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ABI law: all-u64 structs, fixed sizes matching the C side's
    /// BUILD_BUG_ONs (4/4/4/3/1/3 × u64).
    #[test]
    fn abi_struct_sizes() {
        assert_eq!(size_of::<BindArgs>(), 32);
        assert_eq!(size_of::<TransplantArgs>(), 32);
        assert_eq!(size_of::<QueryArgs>(), 32);
        assert_eq!(size_of::<RestoreArgs>(), 24);
        assert_eq!(size_of::<UnbindArgs>(), 8);
        assert_eq!(size_of::<StatusArgs>(), 24);
    }

    /// The request numbers, hand-computed the way `_IOWR` does it
    /// (type `A` = 0x41, all-u64 structs): a typo in either side's
    /// encoding shows up here.
    #[test]
    fn request_numbers_match_the_c_macros() {
        // _IOWR('A', nr, struct) with size 32: (3 << 30) | (32 << 16) | (0x41 << 8) | nr
        let w32 = |nr: u32| (3 << 30) | (32 << 16) | (0x41 << 8) | nr;
        let w = |nr: u32, size: u32| (3 << 30) | (size << 16) | (0x41 << 8) | nr;
        assert_eq!(Ioctl::Bind.request(), w32(0x01));
        assert_eq!(Ioctl::Transplant.request(), w32(0x02));
        assert_eq!(Ioctl::Query.request(), w32(0x03));
        assert_eq!(Ioctl::Restore.request(), w(0x04, 24));
        assert_eq!(Ioctl::Unbind.request(), w(0x05, 8));
        assert_eq!(Ioctl::Status.request(), w(0x06, 24));
    }

    /// The encoding formula itself must be the kernel's, not a private
    /// one: _IOC(3, 0x41, 0x01, 32) = 0xC0204101.
    #[test]
    fn encoding_formula_is_the_kernel_one() {
        assert_eq!(ioc(3, 0x41, 0x01, 32), 0xC020_4101);
    }
}
