//! The `/dev/anchor` device client.
//!
//! Thin, fail-loud ioctl wrappers over [`crate::ioctl`]'s ABI. Every
//! error carries the operation and the likely cause (module not loaded,
//! missing privileges, the refcount-law refusals) — this crate is an
//! experiment instrument first.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;

use serde::Serialize;

use crate::ioctl::{BindArgs, Ioctl, QueryArgs, RestoreArgs, StatusArgs, TransplantArgs, UnbindArgs};

const DEVICE: &str = "/dev/anchor";

/// One raw ioctl: negative rc maps to `errno`.
fn raw_ioctl<T>(file: &File, op: Ioctl, arg: &mut T) -> io::Result<()> {
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            op.request() as libc::c_ulong,
            arg as *mut T as *mut core::ffi::c_void,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Attach an operation-specific hint to an ioctl failure.
fn with_context(op: Ioctl, err: io::Error) -> io::Error {
    let hint = match err.raw_os_error() {
        Some(libc::EPERM) => "requires CAP_SYS_ADMIN (the device is a root-only experiment tier)".to_string(),
        Some(libc::EBUSY) => match op {
            Ioctl::Transplant => {
                "the target PTE is not present (park the victim first) or \
                 a transplant already exists at this (pid, va) — restore first"
                    .to_string()
            }
            Ioctl::Unbind => "the frame is still transplanted — restore before unbind".to_string(),
            Ioctl::Bind => "the GUP pin did not land (is the owner mapping writable and resident?)".to_string(),
            _ => "the facility refused".to_string(),
        },
        Some(libc::EINVAL) => match op {
            Ioctl::Bind => "the page is not an order-0 anonymous page (the flippy law) or the va is unaligned".to_string(),
            Ioctl::Transplant => "the target va is unaligned or a special mapping (PFNMAP/MIXEDMAP/HUGETLB/IO)".to_string(),
            Ioctl::Restore => "the victim's PTE changed under the transplant — experiment integrity breach".to_string(),
            _ => "refused".to_string(),
        },
        Some(libc::ESRCH) => "no such pid".to_string(),
        Some(libc::ENOENT) => match op {
            Ioctl::Bind => "unknown handle".to_string(),
            Ioctl::Transplant => "unknown handle, or no vma/pte covers the va".to_string(),
            Ioctl::Restore => "no transplant record at this (pid, va)".to_string(),
            _ => "not found".to_string(),
        },
        _ => String::new(),
    };
    let name = match op {
        Ioctl::Bind => "bind",
        Ioctl::Transplant => "transplant",
        Ioctl::Query => "query",
        Ioctl::Restore => "restore",
        Ioctl::Unbind => "unbind",
        Ioctl::Status => "status",
    };
    let msg = if hint.is_empty() {
        format!("/dev/anchor {name} failed: {err}")
    } else {
        format!("/dev/anchor {name} failed: {err} — {hint}")
    };
    io::Error::new(err.kind(), msg)
}

/// A pinned physical frame: the module-side handle plus the frame's
/// PFN, returned by [`AnchorDev::bind`].
///
/// The pin keeps the frame alive; it stays mapped in its owner (the
/// attacker's hammer pattern is never disturbed). Pass it to
/// [`AnchorDev::transplant`] by reference and let
/// [`AnchorDev::unbind`] consume it — the ordering law (restore before
/// unbind) is enforced by the module and reflected by the types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BoundFrame {
    /// The module-side handle.
    pub handle: u64,
    /// The pinned frame's PFN.
    pub pfn: u64,
}

impl BoundFrame {
    /// The pinned frame's PFN.
    pub fn pfn(&self) -> u64 {
        self.pfn
    }
}

/// One completed transplant — the placement evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Transplant {
    /// The target pid as passed to the transplant (the restore key; 0
    /// means "current process" was used).
    pub pid: u32,
    /// The target virtual address.
    pub va: u64,
    /// The anchored frame's PFN (the flippy).
    pub frame_pfn: u64,
    /// The displaced frame's PFN (the victim's original table page).
    pub old_pfn: u64,
}

/// The result of a PTE peek ([`AnchorDev::query`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PageQuery {
    /// The PFN at the queried address (0 when not present).
    pub pfn: u64,
    /// Whether the PTE maps a present page.
    pub present: bool,
}

/// Facility counters ([`AnchorDev::status`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AnchorStatus {
    /// Live bind handles.
    pub bound_frames: u64,
    /// Live transplant records.
    pub transplants: u64,
    /// The module kernel's `LINUX_VERSION_CODE`.
    pub kernel_version_code: u64,
}

/// The open `/dev/anchor` device.
#[derive(Debug)]
pub struct AnchorDev {
    file: File,
}

impl AnchorDev {
    /// Open the device (root only: the node is `0600` and the module
    /// additionally checks `CAP_SYS_ADMIN`).
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE)
            .map_err(|err| {
                let hint = match err.raw_os_error() {
                    Some(libc::ENOENT) => {
                        "the anchor module is not loaded — build & insmod it \
                         (crates/swage-anchor/kmod: make check-symbols && make load)"
                            .to_string()
                    }
                    Some(libc::EACCES) | Some(libc::EPERM) => {
                        "the device requires CAP_SYS_ADMIN (root)".to_string()
                    }
                    _ => String::new(),
                };
                let msg = if hint.is_empty() {
                    format!("cannot open {DEVICE}: {err}")
                } else {
                    format!("cannot open {DEVICE}: {err} — {hint}")
                };
                io::Error::new(err.kind(), msg)
            })?;
        Ok(Self { file })
    }

    /// Pin one page from `pid`'s address space at `va` (`None` = this
    /// process) and learn its PFN. The page must be an order-0
    /// anonymous page, writable and resident — the flippy law.
    pub fn bind(&self, pid: Option<u32>, va: u64) -> io::Result<BoundFrame> {
        let mut args = BindArgs {
            pid: pid.unwrap_or(0) as u64,
            va,
            handle: 0,
            pfn: 0,
        };
        raw_ioctl(&self.file, Ioctl::Bind, &mut args).map_err(|e| with_context(Ioctl::Bind, e))?;
        Ok(BoundFrame {
            handle: args.handle,
            pfn: args.pfn,
        })
    }

    /// Anchor the pinned `frame` under the (present, base-page) PTE at
    /// `va` in `pid`'s address space (`None` = this process).
    ///
    /// From here until [`AnchorDev::restore`], the victim's page and
    /// the attacker's pinned page are aliases of one physical frame.
    /// The displaced frame's PFN is returned as evidence.
    pub fn transplant(&self, frame: &BoundFrame, pid: Option<u32>, va: u64) -> io::Result<Transplant> {
        let pid_key = pid.unwrap_or(0);
        let mut args = TransplantArgs {
            handle: frame.handle,
            pid: pid_key as u64,
            va,
            old_pfn: 0,
        };
        raw_ioctl(&self.file, Ioctl::Transplant, &mut args)
            .map_err(|e| with_context(Ioctl::Transplant, e))?;
        log::info!(
            "anchor transplant: pid {pid_key} va {va:#x}: pfn {:#x} -> pinned pfn {:#x} \
             (handle {})",
            args.old_pfn,
            frame.pfn,
            frame.handle
        );
        Ok(Transplant {
            pid: pid_key,
            va,
            frame_pfn: frame.pfn,
            old_pfn: args.old_pfn,
        })
    }

    /// Read-only PTE peek at `va` in `pid`'s address space (`None` =
    /// this process): the placement-evidence primitive, independent of
    /// `/proc/<pid>/pagemap`.
    pub fn query(&self, pid: Option<u32>, va: u64) -> io::Result<PageQuery> {
        let mut args = QueryArgs {
            pid: pid.unwrap_or(0) as u64,
            va,
            pfn: 0,
            present: 0,
        };
        raw_ioctl(&self.file, Ioctl::Query, &mut args).map_err(|e| with_context(Ioctl::Query, e))?;
        Ok(PageQuery {
            pfn: args.pfn,
            present: args.present != 0,
        })
    }

    /// Put the saved pre-transplant PTE back at `(pid, va)` — the exact
    /// key of the transplant call (the same pid form: `None` if the
    /// transplant used `None`). Works even after the target process
    /// exited; refuses if the victim's mapping changed under the
    /// transplant. Returns the restored (original) PFN.
    pub fn restore(&self, pid: Option<u32>, va: u64) -> io::Result<u64> {
        let mut args = RestoreArgs {
            pid: pid.unwrap_or(0) as u64,
            va,
            restored_pfn: 0,
        };
        raw_ioctl(&self.file, Ioctl::Restore, &mut args)
            .map_err(|e| with_context(Ioctl::Restore, e))?;
        log::info!(
            "anchor restore: pid {} va {va:#x} back to pfn {:#x}",
            args.pid,
            args.restored_pfn
        );
        Ok(args.restored_pfn)
    }

    /// Restore a recorded transplant (the record is the key).
    pub fn restore_transplant(&self, t: &Transplant) -> io::Result<u64> {
        self.restore(if t.pid == 0 { None } else { Some(t.pid) }, t.va)
    }

    /// Drop the bind pin. Consumes the frame handle: the module refuses
    /// (`EBUSY`) while the frame is transplanted —
    /// [`AnchorDev::restore`] first (the ordering law).
    pub fn unbind(&self, frame: BoundFrame) -> io::Result<()> {
        let mut args = UnbindArgs {
            handle: frame.handle,
        };
        raw_ioctl(&self.file, Ioctl::Unbind, &mut args)
            .map_err(|e| with_context(Ioctl::Unbind, e))?;
        log::info!("anchor unbind: handle {} (pfn {:#x})", frame.handle, frame.pfn);
        Ok(())
    }

    /// Facility counters (smoke/evidence).
    pub fn status(&self) -> io::Result<AnchorStatus> {
        let mut args = StatusArgs {
            bound_frames: 0,
            transplants: 0,
            kernel_version: 0,
        };
        raw_ioctl(&self.file, Ioctl::Status, &mut args)
            .map_err(|e| with_context(Ioctl::Status, e))?;
        Ok(AnchorStatus {
            bound_frames: args.bound_frames,
            transplants: args.transplants,
            kernel_version_code: args.kernel_version,
        })
    }
}
