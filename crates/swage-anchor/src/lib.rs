//! # swage-anchor
//!
//! Deterministic page anchoring for Rowhammer placement research — the
//! userspace client of the [`/dev/anchor`] kernel module
//! (`kmod/` in this crate).
//!
//! Rowhammer placement experiments need the victim's target page to be
//! a specific, pre-profiled physical frame (the attacker's *flippy*
//! page — the frame whose cells the hammering flips). Steering that
//! frame to the victim through the page allocator is probabilistic
//! (per-CPU-list steering, swap/refault lotteries), which buries the
//! object of study — the hammering itself — under placement variance.
//!
//! The anchor facility makes the placement deterministic without
//! touching the victim's code: it **pins** the attacker's frame
//! ([`AnchorDev::bind`]) and **transplants** it under the victim's
//! page-table entry ([`AnchorDev::transplant`]), so the victim's page
//! and the attacker's page become aliases of one physical frame. The
//! attacker's hammer pattern (the aggressor rows around the flippy)
//! stays mapped and untouched; nothing is ever freed; there is no
//! release campaign and no allocator race. The attack's only remaining
//! variable is the hammering — the isolation this facility exists for.
//!
//! # Platform Requirements
//!
//! - x86_64 Linux
//! - Root privileges (`CAP_SYS_ADMIN`; the device node is `0600`)
//! - The kernel module built and loaded from this crate's `kmod/`
//!   (`make check-symbols && make load` there)
//!
//! # Experiment-tier annotation
//!
//! This facility is **privileged** (a kernel module): it is the
//! deterministic anchor tier of an experiment campaign, not an
//! unprivileged attack step. The in-model placement routes remain the
//! userspace frame-steering campaigns.
//!
//! # The refcount law
//!
//! The transplant is a *leak-style alias*: neither frame's refcount or
//! mapcount is modified. The pinned frame cannot be freed under the
//! alias (the bind pin holds it), and the displaced frame cannot be
//! reused (it stays accounted to its original mapping until
//! [`AnchorDev::restore`] puts the old PTE back). The ordering law is
//! enforced by the module: [`AnchorDev::unbind`] refuses while the
//! frame is transplanted — restore first.
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> std::io::Result<()> {
//! use swage_anchor::{AnchorDev, BoundFrame};
//!
//! let dev = AnchorDev::open()?;                     // /dev/anchor
//!
//! // Pin this process's page at 0x7f0000010000 (the flippy).
//! let frame: BoundFrame = dev.bind(None, 0x7f000001000)?;
//!
//! // Anchor it under the victim's table page (pid 3710378).
//! let t = dev.transplant(&frame, Some(3710378), 0x26966000)?;
//! assert_eq!(t.frame_pfn, frame.pfn());
//!
//! // ... the victim now reads/writes the pinned frame; hammer away ...
//!
//! // Teardown: restore, then unbind (the module enforces the order).
//! dev.restore(Some(3710378), 0x26966000)?;
//! dev.unbind(frame)?;
//! # Ok(())
//! # }
//! ```
//!
//! [`/dev/anchor`]: kmod/README.md

#![warn(missing_docs)]

mod dev;
mod ioctl;

pub use dev::{AnchorDev, AnchorStatus, BoundFrame, PageQuery, Transplant};
pub use ioctl::{ioctl_request, Ioctl};
