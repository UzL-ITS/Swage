/* SPDX-License-Identifier: GPL-2.0 */
/*
 * anchor.h — the /dev/anchor ioctl ABI (the SWAGE anchor facility).
 *
 * Deterministic physical-frame anchoring for Rowhammer placement
 * research: the module pins a physical frame owned by one process (the
 * attacker's profiled flippy page) and transplants it under a chosen
 * page-table entry of another process (the victim's target page), so
 * that victim-side reads and writes land on the attacker's frame while
 * the attacker's own mapping (and the hammer pattern around it) stays
 * untouched.
 *
 * ABI laws:
 *   - every argument struct is built from __u64 fields only (no
 *     pointers, no size_t) so 32-bit compat callers share the exact
 *     layout; the module registers .compat_ioctl to the same handler;
 *   - the ioctl request numbers embed sizeof(struct); both sides
 *     derive them from these definitions, and the module's init
 *     BUILD_BUG_ONs the struct sizes so a drifted build fails loudly
 *     at insmod instead of corrupting arguments;
 *   - all virtual addresses must be page-aligned (EINVAL otherwise);
 *     page granularity is 4 KiB (the module is x86_64-only).
 */

#ifndef _ANCHOR_H
#define _ANCHOR_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define ANCHOR_IOCTL_TYPE 'A'

/* Pin one page from `pid`'s address space at `va` (FOLL_WRITE, a
 * long-lived GUP pin). The page must be an order-0 anonymous page (the
 * flippy law). Returns the module-side handle and the pinned frame's
 * PFN. `pid == 0` means the calling process itself. */
struct anchor_bind_args {
	__u64 pid;		/* in: owner pid (0 = current) */
	__u64 va;		/* in: owner virtual address (page-aligned) */
	__u64 handle;		/* out: the frame handle */
	__u64 pfn;		/* out: the pinned frame's PFN */
};

/* Replace the (present, base-page) PTE at `va` in `pid`'s address
 * space with an entry pointing at the pinned frame `handle`. The old
 * PTE is saved module-side for ANCHOR_RESTORE; its PFN is returned.
 * Refcounting law: neither the old nor the pinned page's refcount or
 * mapcount is modified (an aliased mapping) — the pinned frame stays
 * alive through the bind pin, the displaced frame stays accounted to
 * its original mapping until RESTORE puts the old PTE back. */
struct anchor_transplant_args {
	__u64 handle;		/* in: the ANCHOR_BIND handle */
	__u64 pid;		/* in: target pid (0 = current) */
	__u64 va;		/* in: target virtual address (page-aligned) */
	__u64 old_pfn;		/* out: the displaced frame's PFN */
};

/* Read-only PTE peek at `va` in `pid`'s address space: the PFN and
 * whether the entry is present. This is the placement-evidence
 * primitive (independent of /proc/<pid>/pagemap). */
struct anchor_query_args {
	__u64 pid;		/* in: target pid (0 = current) */
	__u64 va;		/* in: target virtual address */
	__u64 pfn;		/* out: PFN (0 when not present) */
	__u64 present;		/* out: 1 when the PTE maps a present page */
};

/* Put the saved pre-transplant PTE back at (pid, va). `pid`/`va` must
 * match the ANCHOR_TRANSPLANT call exactly (they are the record key;
 * the restore works even after the target process exited — the module
 * keeps the mm alive). Refuses (-EINVAL) if the current PTE no longer
 * points at the anchored frame: something rewrote the victim's mapping
 * under the transplant, which is an experiment-integrity breach. */
struct anchor_restore_args {
	__u64 pid;		/* in: the transplant's target pid */
	__u64 va;		/* in: the transplant's target virtual address */
	__u64 restored_pfn;	/* out: the PFN put back */
};

/* Drop the bind pin for `handle`. Refuses (-EBUSY) while the frame is
 * transplanted: RESTORE first. This is the ordering law that keeps the
 * aliased mapping backed by a live frame at all times. */
struct anchor_unbind_args {
	__u64 handle;		/* in: the ANCHOR_BIND handle */
};

/* Facility counters (smoke/evidence). */
struct anchor_status_args {
	__u64 bound_frames;	/* out: live bind handles */
	__u64 transplants;	/* out: live transplant records */
	__u64 kernel_version;	/* out: LINUX_VERSION_CODE */
};

#define ANCHOR_BIND		_IOWR(ANCHOR_IOCTL_TYPE, 0x01, struct anchor_bind_args)
#define ANCHOR_TRANSPLANT	_IOWR(ANCHOR_IOCTL_TYPE, 0x02, struct anchor_transplant_args)
#define ANCHOR_QUERY		_IOWR(ANCHOR_IOCTL_TYPE, 0x03, struct anchor_query_args)
#define ANCHOR_RESTORE		_IOWR(ANCHOR_IOCTL_TYPE, 0x04, struct anchor_restore_args)
#define ANCHOR_UNBIND		_IOWR(ANCHOR_IOCTL_TYPE, 0x05, struct anchor_unbind_args)
#define ANCHOR_STATUS		_IOWR(ANCHOR_IOCTL_TYPE, 0x06, struct anchor_status_args)

#endif /* _ANCHOR_H */
