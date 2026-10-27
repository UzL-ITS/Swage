# The `/dev/anchor` kernel module

The SWAGE anchor facility's kernel side: **deterministic physical-frame
anchoring** for Rowhammer placement research. The companion Rust crate
(`../`, `swage-anchor`) is the userspace client.

## What it does

Rowhammer placement experiments need the victim's target page to be a
specific, pre-profiled physical frame (the attacker's *flippy* page —
the frame whose DRAM cells the hammering flips). Achieving that through
the allocator is probabilistic (per-CPU-list steering, swap/refault
lotteries), which buries the actual object of study — the hammering —
under placement variance.

This module makes placement deterministic with three ioctls:

| ioctl | effect |
| --- | --- |
| `ANCHOR_BIND(pid, va)` | GUP-pins one order-0 anonymous page (the flippy) and returns its handle + PFN. The page stays mapped in its owner: nothing is freed, no allocator is involved. |
| `ANCHOR_TRANSPLANT(handle, pid, va)` | Replaces the present base-page PTE at `va` in the target process with an entry pointing at the pinned frame. Same protection bits, new frame. The victim's page and the attacker's page are now aliases of one physical frame. |
| `ANCHOR_RESTORE(pid, va)` | Puts the saved original PTE back (works even after the target exited; refuses if the mapping changed under the transplant). |

The victim keeps running stock code against ordinary anonymous memory;
the attacker keeps its hammer pattern and its readable/writable alias of
the frame (a free observation oracle: watch the victim's table entries
and the hammer's flips through your own mapping).

## The refcount law (read before use)

Neither the displaced frame nor the anchored frame has its refcount or
mapcount modified by the transplant:

- the **anchored** frame stays alive through the `ANCHOR_BIND` pin, so a
  concurrent `munmap`/`MADV_DONTNEED` by its owner cannot free it under
  the victim's alias;
- the **displaced** frame stays accounted to its original mapping until
  `ANCHOR_RESTORE` puts the old PTE back — the module never hands it to
  the buddy, so it cannot be reused while aliased out.

Consequences (the experiment contract):

- `ANCHOR_UNBIND` refuses (`EBUSY`) while the frame is transplanted —
  **RESTORE before UNBIND**, always;
- the victim's PTE is not in the anchored frame's rmap: keep the victim
  quiesced (parked between protocol steps) while transplanted, and keep
  swap/reclaim pressure off the victim's table VMA for the duration;
- `rmmod` restores every live transplant first (module exit walks the
  records; an unrestorable mapping is reported loudly, never left
  silently aliased).

## Build & load (root, on the testbed)

```sh
sudo make check-symbols   # verify the module-facing symbols on THIS kernel
                          # (root only: kallsyms hides the addresses from
                          # non-root readers when kptr_restrict is set)
sudo make                 # build against the running kernel
sudo make load            # insmod; /dev/anchor appears via devtmpf (0600)
```

The device requires `CAP_SYS_ADMIN` — this is a privileged experiment
tier, not an attack primitive. The in-model (unprivileged) placement
routes remain the userspace release campaigns.

## Kernel compatibility

- **x86_64 only** (raw PTE surgery with `PTE_PFN_MASK`).
- `follow_pte()` ABI, **verified against the upstream sources**
  (kernel.org `mm/memory.c` at v6.8 / v6.10 / v6.11):

  | kernel | signature | anon targets |
  | --- | --- | --- |
  | ≤ 6.9 | `follow_pte(mm, addr, ptep, ptl)` | yes (v6.8: "@mm: the mm_struct of the target address space") |
  | 6.10 | `follow_pte(vma, addr, ptep, ptl)` | yes (v6.10 doc: "anonymous folios in COW mappings") |
  | ≥ 6.11 | `follow_pte(vma, ...)` | **no** — the 2024 rework restricts it to `VM_IO|VM_PFNMAP` mappings |

  The module auto-selects the form via `LINUX_VERSION_CODE` (6.9 is
  unverified between the two; force with
  `make ANCHOR_FOLLOW_PTE_MM=1` / `ANCHOR_FOLLOW_PTE_VMA=1`) and
  **refuses to build on ≥ 6.11** (`#error`) — the anon transplant
  target is unsupported there until the `apply_to_page_range` walker
  variant lands (that function is exported).
- **The TLB flush — the exported-primitives law** (verified against
  v6.8 `arch/x86/mm/tlb.c`): stock x86 exports only `leave_mm`,
  `__get_current_cr3_fast` and `__flush_tlb_all`. `flush_tlb_mm_range`
  is built-in-only, and its prototype sits behind `#ifndef MODULE` in
  `asm/tlbflush.h` — invisible to modules *by design*. The module's
  default therefore flushes via the exported pair
  `on_each_cpu` + `__flush_tlb_all` — the whole TLB on every CPU, a
  superset of the target-mm flush (transplants are rare events on a
  quiesced testbed, so the heavy flush is acceptable). If your (custom)
  kernel *does* export the ranged flush, build with
  `make ANCHOR_FLUSH_TLB_MM_RANGE=1` — verify the export first
  (`grep flush_tlb_mm_range <KDIR>/Module.symvers` or a test `insmod`).
- `make check-symbols` is **root-only**: with `kernel.kptr_restrict`
  set, `/proc/kallsyms` shows zeroed addresses to non-root readers and
  the check refuses rather than reporting false negatives. Note that
  kallsyms only proves the symbol exists in the image — the definitive
  export test is the module link at `insmod`.
- A kernel with `CONFIG_PAGE_TABLE_CHECK=y` will splat on the transplant
  (the check expects refcounted PTE installations); build the testbed
  kernel without it, or expect the warnings (the transplant still works).
- THP-backed target entries refuse with `EBUSY` — the target must be a
  base-page PTE (the vLLM table's 8 KiB mapping always is; enforce
  `MADV_NOHUGEPAGE` on larger targets).

## The ABI

See `anchor.h`. Every ioctl argument struct is `__u64`-only (no
pointers), so 32-bit compat callers share the layout; the module
registers `.compat_ioctl` to the same handler and `BUILD_BUG_ON`s the
struct sizes at init. The Rust client (`../src/ioctl.rs`) mirrors the
constants and its unit tests re-derive the request numbers — a drifted
build fails on either side, not at runtime.

## dmesg evidence

`bind` / `transplant` / `restore` each log a line with the PFNs involved
(`anchor: transplant: pid 3710378 va 26966000: pfn 12a340 -> pinned pfn
0e2110 ...`), so `dmesg` is a third, kernel-side placement-evidence
channel next to pagemap and the module's own `ANCHOR_QUERY`.
