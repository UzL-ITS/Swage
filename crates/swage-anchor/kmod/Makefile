# The SWAGE anchor facility's kernel module (/dev/anchor).
#
# Build against the running kernel (default) or an explicit tree:
#   make                        # against /lib/modules/$(uname -r)/build
#   make KDIR=/path/to/tree     # against a prepared kernel tree
#   make load                   # build + insmod (root)
#   make unload                 # rmmod (root; the module restores every
#                               # live transplant on unload)
#   make check-symbols          # verify the module-facing symbols exist
#                               # in /proc/kallsyms BEFORE building —
#                               # ROOT ONLY (kallsyms hides the addresses
#                               # from non-root readers when kptr_restrict
#                               # is set; sudo make check-symbols)
#
# Kernel-compatibility overrides (see the top of anchor.c):
#   make ANCHOR_FOLLOW_PTE_MM=1     # force follow_pte(mm, ...) form (<= 6.9)
#   make ANCHOR_FOLLOW_PTE_VMA=1    # force follow_pte(vma, ...) form (>= 6.10)
#   make ANCHOR_FLUSH_TLB_MM_RANGE=1
#                                   # use flush_tlb_mm_range directly —
#                                   # ONLY on kernels that export it
#                                   # (stock x86 does not; verify via
#                                   # Module.symvers or a test insmod)

KDIR ?= /lib/modules/$(shell uname -r)/build
# No -Wextra here: kernel headers do not build clean under it (hundreds
# of -Wunused-parameter from config-dependent inline stubs) — the
# kernel's own default warning set is the module's set.

ifdef ANCHOR_FOLLOW_PTE_MM
ccflags-y += -DANCHOR_FOLLOW_PTE_MM
endif
ifdef ANCHOR_FOLLOW_PTE_VMA
ccflags-y += -DANCHOR_FOLLOW_PTE_VMA
endif
ifdef ANCHOR_FLUSH_TLB_MM_RANGE
ccflags-y += -DANCHOR_FLUSH_TLB_MM_RANGE
endif

obj-m := anchor.o

.PHONY: all clean load unload check-symbols

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

load: all
	insmod anchor.ko

unload:
	rmmod anchor

# The module consumes these module-facing symbols; every one must be
# present in the kernel image. kallsyms cannot distinguish exported
# from non-exported symbols — the definitive export test is the module
# link at insmod — but a missing name here means a guaranteed build
# failure, caught early with a one-line fix (see the overrides above).
# ROOT ONLY: with kptr_restrict, non-root readers get zeroed addresses
# (which would false-negative below); refuse instead of lying.
check-symbols:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "check-symbols must run as root: /proc/kallsyms hides the"; \
		echo "addresses from non-root readers (kernel.kptr_restrict), which"; \
		echo "this check cannot distinguish from a missing symbol."; \
		echo "run: sudo make check-symbols"; \
		exit 1; \
	fi; \
	fail=0; \
	for sym in follow_pte __flush_tlb_all on_each_cpu_cond_mask find_get_pid \
	            get_pid_task get_task_mm pin_user_pages_remote unpin_user_page; do \
		addr=$$(awk -v s=$$sym '$$3 == s { print $$1; exit }' /proc/kallsyms); \
		if [ -z "$$addr" ]; then \
			echo "MISSING from the kernel image: $$sym"; \
			case $$sym in \
			follow_pte) echo "  note: a missing follow_pte is a build-tree/kernel mismatch - the signature forms are a separate concern (ANCHOR_FOLLOW_PTE_MM/VMA)" ;; \
			esac; \
			fail=1; \
		elif [ "$$addr" = "0000000000000000" ]; then \
			echo "present: $$sym (address zeroed - kernel.kptr_restrict=2;"; \
			echo "         insmod will be the proof)"; \
		else \
			echo "ok: $$sym @ $$addr"; \
		fi; \
	done; \
	[ "$$fail" = "0" ]
