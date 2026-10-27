// SPDX-License-Identifier: GPL-2.0
/*
 * anchor.c — /dev/anchor: deterministic physical-frame anchoring for
 * Rowhammer placement research (the SWAGE anchor facility).
 *
 * The module gives privileged experiment drivers three primitives over
 * an otherwise untouched victim:
 *
 *   ANCHOR_BIND        pin an attacker-owned page (the profiled flippy
 *                      frame) and learn its PFN;
 *   ANCHOR_TRANSPLANT  put that frame under a victim page-table entry
 *                      (the victim's page and the attacker's page become
 *                      aliases of one physical frame);
 *   ANCHOR_RESTORE     put the displaced frame back, byte-for-byte
 *                      accounting unchanged.
 *
 * Placement becomes deterministic: the flippy frame never enters the
 * buddy/percpu allocator, so no release campaign, no PCP steering, no
 * swap/refault lottery — the hammering itself is the only variable left
 * in the experiment.
 *
 * Kernel-side laws (the experiment tier's annotation):
 *   - the displaced frame's refcount/mapcount are NOT modified: the old
 *     PTE is saved verbatim and the page stays accounted to its
 *     original mapping (a "leak-style alias"); the anchored frame is
 *     kept alive by the GUP pin, so a concurrent munmap by the owner
 *     cannot free it under the victim's alias;
 *   - the transplant is invisible to the anchored page's rmap: the
 *     victim's PTE is not in the frame's reverse map. Keep the victim
 *     quiesced (parked between protocol steps) for the transplant's
 *     lifetime; reclaim/migration/ksm on the victim's VMA during a
 *     transplant is out of contract and will be caught by RESTORE's
 *     integrity check;
 *   - only present, base-page PTEs are transplanted: a THP-backed or
 *     non-present entry refuses with -EBUSY (fail loud, not silent);
 *   - CAP_SYS_ADMIN is required to open the device (root-only facility).
 *
 * Kernel compatibility:
 *   - follow_pte() ABI drift, verified against the upstream sources
 *     (kernel.org mm/memory.c at v6.8/v6.10/v6.11): <= 6.9 takes
 *     (mm, ...), 6.10 takes (vma, ...), and >= 6.11 restricts the
 *     function to VM_IO|VM_PFNMAP mappings (the 2024 rework) so the
 *     anon transplant target is unsupported there — the module refuses
 *     to build on >= 6.11 (#error) until the apply_to_page_range
 *     walker variant lands. Auto-selected by LINUX_VERSION_CODE;
 *     override at build time with -DANCHOR_FOLLOW_PTE_MM or
 *     -DANCHOR_FOLLOW_PTE_VMA (6.9 is unverified between the forms);
 *   - TLB flush (the exported-primitives law, verified against v6.8
 *     arch/x86/mm/tlb.c): stock x86 exports only leave_mm,
 *     __get_current_cr3_fast and __flush_tlb_all — flush_tlb_mm_range
 *     is built-in-only and its prototype hides behind #ifndef MODULE
 *     in asm/tlbflush.h. Default: on_each_cpu + __flush_tlb_all (the
 *     whole TLB on every CPU — a superset of the target-mm flush);
 *     kernels that export the ranged flush can build with
 *     -DANCHOR_FLUSH_TLB_MM_RANGE to use it;
 *   - x86_64 only (raw PTE surgery with PTE_PFN_MASK).
 */

#define pr_fmt(fmt) "anchor: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/smp.h>
#include <linux/page-flags.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>

#include "anchor.h"

#if !defined(CONFIG_X86_64)
#error "the anchor module is x86_64-only (raw PTE surgery with PTE_PFN_MASK)"
#endif

/* Sanity caps: a research driver binds a handful of flippy candidates
 * and transplants a handful of victim pages; anything beyond that is a
 * runaway loop and must refuse, not wedge the module. */
#define ANCHOR_MAX_FRAMES 256
#define ANCHOR_MAX_TRANSPLANTS 64

/*
 * follow_pte() ABI drift — verified against the upstream sources
 * (kernel.org mm/memory.c, v6.8 / v6.10 / v6.11):
 *
 *   <= 6.9 : int follow_pte(struct mm_struct *mm, unsigned long addr,
 *                            pte_t **ptep, spinlock_t **ptl)
 *            (v6.8 doc: "@mm: the mm_struct of the target address
 *            space") — works on ordinary anon mappings.
 *   6.10   : int follow_pte(struct vm_area_struct *vma, ...) — still
 *            anon-capable (v6.10 doc: "anonymous folios in COW
 *            mappings").
 *   >= 6.11: the 2024 follow_pte rework restricts it to
 *            VM_IO | VM_PFNMAP mappings — useless for the anon
 *            transplant targets; the module refuses to build there
 *            (see the #error below) until the apply_to_page_range
 *            walker variant lands (apply_to_page_range is exported).
 *
 * Auto-selected by LINUX_VERSION_CODE; override at build time with
 * -DANCHOR_FOLLOW_PTE_MM or -DANCHOR_FOLLOW_PTE_VMA if the boundary
 * is wrong for your tree (6.9 is unverified between the two forms).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0) && \
	!defined(ANCHOR_ALLOW_RESTRICTED_FOLLOW_PTE)
#error "anchor: kernels >= 6.11 restrict follow_pte() to VM_IO|VM_PFNMAP mappings - the anon transplant target is unsupported there (the apply_to_page_range walker variant is the planned route). Build with -DANCHOR_ALLOW_RESTRICTED_FOLLOW_PTE only if you understand every anon transplant will fail with -EINVAL."
#endif

#if defined(ANCHOR_FOLLOW_PTE_MM) || \
	(!defined(ANCHOR_FOLLOW_PTE_VMA) && \
	 LINUX_VERSION_CODE < KERNEL_VERSION(6, 10, 0))
#define ANCHOR_PTE_MM_FORM 1
#endif

static int anchor_follow_pte(struct mm_struct *mm, unsigned long addr,
			     pte_t **ptep, spinlock_t **ptl)
{
#ifdef ANCHOR_PTE_MM_FORM
	return follow_pte(mm, addr, ptep, ptl);
#else
	struct vm_area_struct *vma = find_vma(mm, addr);

	if (!vma)
		return -ENOENT;
	return follow_pte(vma, addr, ptep, ptl);
#endif
}

/*
 * The TLB flush — the exported-primitives law.
 *
 * Stock x86 (verified against v6.8 arch/x86/mm/tlb.c) exports only
 * leave_mm, __get_current_cr3_fast and __flush_tlb_all; the precise
 * primitive (flush_tlb_mm_range) is built-in-only, and its prototype
 * hides behind #ifndef MODULE in asm/tlbflush.h. The module therefore
 * defaults to the two exported primitives it does have — on_each_cpu +
 * __flush_tlb_all: the whole TLB on every CPU, a superset of the
 * target-mm flush. Heavy but correct, and transplants are rare events
 * on a quiesced testbed. Kernels that export the ranged flush (a custom
 * build may) can build with -DANCHOR_FLUSH_TLB_MM_RANGE to use it.
 */
extern void __flush_tlb_all(void); /* EXPORT_SYMBOL_GPL, arch/x86/mm/tlb.c */

static void anchor_flush_tlb_local(void *unused)
{
	__flush_tlb_all();
}

#ifdef ANCHOR_FLUSH_TLB_MM_RANGE
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
			       unsigned long end, unsigned int stride_shift,
			       bool freed_tables);
static void anchor_flush_tlb(struct mm_struct *mm, unsigned long va)
{
	flush_tlb_mm_range(mm, va, va + PAGE_SIZE, PAGE_SHIFT, false);
}
#else
static void anchor_flush_tlb(struct mm_struct *mm, unsigned long va)
{
	(void)mm;
	(void)va;
	on_each_cpu(anchor_flush_tlb_local, NULL, 1);
}
#endif

struct bound_frame {
	u64 handle;
	struct page *page;
	unsigned long pfn;
	u64 owner_pid;
	struct list_head list;
};

struct transplant_rec {
	struct mm_struct *mm;	/* mm ref held until RESTORE */
	unsigned long va;
	u64 pid;		/* the TRANSPLANT pid (the record key) */
	pte_t old_pte;		/* saved verbatim */
	unsigned long old_pfn;
	unsigned long flippy_pfn;
	struct bound_frame *frame;
	struct list_head list;
};

static DEFINE_MUTEX(anchor_lock);
static LIST_HEAD(bound_list);
static LIST_HEAD(transplant_list);
static u64 next_handle = 1;
static unsigned int bound_count;
static unsigned int transplant_count;

static struct bound_frame *find_frame(u64 handle)
{
	struct bound_frame *f;

	list_for_each_entry(f, &bound_list, list)
		if (f->handle == handle)
			return f;
	return NULL;
}

static struct transplant_rec *find_transplant(u64 pid, unsigned long va)
{
	struct transplant_rec *rec;

	list_for_each_entry(rec, &transplant_list, list)
		if (rec->pid == pid && rec->va == va)
			return rec;
	return NULL;
}

/* Is this frame currently aliased into any victim? (The unbind
 * ordering law: RESTORE before UNBIND.) */
static struct transplant_rec *find_transplant_by_frame(struct bound_frame *f)
{
	struct transplant_rec *rec;

	list_for_each_entry(rec, &transplant_list, list)
		if (rec->frame == f)
			return rec;
	return NULL;
}

/* Resolve a pid (0 = current) to a task with a reference held. */
static int anchor_get_task(u64 pid, struct task_struct **out)
{
	struct pid *spid;
	struct task_struct *task;

	if (!pid) {
		get_task_struct(current);
		*out = current;
		return 0;
	}
	spid = find_get_pid((pid_t)pid);
	if (!spid)
		return -ESRCH;
	task = get_pid_task(spid, PIDTYPE_PID);
	put_pid(spid);
	if (!task)
		return -ESRCH;
	*out = task;
	return 0;
}

/*
 * Fail loud when a huge folio or a device mapping backs the range: the
 * transplant writes a base-page PTE, so a PMD entry (THP) or a
 * non-present/dead page-table walk must be an explicit -EBUSY/-ENOENT,
 * never a silent wrong-level write.
 */
static int anchor_check_base_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -ENOENT;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -ENOENT;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return -ENOENT;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return -ENOENT;
	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
		return -EBUSY;
	return 0;
}

static int anchor_bind(struct anchor_bind_args *a)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct page *page;
	struct bound_frame *f;
	long pinned;
	int ret;

	if (!PAGE_ALIGNED(a->va))
		return -EINVAL;

	ret = anchor_get_task(a->pid, &task);
	if (ret)
		return ret;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	/* No mmap_lock held: the GUP slow path takes it internally. */
	pinned = pin_user_pages_remote(mm, a->va, 1, FOLL_WRITE, &page, NULL);
	mmput(mm);
	if (pinned < 0)
		return (int)pinned;
	if (pinned != 1)
		return -EBUSY;

	/* The flippy law: a single order-0 anonymous page. */
	if (!PageAnon(page) || PageCompound(page)) {
		unpin_user_page(page);
		return -EINVAL;
	}

	mutex_lock(&anchor_lock);
	if (bound_count >= ANCHOR_MAX_FRAMES) {
		mutex_unlock(&anchor_lock);
		unpin_user_page(page);
		return -EBUSY;
	}
	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		mutex_unlock(&anchor_lock);
		unpin_user_page(page);
		return -ENOMEM;
	}
	f->handle = next_handle++;
	f->page = page;
	f->pfn = page_to_pfn(page);
	f->owner_pid = a->pid ? a->pid : (u64)task_pid_nr(current);
	INIT_LIST_HEAD(&f->list);
	list_add(&f->list, &bound_list);
	bound_count++;
	a->handle = f->handle;
	a->pfn = (u64)f->pfn;
	mutex_unlock(&anchor_lock);

	pr_info("bind: handle %llu pins pfn %05lx (owner pid %llu, va %llx)\n",
		f->handle, f->pfn, f->owner_pid, a->va);
	return 0;
}

/*
 * The transplant core. Lock order: anchor_lock -> mmap_read_lock ->
 * pte lock (no other path nests these).
 */
static int anchor_transplant(struct anchor_transplant_args *a)
{
	struct bound_frame *f;
	struct transplant_rec *rec;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t old, new;
	int ret;

	if (!PAGE_ALIGNED(a->va))
		return -EINVAL;

	ret = anchor_get_task(a->pid, &task);
	if (ret)
		return ret;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	mutex_lock(&anchor_lock);

	f = find_frame(a->handle);
	if (!f) {
		ret = -ENOENT;
		goto out_mm;
	}
	if (find_transplant(a->pid, a->va)) {
		/* One transplant per (pid, va): RESTORE first. */
		ret = -EBUSY;
		goto out_mm;
	}
	if (transplant_count >= ANCHOR_MAX_TRANSPLANTS) {
		ret = -EBUSY;
		goto out_mm;
	}

	rec = kzalloc(sizeof(*rec), GFP_KERNEL);
	if (!rec) {
		ret = -ENOMEM;
		goto out_mm;
	}

	mmap_read_lock(mm);
	vma = find_vma(mm, a->va);
	if (!vma || vma->vm_start > a->va) {
		ret = -ENOENT;
		goto out_unlock_mm;
	}
	if (vma->vm_flags & (VM_PFNMAP | VM_MIXEDMAP | VM_HUGETLB | VM_IO)) {
		pr_err("transplant: va %llx is a special mapping — refusing\n",
		       a->va);
		ret = -EINVAL;
		goto out_unlock_mm;
	}

	ret = anchor_check_base_pte(mm, a->va);
	if (ret)
		goto out_unlock_mm;

	ret = anchor_follow_pte(mm, a->va, &ptep, &ptl);
	if (ret) {
		if (ret == -EINVAL)
			pr_err("transplant: no present PTE at %llx - the target page is not resident (park the victim with the page faulted in first) or the page-table walk refused\n",
				a->va);
		goto out_unlock_mm;
	}

	old = READ_ONCE(*ptep);
	if (!pte_present(old)) {
		pte_unmap_unlock(ptep, ptl);
		pr_err("transplant: the PTE at %llx is not present — park the victim first\n",
		       a->va);
		ret = -EBUSY;
		goto out_unlock_mm;
	}

	/* Same prot bits, new frame: keep every flag (present/rw/user/nx/
	 * accessed/dirty) and swap only the physical-address bits. */
	new = pfn_pte(f->pfn, __pgprot(pte_val(old) & PTE_FLAGS_MASK));
	set_pte_at(mm, a->va, ptep, new);
	a->old_pfn = (u64)pte_pfn(old);
	pte_unmap_unlock(ptep, ptl);
	mmap_read_unlock(mm);
	anchor_flush_tlb(mm, a->va);

	rec->mm = mm;
	rec->va = a->va;
	rec->pid = a->pid;
	rec->old_pte = old;
	rec->old_pfn = pte_pfn(old);
	rec->flippy_pfn = f->pfn;
	rec->frame = f;
	INIT_LIST_HEAD(&rec->list);
	list_add(&rec->list, &transplant_list);
	transplant_count++;
	mutex_unlock(&anchor_lock);

	pr_info("transplant: pid %llu va %llx: pfn %05lx -> pinned pfn %05lx (handle %llu)\n",
		a->pid, a->va, rec->old_pfn, f->pfn, a->handle);
	return 0;

out_unlock_mm:
	mmap_read_unlock(mm);
	kfree(rec);
out_mm:
	mutex_unlock(&anchor_lock);
	mmput(mm);
	return ret;
}

static int anchor_query(struct anchor_query_args *a)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t pte;
	int ret;

	a->pfn = 0;
	a->present = 0;

	if (!PAGE_ALIGNED(a->va))
		return -EINVAL;

	ret = anchor_get_task(a->pid, &task);
	if (ret)
		return ret;
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	mmap_read_lock(mm);
	vma = find_vma(mm, a->va);
	if (!vma || vma->vm_start > a->va) {
		ret = -ENOENT;
		goto out;
	}
	ret = anchor_follow_pte(mm, a->va, &ptep, &ptl);
	if (ret) {
		/* follow_pte refuses non-present PTEs with -EINVAL: that is a
	 * graceful "not present" answer for a peek, not an error. */
		if (ret == -EINVAL)
			ret = 0;
		goto out;
	}
	pte = READ_ONCE(*ptep);
	if (pte_present(pte)) {
		a->present = 1;
		a->pfn = (u64)pte_pfn(pte);
	}
	pte_unmap_unlock(ptep, ptl);
	ret = 0;
out:
	mmap_read_unlock(mm);
	mmput(mm);
	return ret;
}

/*
 * Pure record-key lookup (the pid is NOT resolved): the restore works
 * even after the target process exited, because the record holds the
 * mm alive. The integrity check refuses when the victim's PTE changed
 * under the transplant.
 */
static int anchor_restore(struct anchor_restore_args *a)
{
	struct transplant_rec *rec;
	pte_t *ptep;
	spinlock_t *ptl;
	pte_t cur;
	int ret;

	if (!PAGE_ALIGNED(a->va))
		return -EINVAL;

	mutex_lock(&anchor_lock);
	rec = find_transplant(a->pid, a->va);
	if (!rec) {
		mutex_unlock(&anchor_lock);
		return -ENOENT;
	}

	mmap_read_lock(rec->mm);
	ret = anchor_follow_pte(rec->mm, a->va, &ptep, &ptl);
	if (ret) {
		mmap_read_unlock(rec->mm);
		mutex_unlock(&anchor_lock);
		return ret;
	}
	cur = READ_ONCE(*ptep);
	if (!pte_present(cur) || pte_pfn(cur) != rec->flippy_pfn) {
		pte_unmap_unlock(ptep, ptl);
		mmap_read_unlock(rec->mm);
		mutex_unlock(&anchor_lock);
		pr_err("restore: the PTE at (pid %llu, %llx) no longer points at the anchored frame %05lx — the victim's mapping changed under the transplant\n",
		       a->pid, a->va, rec->flippy_pfn);
		return -EINVAL;
	}
	set_pte_at(rec->mm, a->va, ptep, rec->old_pte);
	pte_unmap_unlock(ptep, ptl);
	mmap_read_unlock(rec->mm);
	anchor_flush_tlb(rec->mm, a->va);

	a->restored_pfn = (u64)rec->old_pfn;
	list_del(&rec->list);
	transplant_count--;
	mutex_unlock(&anchor_lock);

	mmput(rec->mm);
	pr_info("restore: pid %llu va %llx back to pfn %05lx\n",
		a->pid, a->va, rec->old_pfn);
	kfree(rec);
	return 0;
}

static int anchor_unbind(struct anchor_unbind_args *a)
{
	struct bound_frame *f;
	struct page *page;

	mutex_lock(&anchor_lock);
	f = find_frame(a->handle);
	if (!f) {
		mutex_unlock(&anchor_lock);
		return -ENOENT;
	}
	if (find_transplant_by_frame(f)) {
		/* The ordering law: RESTORE before UNBIND. */
		mutex_unlock(&anchor_lock);
		return -EBUSY;
	}
	list_del(&f->list);
	bound_count--;
	page = f->page;
	mutex_unlock(&anchor_lock);

	unpin_user_page(page);
	kfree(f);
	pr_info("unbind: handle %llu unpinned\n", a->handle);
	return 0;
}

static int anchor_status(struct anchor_status_args *a)
{
	mutex_lock(&anchor_lock);
	a->bound_frames = bound_count;
	a->transplants = transplant_count;
	mutex_unlock(&anchor_lock);
	a->kernel_version = LINUX_VERSION_CODE;
	return 0;
}

static long anchor_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	int ret;

	switch (cmd) {
	case ANCHOR_BIND: {
		struct anchor_bind_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = anchor_bind(&a);
		if (!ret && copy_to_user(uarg, &a, sizeof(a)))
			return -EFAULT;
		return ret;
	}
	case ANCHOR_TRANSPLANT: {
		struct anchor_transplant_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = anchor_transplant(&a);
		if (!ret && copy_to_user(uarg, &a, sizeof(a)))
			return -EFAULT;
		return ret;
	}
	case ANCHOR_QUERY: {
		struct anchor_query_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = anchor_query(&a);
		if (!ret && copy_to_user(uarg, &a, sizeof(a)))
			return -EFAULT;
		return ret;
	}
	case ANCHOR_RESTORE: {
		struct anchor_restore_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = anchor_restore(&a);
		if (!ret && copy_to_user(uarg, &a, sizeof(a)))
			return -EFAULT;
		return ret;
	}
	case ANCHOR_UNBIND: {
		struct anchor_unbind_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		return anchor_unbind(&a);
	}
	case ANCHOR_STATUS: {
		struct anchor_status_args a;

		if (copy_from_user(&a, uarg, sizeof(a)))
			return -EFAULT;
		ret = anchor_status(&a);
		if (!ret && copy_to_user(uarg, &a, sizeof(a)))
			return -EFAULT;
		return ret;
	}
	default:
		return -ENOTTY;
	}
}

static int anchor_open(struct inode *inode, struct file *file)
{
	/* The facility is a privileged experiment tier: root only. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

static const struct file_operations anchor_fops = {
	.owner = THIS_MODULE,
	.open = anchor_open,
	.unlocked_ioctl = anchor_ioctl,
	.compat_ioctl = anchor_ioctl,
};

static struct miscdevice anchor_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "anchor",
	.fops = &anchor_fops,
	.mode = 0600,
};

static int __init anchor_init(void)
{
	int ret;

	/* The ABI laws, enforced at load time: a drifted build fails at
	 * insmod instead of corrupting ioctl arguments. */
	BUILD_BUG_ON(sizeof(struct anchor_bind_args) != 4 * sizeof(__u64));
	BUILD_BUG_ON(sizeof(struct anchor_transplant_args) != 4 * sizeof(__u64));
	BUILD_BUG_ON(sizeof(struct anchor_query_args) != 4 * sizeof(__u64));
	BUILD_BUG_ON(sizeof(struct anchor_restore_args) != 3 * sizeof(__u64));
	BUILD_BUG_ON(sizeof(struct anchor_unbind_args) != 1 * sizeof(__u64));
	BUILD_BUG_ON(sizeof(struct anchor_status_args) != 3 * sizeof(__u64));

	ret = misc_register(&anchor_misc);
	if (ret) {
		pr_err("misc_register failed: %d\n", ret);
		return ret;
	}
	pr_info("/dev/anchor registered (deterministic frame anchoring; %s-form follow_pte)\n",
#ifdef ANCHOR_PTE_MM_FORM
		"mm"
#else
		"vma"
#endif
		);
	return 0;
}

static void __exit anchor_exit(void)
{
	struct transplant_rec *rec, *rec_n;
	struct bound_frame *f, *f_n;
	pte_t *ptep;
	spinlock_t *ptl;

	/* Never leave an alias behind: restore everything still live. */
	mutex_lock(&anchor_lock);
	list_for_each_entry_safe(rec, rec_n, &transplant_list, list) {
		bool restored = false;

		mmap_read_lock(rec->mm);
		if (!anchor_follow_pte(rec->mm, rec->va, &ptep, &ptl)) {
			pte_t cur = READ_ONCE(*ptep);

			if (pte_present(cur) && pte_pfn(cur) == rec->flippy_pfn) {
				set_pte_at(rec->mm, rec->va, ptep, rec->old_pte);
				restored = true;
			}
			pte_unmap_unlock(ptep, ptl);
		}
		mmap_read_unlock(rec->mm);
		if (restored) {
			anchor_flush_tlb(rec->mm, rec->va);
			pr_info("exit-restore: pid %llu va %llx back to pfn %05lx\n",
				rec->pid, rec->va, rec->old_pfn);
		} else {
			pr_err("exit-restore: (pid %llu, %llx) unmapped or changed under the transplant - leaving it\n",
				rec->pid, rec->va);
		}
		list_del(&rec->list);
		mmput(rec->mm);
		kfree(rec);
	}
	list_for_each_entry_safe(f, f_n, &bound_list, list) {
		list_del(&f->list);
		unpin_user_page(f->page);
		kfree(f);
	}
	mutex_unlock(&anchor_lock);

	misc_deregister(&anchor_misc);
	pr_info("unloaded\n");
}

module_init(anchor_init);
module_exit(anchor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SWAGE contributors");
MODULE_DESCRIPTION("Deterministic physical-frame anchoring for Rowhammer placement research (/dev/anchor)");
MODULE_VERSION("0.1");
