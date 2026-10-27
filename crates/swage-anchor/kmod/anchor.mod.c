#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xb355227a, "find_get_pid" },
	{ 0x25679007, "get_pid_task" },
	{ 0xc08ebf33, "put_pid" },
	{ 0x47d78282, "pcpu_hot" },
	{ 0x296695f, "refcount_warn_saturate" },
	{ 0xf680198d, "pv_ops" },
	{ 0xd4ec10e6, "BUG_func" },
	{ 0x4dfa8d4b, "mutex_lock" },
	{ 0x5a5a2271, "__cpu_online_mask" },
	{ 0x63f835ba, "on_each_cpu_cond_mask" },
	{ 0x25493e5, "mmput" },
	{ 0x37a0cba, "kfree" },
	{ 0xda3942b7, "__tracepoint_mmap_lock_start_locking" },
	{ 0x668b19a1, "down_read" },
	{ 0x5b0c3509, "__tracepoint_mmap_lock_acquire_returned" },
	{ 0x61a40209, "follow_pte" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x2469810f, "__rcu_read_unlock" },
	{ 0x6ed4f980, "__tracepoint_mmap_lock_released" },
	{ 0x53b954a2, "up_read" },
	{ 0x15568ad0, "__mmap_lock_do_trace_released" },
	{ 0x11901e5c, "__mmap_lock_do_trace_acquire_returned" },
	{ 0x7835bbb3, "__mmap_lock_do_trace_start_locking" },
	{ 0x1d19f77b, "physical_mask" },
	{ 0xc5126736, "unpin_user_page" },
	{ 0x3213f038, "mutex_unlock" },
	{ 0x1e8714c9, "misc_deregister" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0x858dcc02, "get_task_mm" },
	{ 0x931d4d0c, "find_vma" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x30986499, "pin_user_pages_remote" },
	{ 0xbcb36fe4, "hugetlb_optimize_vmemmap_key" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0xff1b9023, "kmalloc_caches" },
	{ 0x36f6a184, "kmalloc_trace" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x3611ad18, "__put_task_struct" },
	{ 0x72d79d83, "pgdir_shift" },
	{ 0xe16cab4a, "boot_cpu_data" },
	{ 0x8a35b432, "sme_me_mask" },
	{ 0xdad13544, "ptrs_per_p4d" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xc512626a, "__supported_pte_mask" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x54cd4f67, "misc_register" },
	{ 0x122c3a7e, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0xc6cbbc89, "capable" },
	{ 0x40a0aafc, "__flush_tlb_all" },
	{ 0x60ea0e27, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "F225BCB225F6979E46FA558");
