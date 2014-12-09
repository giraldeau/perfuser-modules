 /*
 * perfuser.c
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include "wrapper/vmalloc.h"

#include "perfuser-abi.h"

static struct proc_dir_entry *perfuser_proc_dentry;

long perfuser_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
	case PERFUSER_CREATE:
		printk("perfuser_ioctl %p 0x%x 0x%lx\n", file, cmd, arg);
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

static const struct file_operations perfuser_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = perfuser_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = perfuser_ioctl,
#endif
};

int __init perfuser_init(void)
{
	int ret = 0;

	wrapper_vmalloc_sync_all();
	perfuser_proc_dentry = proc_create_data(PERFUSER_PROC,
			S_IRUSR | S_IWUSR, NULL, &perfuser_fops, NULL);

	if (!perfuser_proc_dentry) {
		printk(KERN_ERR "Error creating perfuser control file\n");
		ret = -ENOMEM;
		goto error;
	}

error:
	return ret;
}
module_init(perfuser_init);

void __exit perfuser_exit(void)
{
	if (perfuser_proc_dentry)
		remove_proc_entry(PERFUSER_PROC, NULL);
}
module_exit(perfuser_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Perf sample user addons");
MODULE_VERSION("0.0.1");
