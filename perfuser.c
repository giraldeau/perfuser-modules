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
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/sched.h>

#include "perfuser-abi.h"

static struct proc_dir_entry *perfuser_proc_dentry;

void perf_output_sample_probe(struct perf_output_handle *handle,
			struct perf_event_header *header,
			struct perf_sample_data *data,
			struct perf_event *event)
{
	int ret;
	struct task_struct *task;

	task = get_current();

	if (printk_ratelimit())
		printk("perf_output_sample_probe task=%d %s\n", task->pid, task->comm);

	// int sig, struct siginfo *info, struct task_struct *p)
	if (strcmp("test_ioctl", task->comm) == 0) {
		ret = send_sig_info(SIGUSR1, SEND_SIG_NOINFO, task);
		if (ret < 0)
			printk("send_sig_info error=%d\n", ret);
		else
			printk("send_sig_info OK\n");
	}

    jprobe_return();
    return;
}

static struct jprobe perf_sample_jprobe = {
		.entry = perf_output_sample_probe,
		.kp = {
			.symbol_name = "perf_output_sample",
		},
};


long perfuser_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
	case PERFUSER_REGISTER:
		printk("perfuser_ioctl register %p 0x%x 0x%lx\n", file, cmd, arg);
		break;
	case PERFUSER_UNREGISTER:
		printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
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
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
			NULL, &perfuser_fops, NULL);

	if (!perfuser_proc_dentry) {
		printk(KERN_ERR "Error creating perfuser control file\n");
		ret = -ENOMEM;
		goto error;
	}

	ret = register_jprobe(&perf_sample_jprobe);
	if (ret < 0) {
		printk("register_jprobe failed, returned %d\n", ret);
		ret = -1;
		goto error;
	}

	return ret;

error:
	if (perfuser_proc_dentry)
		remove_proc_entry(PERFUSER_PROC, NULL);

	return ret;
}
module_init(perfuser_init);

void __exit perfuser_exit(void)
{
	if (perfuser_proc_dentry)
		remove_proc_entry(PERFUSER_PROC, NULL);
	unregister_jprobe(&perf_sample_jprobe);
}
module_exit(perfuser_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Perf sample user addons");
MODULE_VERSION("0.0.1");
