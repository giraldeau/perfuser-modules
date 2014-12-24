 /*
 * perfuser.c
 *
 *  Created on: Dec 9, 2014
 *      Author: francis
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/perf_event.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/types.h>

#include "wrapper/vmalloc.h"
#include "perfuser-abi.h"

static struct proc_dir_entry *perfuser_proc_dentry;

struct perfuser_key {
	pid_t ptid;
} __attribute__((__packed__));

struct perfuser_val {
	pid_t ptid;
	int signo;
	struct hlist_node hlist;
};

/* map<ptid, perfuser_client> */
static DEFINE_HASHTABLE(map, 3);
static DEFINE_SPINLOCK(map_lock);

static int perf_output_sample_probe(struct kprobe *p, struct pt_regs *regs)
{
	int ret;
	u32 hash;
	struct hlist_node *next;
	struct perfuser_key key;
	struct perfuser_val *val;
	struct task_struct *task;

	task = get_current();

	key.ptid = task->pid;
	hash = jhash(&key, sizeof(key), 0);
	hash_for_each_possible_safe(map, val, next, hlist, hash) {
		if (val->ptid != key.ptid)
			continue;
		/* send signal to this specific thread */
		ret = send_sig_info(SIGUSR1, SEND_SIG_NOINFO, task);
		break;
	}
	return 0;
}

static struct kprobe perf_sample_kprobe = {
	.symbol_name = "perf_output_end",
	.pre_handler = perf_output_sample_probe,
};


long perfuser_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	u32 hash;
	unsigned long flags;
	struct perfuser_key key;
	struct perfuser_val *val;
	struct hlist_node *next;
	struct task_struct *task = get_current();
	int found = 0;
	int ret = 0;
	int bkt;

	key.ptid = task->pid;
	hash = jhash(&key, sizeof(key), 0);

	switch(cmd) {
	case PERFUSER_REGISTER:
		hash_for_each_possible_safe(map, val, next, hlist, hash) {
			if (val->ptid == key.ptid) {
				// already registered, nothing to do
				found = 1;
				break;
			}
		}
		if (found)
			break;
		val = kzalloc(sizeof(struct perfuser_val), GFP_KERNEL);
		val->ptid = key.ptid;
		val->signo = SIGUSR1;
		spin_lock_irqsave(&map_lock, flags);
		hash_add(map, &val->hlist, hash);
		spin_unlock_irqrestore(&map_lock, flags);
		printk("perfuser_ioctl register %p 0x%x 0x%lx\n", file, cmd, arg);
		break;
	case PERFUSER_UNREGISTER:
		hash_for_each_possible_safe(map, val, next, hlist, hash) {
			if (val->ptid != key.ptid)
				continue;
			spin_lock_irqsave(&map_lock, flags);
			hash_del(&val->hlist);
			spin_unlock_irqrestore(&map_lock, flags);
			kfree(val);
			break;
		}
		printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
		break;
	case PERFUSER_DEBUG:
		printk("perfuser_ioctl debug\n");
		hash_for_each_safe(map, bkt, next, val, hlist) {
			printk("perfuser_ioctl task registered %d %d\n", val->ptid, val->signo);
		}
		break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	return ret;
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

	ret = register_kprobe(&perf_sample_kprobe);
	if (ret < 0) {
		printk("register_kprobe failed, returned %d\n", ret);
		ret = -1;
		goto error;
	}
	printk("kprobe_ftrace=%d\n", kprobe_ftrace(&perf_sample_kprobe));
	printk("kprobe_optimized=%d\n", kprobe_optimized(&perf_sample_kprobe));

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
	unregister_kprobe(&perf_sample_kprobe);
}
module_exit(perfuser_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Perf sample user addons");
MODULE_VERSION("0.0.1");
