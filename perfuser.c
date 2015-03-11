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
#include <linux/irq_work.h>
#include <linux/percpu.h>

#include "wrapper/vmalloc.h"
#include "perfuser-abi.h"

static struct proc_dir_entry *perfuser_proc_dentry;

struct perfuser_key {
	pid_t tgid;
} __attribute__((__packed__));

struct perfuser_val {
	pid_t tgid;
	int signo;
	struct perfuser_siginfo info;
	struct hlist_node hlist;
	struct rcu_head rcu;
};


/* map<perfuser_key, perfuser_val> */
static DEFINE_HASHTABLE(map, 3);

DEFINE_SPINLOCK(map_lock);

/*
 * RCU related functions
 */
static void perfuser_free_val_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct perfuser_val, rcu));
}

static struct perfuser_val*
perfuser_find_val(struct task_struct *task)
{
	u32 hash;
	struct perfuser_key key;
	struct perfuser_val *val;

	key.tgid = task->tgid;
	hash = jhash(&key, sizeof(key), 0);
	hash_for_each_possible_rcu(map, val, hlist, hash) {
		if (key.tgid == val->tgid) {
			return val;
		}
	}
	return NULL;
}

static int
perfuser_register(struct task_struct *task, int signo)
{
	u32 hash;
	struct perfuser_key key;
	struct perfuser_val *val;

	rcu_read_lock();
	val = perfuser_find_val(task);
	if (val) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	val = kzalloc(sizeof(struct perfuser_val), GFP_KERNEL);
	if (!val)
		return -ENOMEM;
	val->signo = signo;
	val->tgid = task->tgid;
	key.tgid = task->tgid;
	hash = jhash(&key, sizeof(key), 0);
	spin_lock(&map_lock);
	hash_add_rcu(map, &val->hlist, hash);
	spin_unlock(&map_lock);
	return 0;
}

static void perfuser_unregister(struct task_struct *task)
{
	struct perfuser_val *val;

	rcu_read_lock();
	val = perfuser_find_val(task);
	if (val) {
		spin_lock(&map_lock);
		hash_del_rcu(&val->hlist);
		spin_unlock(&map_lock);
		call_rcu(&val->rcu, perfuser_free_val_rcu);
	}
	rcu_read_unlock();
}

static
void perfuser_irq_work(struct irq_work *entry)
{
	struct perfuser_val *val;
	struct task_struct *task;

	task = get_current();

	if (printk_ratelimit())
		printk("perfuser_irq_work\n");

	rcu_read_lock();
	val = perfuser_find_val(task);
	if (val != NULL) {
		send_sig_info(val->signo, (void *)&val->info, task);
	}
	rcu_read_unlock();
}

static struct irq_work irq_w = { .func = perfuser_irq_work };

/*
 * Probe called when a perf sample is generated
 */
static int perf_output_sample_probe(struct kprobe *p, struct pt_regs *regs)
{
	struct perfuser_val *val;
	struct perf_output_handle *handle = (void *) regs->di;

	rcu_read_lock();
	val = perfuser_find_val(get_current());
	if (val && handle && handle->event) {
		val->info._perf.type = handle->event->attr.type;
		val->info._perf.config = handle->event->attr.config;
	}
	rcu_read_unlock();
	irq_work_queue(&irq_w);

	/*
	if (handle || handle->event) {
		printk("handle->event->attr.type=%d\n", handle->event->attr.type);
		printk("handle->event->attr.config=%llu\n", handle->event->attr.config);
	}
	*/
	return 0;
}

static struct kprobe perf_sample_kprobe = {
	.symbol_name = "perf_output_end",
	.pre_handler = perf_output_sample_probe,
};

static int check_signal(unsigned long sig)
{
	return (sig == SIGUSR1 || sig == SIGUSR2);
}

long perfuser_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct perfuser_val *val;
	struct perfuser_info info;
	struct task_struct *task = get_current();
	int ret = 0;
	int bkt;
	void __user *uinfo = (void *) arg;

	if (cmd != PERFUSER_IOCTL)
		return -ENOIOCTLCMD;

	if (copy_from_user(&info, uinfo, sizeof(struct perfuser_info)))
		return -EFAULT;

	switch(info.cmd) {
	case PERFUSER_REGISTER:
		if (!check_signal(info.signo))
			return -EINVAL;
		/* do registration */
		ret = perfuser_register(task, info.signo);
		printk("perfuser_ioctl register %p 0x%x 0x%lx\n", file, cmd, arg);
		break;
	case PERFUSER_UNREGISTER:
		perfuser_unregister(task);
		printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
		break;
	case PERFUSER_DEBUG:
		printk("perfuser_ioctl debug\n");
		rcu_read_lock();
		hash_for_each_rcu(map, bkt, val, hlist) {
			printk("perfuser_ioctl task registered %d %d\n", val->tgid, val->signo);
		}
		rcu_read_unlock();
		break;
	case PERFUSER_SENDSIG:
	{
		struct perfuser_siginfo si;
		if (!check_signal(info.signo))
			return -EINVAL;
		si._info.si_signo = info.signo;
		si._info.si_errno = 0;
		si._info.si_code = SI_KERNEL;
		si._perf.type = PERF_TYPE_SOFTWARE;
		si._perf.config = PERF_COUNT_SW_DUMMY;
		ret = send_sig_info(info.signo, (void *) &si, task);
		break;
	}
	case PERFUSER_NONE: // do nothing
		break;
	default:
		ret = -ENOTSUPP;
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
	struct perfuser_val *val;
	int bkt;

	if (perfuser_proc_dentry)
		remove_proc_entry(PERFUSER_PROC, NULL);

	unregister_kprobe(&perf_sample_kprobe);

	irq_work_sync(&irq_w);

	rcu_read_lock();
	hash_for_each_rcu(map, bkt, val, hlist) {
		hash_del_rcu(&val->hlist);
		call_rcu(&val->rcu, perfuser_free_val_rcu);
	}
	rcu_read_unlock();
	synchronize_rcu();
}
module_exit(perfuser_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Perf sample user addons");
MODULE_VERSION("0.0.1");
