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
	struct rcu_head rcu;
};

/* map<perfuser_key, perfuser_val> */
static DEFINE_HASHTABLE(map, 3);

/*
 * RCU related functions
 */
static void perfuser_free_val_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct perfuser_val, rcu));
}

static struct perfuser_val*
perfuser_find_val(struct perfuser_key *key, u32 hash)
{
	struct perfuser_val *val;

	hash_for_each_possible_rcu(map, val, hlist, hash) {
		if (key->ptid == val->ptid) {
			return val;
		}
	}
	return NULL;
}

static
void perfuser_irq_work(struct irq_work *work)
{
	u32 hash;
	struct perfuser_key key;
	struct perfuser_val *val;
	struct task_struct *task;

	task = get_current();

	if (printk_ratelimit())
		printk("perfuser_irq_work\n");

	key.ptid = task->tgid;
	hash = jhash(&key, sizeof(key), 0);
	rcu_read_lock();
	val = perfuser_find_val(&key, hash);
	if (val != NULL) {
		send_sig_info(val->signo, SEND_SIG_NOINFO, task);
	}
	rcu_read_unlock();
}

static struct irq_work irq_w = { .func = perfuser_irq_work };

/*
 * Probe called when a perf sample is generated
 */
static int perf_output_sample_probe(struct kprobe *p, struct pt_regs *regs)
{
	irq_work_queue(&irq_w);
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
	u32 hash;
	struct perfuser_key key;
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

	key.ptid = task->pid;
	hash = jhash(&key, sizeof(key), 0);

	switch(info.cmd) {
	case PERFUSER_REGISTER:
		if (!check_signal(info.sig))
			return -EINVAL;
		/* check if already registered */
		rcu_read_lock();
		val = perfuser_find_val(&key, hash);
		if (val) {
			rcu_read_unlock();
			break;
		}
		rcu_read_unlock();
		/* do registration */
		val = kzalloc(sizeof(struct perfuser_val), GFP_KERNEL);
		val->ptid = key.ptid;
		val->signo = info.sig;
		hash_add_rcu(map, &val->hlist, hash);
		printk("perfuser_ioctl register %p 0x%x 0x%lx\n", file, cmd, arg);
		break;
	case PERFUSER_UNREGISTER:
		rcu_read_lock();
		val = perfuser_find_val(&key, hash);
		if (val) {
			hash_del_rcu(&val->hlist);
			call_rcu(&val->rcu, perfuser_free_val_rcu);
			printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
		}
		rcu_read_unlock();
		break;
	case PERFUSER_DEBUG:
		printk("perfuser_ioctl debug\n");
		rcu_read_lock();
		hash_for_each_rcu(map, bkt, val, hlist) {
			printk("perfuser_ioctl task registered %d %d\n", val->ptid, val->signo);
		}
		rcu_read_unlock();
		break;
	case PERFUSER_SENDSIG:
		if (!check_signal(info.sig))
			return -EINVAL;
		ret = send_sig_info(info.sig, SEND_SIG_NOINFO, task);
		break;
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
