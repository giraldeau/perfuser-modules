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
#include <linux/fs.h>
#include <linux/slab.h>

#include "wrapper/vmalloc.h"
#include "perfuser-abi.h"

static struct proc_dir_entry *perfuser_proc_dentry;

struct pkey {
	struct task_struct *task;
} __attribute__((__packed__));

struct pval {
	struct task_struct *task;
	int enabled;
	int signo;
	atomic_t count;
	atomic_t delayed;
	atomic_t ts;
	struct irq_work irq_work;
	struct hlist_node hlist;
	struct rcu_head rcu;
};

/* map<pkey, pval> */
static DEFINE_HASHTABLE(map, 3);
static DEFINE_SPINLOCK(lock);

static struct kmem_cache *cachep;

static void perfuser_irq_work(struct irq_work *entry);

/*
 * RCU related functions
 */
static void perfuser_free_val_rcu(struct rcu_head *rcu)
{
	struct pval *val;

	val = container_of(rcu, struct pval, rcu);
	/*
	 * I think irq_work_sync() is not required: synchronize_rcu()
	 * makes sure no irq_work is in use.
	 */
	kfree(val);
}

static struct pval*
map_get(struct pkey *key)
{
	u32 hash;
	struct pval *val;

	hash = jhash(&key, sizeof(key), 0);
	hash_for_each_possible_rcu(map, val, hlist, hash) {
		if (key->task == val->task) {
			return val;
		}
	}
	return NULL;
}
static struct pval*
map_put(struct pkey *key, struct pval *val)
{
	u32 hash = jhash(&key, sizeof(key), 0);
	spin_lock(&lock);
	hash_add_rcu(map, &val->hlist, hash);
	spin_unlock(&lock);
	return val;
}

static struct pval*
map_remove(struct pkey *key)
{
	struct pval *val = map_get(key);
	if (val) {
		spin_lock(&lock);
		hash_del_rcu(&val->hlist);
		spin_unlock(&lock);
	}
	return NULL;
}

static struct pval*
perfuser_register(struct task_struct *task, int signo)
{
	struct pkey key = { .task = task };
	struct pval *val;

	val = kmem_cache_alloc(cachep, GFP_ATOMIC);
	if (!val)
		return NULL;
	memset(val, 0, sizeof(*val));
	val->task = task;
	val->enabled = 1;
	val->signo = signo;
	atomic_set(&val->count, 0);
	atomic_set(&val->delayed, 0);
	atomic_set(&val->ts, 0);
	val->irq_work.func = perfuser_irq_work;
	return map_put(&key, val);
}

static void perfuser_unregister(struct task_struct *task)
{
	struct pval *val;
	struct pkey key = { .task = task };

	rcu_read_lock();
	val = map_remove(&key);
	if (val) {
		call_rcu(&val->rcu, perfuser_free_val_rcu);
	}
	rcu_read_unlock();
}

static
void perfuser_irq_work(struct irq_work *entry)
{
	struct pval *val;

	rcu_read_lock();
	val = container_of(entry, struct pval, irq_work);
	if (sigismember(&val->task->blocked, val->signo))
		atomic_inc(&val->delayed);
	send_sig_info(val->signo, SEND_SIG_NOINFO, val->task);
	rcu_read_unlock();
	if (printk_ratelimit())
		printk("perfuser_irq_work\n");
}

/*
 * Probe called when a perf sample is generated
 */
static int perf_output_sample_probe(struct kprobe *p, struct pt_regs *regs)
{
	struct pval *val;
	struct pkey key;
	struct task_struct *task = get_current();
	//struct perf_output_handle *handle = (void *) regs->di;
	/*
	 * FIXME: is it possible to get migrated between the NMI and the IRQ?
	 */
	rcu_read_lock();
	key.task = task;
	val = map_get(&key);
	if (val)
		goto found;
	/* check if the group leader is registered */
	key.task = task->group_leader;
	val = map_get(&key);
	if (!val)
		goto out;
	// the group leader is found, create entry for this thread
	val = perfuser_register(task, val->signo);
	if (!val)
		goto out;

found:
	atomic_inc(&val->count);
	irq_work_queue(&val->irq_work);
out:
	rcu_read_unlock();
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

int perfuser_open(struct inode *inode, struct file *file)
{
	return 0;
}

ssize_t perfuser_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
	return 0;
}

int perfuser_flush(struct file *file, fl_owner_t id)
{
	rcu_read_lock();
	perfuser_unregister(get_current());
	rcu_read_unlock();
	printk("perfuser_flush %d\n", get_current()->pid);
	return 0;
}

int perfuser_release(struct inode *inode, struct file *file)
{
	int bkt;
	struct pval *val;
	struct task_struct *task = get_current();

	rcu_read_lock();
	hash_for_each_rcu(map, bkt, val, hlist) {
		if (val->task->group_leader == task->group_leader) {
			irq_work_sync(&val->irq_work);
			hash_del_rcu(&val->hlist);
			call_rcu(&val->rcu, perfuser_free_val_rcu);
		}
	}
	rcu_read_unlock();
	printk("perfuser_release %d\n", get_current()->pid);
	return 0;
}

long perfuser_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pval *val;
	struct pkey key;
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
		/* do registration of the group leader */
		key.task = task->group_leader;
		rcu_read_lock();
		val = map_get(&key);
		if (!val) {
			val = perfuser_register(task->group_leader, info.signo);
		}
		if (!val)
			ret = -ENOMEM;
		rcu_read_unlock();
		printk("perfuser_ioctl register %d %p 0x%x 0x%lx\n", ret, file, cmd, arg);
		break;
	case PERFUSER_UNREGISTER:
		perfuser_unregister(task->group_leader);
		printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
		break;
	case PERFUSER_DEBUG:
		printk("perfuser_ioctl debug\n");
		rcu_read_lock();
		hash_for_each_rcu(map, bkt, val, hlist) {
			printk("perfuser_ioctl task registered %d %d %d\n", val->task->tgid, val->task->pid, val->signo);
		}
		rcu_read_unlock();
		break;
	case PERFUSER_SENDSIG:
	{
		siginfo_t si = {
			.si_signo = info.signo,
			.si_errno = 0,
			.si_code = SI_KERNEL,
		};
		if (!check_signal(info.signo))
			return -EINVAL;
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
	.open = perfuser_open,
	.read = perfuser_read,
	.flush = perfuser_flush,
	.release = perfuser_release,
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

	cachep = KMEM_CACHE(pval, 0);

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
	if (cachep)
		kmem_cache_destroy(cachep);

	return ret;
}
module_init(perfuser_init);

void __exit perfuser_exit(void)
{
	struct pval *val;
	int bkt;

	if (perfuser_proc_dentry)
		remove_proc_entry(PERFUSER_PROC, NULL);

	unregister_kprobe(&perf_sample_kprobe);

	rcu_read_lock();
	hash_for_each_rcu(map, bkt, val, hlist) {
		irq_work_sync(&val->irq_work);
		hash_del_rcu(&val->hlist);
		call_rcu(&val->rcu, perfuser_free_val_rcu);
	}
	rcu_read_unlock();
	synchronize_rcu();
	if (cachep)
		kmem_cache_destroy(cachep);
}
module_exit(perfuser_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Francis Giraldeau");
MODULE_DESCRIPTION("Perf sample user addons");
MODULE_VERSION("0.0.1");
