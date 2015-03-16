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
	pid_t pid;
} __attribute__((__packed__));

struct pval {
	pid_t pid;
	pid_t tgid;
	int enabled;
	int signo;
	atomic_t count_sig;
	atomic_t count_irq;
	atomic_t count_nmi;
	atomic_t count_err;
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
	kmem_cache_free(cachep, val);
}

#define MATCH_PID 0
#define MATCH_TGID 1
static struct pval*
map_get(struct pkey *key, int group)
{
	u32 hash;
	struct pval *val;

	hash = jhash(key, sizeof(*key), 0);
	hash_for_each_possible_rcu(map, val, hlist, hash) {
		if (group == MATCH_TGID && key->pid == val->tgid) {
			return val;
		}
		if (group == MATCH_PID && key->pid == val->pid) {
			return val;
		}
	}
	return NULL;
}
static struct pval*
map_put(struct pkey *key, struct pval *val)
{
	u32 hash = jhash(key, sizeof(*key), 0);
	spin_lock(&lock);
	hash_add_rcu(map, &val->hlist, hash);
	spin_unlock(&lock);
	return val;
}

/* Not necessary at this time */
/*
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
*/

static struct pval*
perfuser_register(int pid, int tgid, int signo)
{
	struct pkey key = { .pid = pid };
	struct pval *val;

	val = kmem_cache_alloc(cachep, GFP_ATOMIC);
	if (!val) {
		WARN_ONCE(!val, "perfuser_register failed for pid=%d tgid=%d\n", pid, tgid);
		return NULL;
	}
	memset(val, 0, sizeof(*val));
	val->pid = pid;
	val->tgid = tgid;
	val->enabled = 1;
	val->signo = signo;
	atomic_set(&val->count_sig, 0);
	atomic_set(&val->count_irq, 0);
	atomic_set(&val->count_nmi, 0);
	atomic_set(&val->count_err, 0);
	atomic_set(&val->delayed, 0);
	atomic_set(&val->ts, 0);
	val->irq_work.func = perfuser_irq_work;
	printk("perfuser_register %d %d\n", pid, tgid);
	return map_put(&key, val);
}

static void perfuser_unregister(int tgid)
{
	int bkt;
	struct pval *val;

	rcu_read_lock();
	hash_for_each_rcu(map, bkt, val, hlist) {
		if (val->tgid == tgid) {
			printk("perfuser_unregister %d %d\n", val->pid, val->tgid);
			irq_work_sync(&val->irq_work);
			hash_del_rcu(&val->hlist);
			call_rcu(&val->rcu, perfuser_free_val_rcu);
		}
	}
	rcu_read_unlock();
}

static
void perfuser_irq_work(struct irq_work *entry)
{
	struct pval *val;
	int ret;
	struct task_struct *task = get_current();

	rcu_read_lock();
	val = container_of(entry, struct pval, irq_work);

	ret = task->pid != val->pid || task->tgid != val->tgid;
	if (ret) {
		WARN_ONCE(ret, "perfuser_irq_work task does not match pval\n");
		rcu_read_unlock();
		return;
	}

	if (sigismember(&task->blocked, val->signo))
		atomic_inc(&val->delayed);
	atomic_inc(&val->count_irq);
	ret = send_sig_info(val->signo, SEND_SIG_NOINFO, task);
	if (ret == 0)
		atomic_inc(&val->count_sig);
	rcu_read_unlock();
}

/*
 * Probe called when a perf sample is generated
 */
static int perf_output_sample_probe(struct kprobe *p, struct pt_regs *regs)
{
	struct pval *val;
	struct pval *val_sibling;
	struct pkey key;
	struct task_struct *task = get_current();
	//struct perf_output_handle *handle = (void *) regs->di;
	/*
	 * FIXME: is it possible to get migrated between the NMI and the IRQ?
	 */
	rcu_read_lock();
	key.pid = task->pid;
	val = map_get(&key, MATCH_PID);
	if (val)
		goto found;
	/* check if a sibling thread is registered */
	key.pid = task->tgid;
	val_sibling = map_get(&key, MATCH_TGID);
	if (!val_sibling)
		goto out;
	val = perfuser_register(task->pid, task->tgid, val_sibling->signo);
	if (!val) {
		atomic_inc(&val_sibling->count_err);
		goto out;
	}

found:
	printk("perf_output_sample_probe\n");
	atomic_inc(&val->count_nmi);
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

int perfuser_release(struct inode *inode, struct file *file)
{
	struct task_struct *task = get_current();
	perfuser_unregister(task->tgid);
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
		printk("perfuser_ioctl register %d %p 0x%x 0x%lx\n", ret, file, cmd, arg);
		/* do registration of the group leader */
		key.pid = task->pid;
		rcu_read_lock();
		val = map_get(&key, MATCH_PID);
		if (!val)
			val = perfuser_register(task->pid, task->tgid, info.signo);
		if (!val)
			ret = -ENOMEM;
		rcu_read_unlock();
		break;
	case PERFUSER_UNREGISTER:
		// unregister all threads
		perfuser_unregister(task->tgid);
		printk("perfuser_ioctl unregister %p 0x%x\n", file, cmd);
		break;
	case PERFUSER_DEBUG:
		printk("perfuser_ioctl debug\n");
		printk("%5s %5s %5s %5s %5s %5s\n", "pid", "tid", "nmi", "irq", "sig", "err");
		rcu_read_lock();
		hash_for_each_rcu(map, bkt, val, hlist) {
			printk("%5d %5d %5d %5d %5d %5d\n",
					val->tgid, val->pid,
					atomic_read(&val->count_nmi),
					atomic_read(&val->count_irq),
					atomic_read(&val->count_sig),
					atomic_read(&val->count_err));
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
