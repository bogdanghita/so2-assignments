/*
 * SO2 Tema1 - SO2 Kprobe based tracer
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>

#include "tracer.h"


MODULE_DESCRIPTION("SO2 Kprobe based tracer");
MODULE_AUTHOR("Bogdan Ghita");
MODULE_LICENSE("GPL");


#define LOG_LEVEL KERN_ALERT

#define LOCKED    0
#define UNLOCKED  1

#define FALSE     0
#define TRUE      1


static int proc_open_handler(struct inode *inode, struct file *file);
static int proc_release_handler(struct inode *inode, struct file *file);
static int proc_read_handler(struct file *file, char __user *user_buffer,
	size_t size, loff_t *offset);

static int dev_open_handler(struct inode *inode, struct file *file);
static int dev_release_handler(struct inode *inode, struct file *file);
static long dev_ioctl_handler (struct file *file, unsigned int cmd,
	unsigned long arg);

static int handler_schedule(void);
static int handler_up(struct semaphore *sem);
static int handler_down_interruptible(struct semaphore *sem);
static int handler_mutex_lock(struct mutex *lock, unsigned int subclass);
static int handler_mutex_unlock(struct mutex *lock);
static int handler_kfree(const void *objp);
static int entry_handler_kmalloc(struct kretprobe_instance *ri,
	struct pt_regs *regs);
static int handler_kmalloc(struct kretprobe_instance *ri,
	struct pt_regs *regs);


struct device_data {
	struct list_head proc_list;
	atomic_t proc_read_lock;
	spinlock_t proc_list_lock;
	int proc_read_first;
};

struct trace_data {
	int cnt_kmalloc;
	int cnt_kfree;
	int cnt_schedule;
	int cnt_up;
	int cnt_down_interruptible;
	int cnt_mutex_lock;
	int cnt_mutex_unlock;
	int mem_kmalloc;
	int mem_kfree;
};

struct mem_data {
	unsigned long addr;
	long size;
	struct list_head list;
};

struct proc_data {
	pid_t pid;
	struct trace_data t_data;
	struct list_head mem_list;
	struct list_head list;
	spinlock_t mem_list_lock;
};


static struct jprobe probe_schedule = {
	.kp = {
		.symbol_name = "schedule"
	},
	.entry = (kprobe_opcode_t *) handler_schedule
};
static struct jprobe probe_up = {
	.kp = {
		.symbol_name = "up"
	},
	.entry = (kprobe_opcode_t *) handler_up
};
static struct jprobe probe_down_interruptible = {
	.kp = {
		.symbol_name = "down_interruptible"
	},
	.entry = (kprobe_opcode_t *) handler_down_interruptible
};
static struct jprobe probe_mutex_lock = {
	.kp = {
		.symbol_name = "mutex_lock_nested"
	},
	.entry = (kprobe_opcode_t *) handler_mutex_lock
};
static struct jprobe probe_mutex_unlock = {
	.kp = {
		.symbol_name = "mutex_unlock"
	},
	.entry = (kprobe_opcode_t *) handler_mutex_unlock
};
static struct jprobe probe_kfree = {
	.kp = {
		.symbol_name = "kfree"
	},
	.entry = (kprobe_opcode_t *) handler_kfree
};
static struct kretprobe probe_kmalloc = {
	.kp = {
		.symbol_name = "__kmalloc"
	},
	.entry_handler = entry_handler_kmalloc,
	.handler = handler_kmalloc,
	.data_size  = sizeof(struct mem_data),
	.maxactive  = 40
};


/*
 * MODULE DATA
 */

static struct proc_dir_entry *proc_entry;
static struct device_data dev_data;

const struct file_operations dev_fops = {
	.owner            = THIS_MODULE,
	.open             = dev_open_handler,
	.release          = dev_release_handler,
	.unlocked_ioctl   = dev_ioctl_handler
};

const struct file_operations proc_fops = {
	.owner    = THIS_MODULE,
	.open     = proc_open_handler,
	.release  = proc_release_handler,
	.read     = proc_read_handler
};

struct miscdevice tracer_dev = {
	.minor  = TRACER_DEV_MINOR,
	.name   = TRACER_DEV_NAME,
	.fops   = &dev_fops
};


/*
 * DATA METHODS
 */

static void init_trace_data(struct trace_data *data)
{
	data->cnt_kmalloc = 0;
	data->cnt_kfree = 0;
	data->cnt_schedule = 0;
	data->cnt_up = 0;
	data->cnt_down_interruptible = 0;
	data->cnt_mutex_lock = 0;
	data->cnt_mutex_unlock = 0;
	data->mem_kmalloc = 0;
	data->mem_kfree = 0;
}

static void init_proc_data(struct proc_data *data, pid_t pid)
{
	data->pid = pid;
	init_trace_data(&data->t_data);
	spin_lock_init(&data->mem_list_lock);
	INIT_LIST_HEAD(&data->mem_list);
}

static void clean_proc_data(struct proc_data *data)
{
	struct list_head *p, *tmp;
	struct mem_data *m_data;

	spin_lock(&data->mem_list_lock);
	list_for_each_safe(p, tmp, &data->mem_list) {
		m_data = list_entry(p, struct mem_data, list);
		list_del(p);
		kfree(m_data);
	}
	spin_unlock(&data->mem_list_lock);
}

static void init_device_data(void)
{
	atomic_set(&dev_data.proc_read_lock, UNLOCKED);
	spin_lock_init(&dev_data.proc_list_lock);
	INIT_LIST_HEAD(&dev_data.proc_list);
}

static int clean_device_data(void)
{
	struct list_head *p, *tmp;
	struct proc_data *p_data;

	spin_lock(&dev_data.proc_list_lock);
	list_for_each_safe(p, tmp, &dev_data.proc_list) {
		p_data = list_entry(p, struct proc_data, list);
		list_del(p);
		clean_proc_data(p_data);
		kfree(p_data);
	}
	spin_unlock(&dev_data.proc_list_lock);

	return 0;
}

static int proc_data_to_string(char *buf, size_t size, struct proc_data *p_data)
{
	int count = 0;

	count += snprintf(buf + count, size - count, "%-6d", p_data->pid);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-8d",
		p_data->t_data.cnt_kmalloc);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-8d",
		p_data->t_data.cnt_kfree);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-12d",
		p_data->t_data.mem_kmalloc);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-12d",
		p_data->t_data.mem_kfree);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-8d",
		p_data->t_data.cnt_schedule);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-6d",
		p_data->t_data.cnt_up);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-6d",
		p_data->t_data.cnt_down_interruptible);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-6d",
		p_data->t_data.cnt_mutex_lock);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "%-6d",
		p_data->t_data.cnt_mutex_unlock);
	if (count >= size)
		return size;
	count += snprintf(buf + count, size - count, "\n");
	if (count >= size)
		return size;

	return count;
}


/*
 * PROC_LIST METHODS
 */

static struct proc_data *get_proc_data(pid_t pid)
{
	struct list_head *p;
	struct proc_data *p_data;

	// lock is done outside
	list_for_each(p, &dev_data.proc_list) {
		p_data = list_entry(p, struct proc_data, list);
		if (p_data->pid == pid)
			return p_data;
	}

	return NULL;
}

static int add_process(pid_t pid)
{
	struct proc_data *p_data;

	dprintk(LOG_LEVEL "tracer: [add_process] pid=%d\n", pid);

	// check if pid already in list
	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	spin_unlock(&dev_data.proc_list_lock);
	if (p_data != NULL) {
		dprintk(LOG_LEVEL "tracer: [add_process] process with pid=%d "
			"already added\n", pid);
		return 0;
	}

	// add new entry to proc_list
	p_data = kmalloc(sizeof(*p_data), GFP_KERNEL);
	if (!p_data)
		return -ENOMEM;
	init_proc_data(p_data, pid);

	spin_lock(&dev_data.proc_list_lock);
	list_add(&p_data->list, &dev_data.proc_list);
	spin_unlock(&dev_data.proc_list_lock);

	return 0;
}

static int remove_process(pid_t pid)
{
	struct proc_data *p_data;

	dprintk(LOG_LEVEL "tracer: [remove_process] pid=%d\n", pid);

	// remove entry from proc_list
	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		dprintk(LOG_LEVEL "tracer: [remove_process] process with "
			"pid=%d not found\n", pid);
	else
		list_del(&p_data->list);
	spin_unlock(&dev_data.proc_list_lock);

	if (p_data)
		kfree(p_data);

	return 0;
}


/*
 * FILE OPERATION HANDLERS
 */

static int dev_open_handler(struct inode *inode, struct file *file)
{
	dprintk(LOG_LEVEL "tracer: [dev_open_handler]\n");
	return 0;
}

static int dev_release_handler(struct inode *inode, struct file *file)
{
	dprintk(LOG_LEVEL "tracer: [dev_release_handler]\n");
	return 0;
}

static long dev_ioctl_handler (struct file *file, unsigned int cmd,
	unsigned long arg)
{
	dprintk(LOG_LEVEL "tracer: [dev_ioctl_handler]\n");

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		add_process(arg);
		break;
	case TRACER_REMOVE_PROCESS:
		remove_process(arg);
		break;
	default:
		return -ENOTTY;
	}

	return 0;
}

static int proc_open_handler(struct inode *inode, struct file *file)
{
	int initial_flag;

	dprintk(LOG_LEVEL "tracer: [proc_open_handler]\n");

	// the file can be opened only by one process at a time
	initial_flag = atomic_cmpxchg(&dev_data.proc_read_lock, UNLOCKED,
		LOCKED);
	if (initial_flag == LOCKED) {
		dprintk(LOG_LEVEL "tracer: device busy\n");
		return -EBUSY;
	}

	dev_data.proc_read_first = TRUE;

	return 0;
}

static int proc_release_handler(struct inode *inode, struct file *file)
{
	dprintk(LOG_LEVEL "tracer: [proc_release_handler]\n");

	// release read lock
	atomic_set(&dev_data.proc_read_lock, UNLOCKED);

	return 0;
}

static int proc_read_handler(struct file *file, char __user *user_buffer,
	size_t size, loff_t *offset)
{
	struct list_head *p;
	struct proc_data *p_data;
	int count = 0;
	char *tmp_buffer;

	dprintk(LOG_LEVEL "tracer: [proc_read_handler]\n");

	// write only what fits in the buffer in the first read() call
	if (dev_data.proc_read_first == FALSE)
		return 0;
	dev_data.proc_read_first = FALSE;

	// alloc kernel space buffer
	tmp_buffer = kmalloc(sizeof(char) * size, GFP_KERNEL);
	if (!tmp_buffer)
		return -ENOMEM;

	// print header
	count += snprintf(tmp_buffer, size, "PID   kmalloc kfree   kmalloc_mem "
		"kfree_mem   sched   up    down  lock  unlock\n");
	if (count >= size)
		return 0;

	// print items in proc_list
	spin_lock(&dev_data.proc_list_lock);
	list_for_each(p, &dev_data.proc_list) {
		p_data = list_entry(p, struct proc_data, list);
		count += proc_data_to_string(tmp_buffer + count, size - count,
			p_data);
		if (count >= size)
			break;
	}
	spin_unlock(&dev_data.proc_list_lock);
	if (count >= size)
		count = size;

	// copy data to user buffer
	if (copy_to_user(user_buffer, tmp_buffer, count))
		return -EFAULT;

	return count;
}


/*
 * PROBES
 */

static int handler_schedule(void)
{
	int pid;
	struct proc_data *p_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler;

	p_data->t_data.cnt_schedule += 1;

end_jprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int handler_up(struct semaphore *sem)
{
	int pid;
	struct proc_data *p_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler;

	p_data->t_data.cnt_up += 1;

end_jprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int handler_down_interruptible(struct semaphore *sem)
{
	int pid;
	struct proc_data *p_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler;

	p_data->t_data.cnt_down_interruptible += 1;

end_jprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int handler_mutex_lock(struct mutex *lock, unsigned int subclass)
{
	int pid;
	struct proc_data *p_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler;

	p_data->t_data.cnt_mutex_lock += 1;

end_jprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int handler_mutex_unlock(struct mutex *lock)
{
	int pid;
	struct proc_data *p_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler;

	p_data->t_data.cnt_mutex_unlock += 1;

end_jprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int handler_kfree(const void *objp)
{
	int pid;
	struct proc_data *p_data;
	unsigned long addr;
	long size;
	struct list_head *p;
	struct mem_data *m_data = NULL;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_jprobe_handler_unlock_proc;

	p_data->t_data.cnt_kfree += 1;

	// get addr from args
	addr = (unsigned long)objp;

	// get mem_data from proc_data->mem_list and remove it from list
	spin_lock(&p_data->mem_list_lock);
	list_for_each(p, &p_data->mem_list) {
		m_data = list_entry(p, struct mem_data, list);
		if (m_data->addr == addr) {
			list_del(p);
			break;
		}
	}
	// kmalloc not called for this process
	if (!m_data)
		goto end_jprobe_handler_unlock_mem;

	size = m_data->size;
	p_data->t_data.mem_kfree += size;

	spin_unlock(&p_data->mem_list_lock);
	spin_unlock(&dev_data.proc_list_lock);

	// free memory for mem_data
	kfree(m_data);

	jprobe_return();
	return 0;

end_jprobe_handler_unlock_mem:
	spin_unlock(&p_data->mem_list_lock);
end_jprobe_handler_unlock_proc:
	spin_unlock(&dev_data.proc_list_lock);
	jprobe_return();
	return 0;
}

static int entry_handler_kmalloc(struct kretprobe_instance *ri,
	struct pt_regs *regs)
{
	int pid;
	struct proc_data *p_data;
	long size;
	struct mem_data *m_data;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data)
		goto end_kretprobe_handler;

	p_data->t_data.cnt_kmalloc += 1;

	// get size from args
	size = regs->ax;
	p_data->t_data.mem_kmalloc += size;

	// save size in mem_data (ri->data)
	m_data = (struct mem_data *)ri->data;
	m_data->size = size;

end_kretprobe_handler:
	spin_unlock(&dev_data.proc_list_lock);
	return 0;
}

static int handler_kmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int pid;
	struct proc_data *p_data;
	unsigned long addr;
	struct mem_data *m_data;
	struct mem_data *m_data_new;

	// alloc memory for mem_data
	m_data_new = kmalloc(sizeof(*m_data_new), GFP_ATOMIC);
	if (!m_data_new)
		return -ENOMEM;

	pid = current->pid;

	spin_lock(&dev_data.proc_list_lock);
	p_data = get_proc_data(pid);
	if (!p_data) {
		spin_unlock(&dev_data.proc_list_lock);
		kfree(m_data_new);
		return 0;
	}

	addr = regs_return_value(regs);

	// save addr in mem_data (ri->data)
	m_data = (struct mem_data *)ri->data;
	m_data->addr = addr;

	m_data_new->addr = m_data->addr;
	m_data_new->size = m_data->size;

	// save mem_data to proc_data->mem_list
	spin_lock(&p_data->mem_list_lock);
	list_add(&m_data_new->list, &p_data->mem_list);

	spin_unlock(&p_data->mem_list_lock);
	spin_unlock(&dev_data.proc_list_lock);
	return 0;
}

static int register_probes(void)
{
	int ret;

	ret = register_jprobe(&probe_schedule);
	if (ret < 0)
		return -1;
	ret = register_jprobe(&probe_up);
	if (ret < 0)
		return -1;
	ret = register_jprobe(&probe_down_interruptible);
	if (ret < 0)
		return -1;
	ret = register_jprobe(&probe_mutex_lock);
	if (ret < 0)
		return -1;
	ret = register_jprobe(&probe_mutex_unlock);
	if (ret < 0)
		return -1;
	ret = register_jprobe(&probe_kfree);
	if (ret < 0)
		return -1;
	ret = register_kretprobe(&probe_kmalloc);
	if (ret < 0)
		return -1;

	return 0;
}

static void unregister_probes(void)
{
	unregister_jprobe(&probe_schedule);
	unregister_jprobe(&probe_up);
	unregister_jprobe(&probe_down_interruptible);
	unregister_jprobe(&probe_mutex_lock);
	unregister_jprobe(&probe_mutex_unlock);
	unregister_jprobe(&probe_kfree);
	unregister_kretprobe(&probe_kmalloc);
}


/*
 * MODULE STATE HANDLERS
 */

static int tracer_init(void)
{
	int err;

	dprintk(LOG_LEVEL "tracer: [tracer_init]\n");

	init_device_data();

	// add entry to /proc/
	proc_entry = proc_create(TRACER_DEV_NAME, 0000, NULL, &proc_fops);
	if (!proc_entry)
		return -ENOMEM;

	// register probes
	if (register_probes() < 0) {
		dprintk(LOG_LEVEL "tracer: [tracer_init] register_probes "
			"error: unable to register probes\n");
		return -1;
	}
	dprintk(LOG_LEVEL "tracer: [tracer_init] register_probes: success\n");

	// register device
	err = misc_register(&tracer_dev);
	if (err) {
		dprintk(LOG_LEVEL "tracer: [tracer_init] misc_register "
			"error: %d\n", err);
		return err;
	}
	dprintk(LOG_LEVEL "tracer: [tracer_init] misc_register: success\n");

	return 0;
}

static void tracer_exit(void)
{
	dprintk(LOG_LEVEL "tracer: [tracer_exit]\n");

	// deregister device
	misc_deregister(&tracer_dev);
	dprintk(LOG_LEVEL "tracer: [tracer_exit] misc_deregister: success\n");

	// unregister probes
	unregister_probes();
	dprintk(LOG_LEVEL "tracer: [tracer_exit] unregister_probes: success\n");

	// remove entry from /proc/
	proc_remove(proc_entry);

	clean_device_data();
}

module_init(tracer_init);
module_exit(tracer_exit);
