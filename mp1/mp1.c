#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include "mp1_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP1");

#define DIRECTORY "mp1"
#define FILENAME "status"
#define MAX_STR_LEN 32
static struct proc_dir_entry *mp1_dir, *status_file;
LIST_HEAD(mp1_process_list);
static struct timer_list mp1_timer;
static struct workqueue_struct *wq = NULL;
static DEFINE_SPINLOCK(mp1_list_lock);
struct mp1_process {
	pid_t pid;
	unsigned long cpu_use;
	struct list_head elem;
};

struct status_file_buffer {
	size_t size;
	char buf[0];
};

static void update_cpu_time(struct work_struct *work) {
	struct mp1_process *proc, *tmp;
	unsigned long cpu_time, flags;
	spin_lock_irqsave(&mp1_list_lock, flags);
	list_for_each_entry_safe(proc, tmp, &mp1_process_list, elem) {
		if (get_cpu_use(proc->pid, &cpu_time) == 0) {
			proc->cpu_use = cpu_time;
		}
		else {
			list_del(&proc->elem);
			kfree(proc);
		}
	}
	spin_unlock_irqrestore(&mp1_list_lock, flags);
}

DECLARE_WORK(mp1_work, update_cpu_time);

static void enq_work(unsigned long arg) {
	queue_work(wq, &mp1_work);
	mod_timer(&mp1_timer, jiffies + msecs_to_jiffies(5000));
}

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *offp) {
	struct mp1_process *proc;
	ssize_t bytes_read;
	char *kbuf;
	struct status_file_buffer *sbuf;
	unsigned long flags;
	size_t size = 0;

	// If buffer is not user writable don't even try
	if (!access_ok(VERIFY_WRITE, buffer, count)) {
		bytes_read = -EINVAL;
		goto out;
	}

	// Check if the user has already read part of the buffer
	if (*offp || file->private_data) {
		sbuf = file->private_data;
		size = sbuf->size;
		kbuf = sbuf->buf;
		if (*offp >= size) {
			// The user has reached EOF
			bytes_read = 0;
		}
		else {
			// Copy remaining buffer to user space as requested
			bytes_read = (size - *offp < count) ? (size - *offp) : count;
			bytes_read -= copy_to_user(buffer, kbuf + *offp, bytes_read);
			*offp += bytes_read;
		}
		goto out;
	}

	// Calculate list size and allocate memory accordingly
	spin_lock_irqsave(&mp1_list_lock, flags);
	list_for_each_entry(proc, &mp1_process_list, elem)
		size++;
	spin_unlock_irqrestore(&mp1_list_lock, flags);

	sbuf = kmalloc(sizeof(struct status_file_buffer) + size * MAX_STR_LEN, GFP_KERNEL);
	if (sbuf == NULL) {
		bytes_read = -ENOMEM;
		goto out;
	}

	// Read the output to a per-file buffer
	size *= MAX_STR_LEN;
	kbuf = sbuf->buf;
	file->private_data = sbuf;
	bytes_read = 0;
	spin_lock_irqsave(&mp1_list_lock, flags);
	list_for_each_entry(proc, &mp1_process_list, elem) {
		bytes_read += scnprintf(kbuf + bytes_read, size - bytes_read, "%d: %lu\n", proc->pid, proc->cpu_use);
		if (bytes_read >= size)
			break;
	}
	spin_unlock_irqrestore(&mp1_list_lock, flags);

	sbuf->size = bytes_read;
	bytes_read = (bytes_read < count) ? bytes_read : count;
	bytes_read -= copy_to_user(buffer, kbuf, bytes_read);
	*offp += bytes_read;

out:
	return bytes_read;
}

static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *offp) {
	ssize_t bytes_written;
	pid_t pid;
	int error;
	struct mp1_process *proc;
	unsigned long flags;
	char *kbuf;

	// If buffer is not user readable don't even try
	if (!access_ok(VERIFY_READ, buffer, count)) {
		bytes_written = -EINVAL;
		goto out;
	}

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (kbuf == NULL) {
		bytes_written = -ENOMEM;
		goto out;
	}

	bytes_written = count - copy_from_user(kbuf, buffer, count);
	// Some programs don't send NULL byte so add it here
	kbuf[count] = '\0';
	if ((error = kstrtoint(kbuf, 10, &pid))) {
		bytes_written = error;
		goto free_and_out;
	}

	proc = kmalloc(sizeof(struct mp1_process), GFP_KERNEL);
	proc->pid = pid;
	proc->cpu_use = 0;
	spin_lock_irqsave(&mp1_list_lock, flags);
	list_add_tail(&proc->elem, &mp1_process_list);
	spin_unlock_irqrestore(&mp1_list_lock, flags);

free_and_out:
	kfree(kbuf);
out:
	return bytes_written;
}

static int mp1_release(struct inode *inode, struct file *file) {
	kfree(file->private_data);
	return 0;
}

static const struct file_operations mp1_file = {
	.owner = THIS_MODULE,
	.read = mp1_read,
	.write = mp1_write,
	.release = mp1_release,
};

// mp1_init - Called when module is loaded
int __init mp1_init(void)
{
	int error = 0;

	// Create /proc/mp1 directory
	mp1_dir = proc_mkdir(DIRECTORY, NULL);
	if (mp1_dir == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY " creation failed\n");
		goto out;
	}

	// Create /proc/mp1/status entry
	status_file = proc_create(FILENAME, 0666, mp1_dir, &mp1_file);
	if (status_file == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY "/" FILENAME " creation failed\n");
		goto out;
	}

	setup_timer(&mp1_timer, enq_work, 0);
	mod_timer(&mp1_timer, jiffies + msecs_to_jiffies(5000));

	wq = create_singlethread_workqueue("mp1");

out:
	return error;
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
	struct mp1_process *proc, *tmp;

	del_timer(&mp1_timer);

	flush_workqueue(wq);
	destroy_workqueue(wq);

	remove_proc_entry("status", mp1_dir);
	remove_proc_entry("mp1", NULL);

	// Clear the list last when no one can modify it
	list_for_each_entry_safe(proc, tmp, &mp1_process_list, elem) {
		list_del(&proc->elem);
		kfree(proc);
	}
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);
