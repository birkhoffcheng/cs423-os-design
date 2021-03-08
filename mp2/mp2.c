#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include "mp2_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP2");

#define DIRECTORY "mp2"
#define FILENAME "status"
static struct proc_dir_entry *mp_dir, *status_file;
static LIST_HEAD(process_list);
static DEFINE_SPINLOCK(process_list_lock);

enum task_state {
	SLEEPING,
	READY,
	RUNNING
};

struct mp2_task_struct {
	pid_t pid;
	struct task_struct *linux_task;
	struct timer_list wakeup_timer;
	struct list_head elem;
	unsigned long period_ms;
	unsigned long runtime_ms;
	unsigned long deadline_jiff;
	enum task_state state;
};

static ssize_t mp_read(struct file *file, char __user *buffer, size_t count, loff_t *offp) {
	ssize_t bytes_read = 0;

	if (!access_ok(VERIFY_WRITE, buffer, count)) {
		bytes_read = -EINVAL;
		goto out;
	}

out:
	return bytes_read;
}

static ssize_t mp_write(struct file *file, const char __user *buffer, size_t count, loff_t *offp) {
	ssize_t bytes_written;
	char *kbuf;

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
	kbuf[count] = '\0';

free_and_out:
	kfree(kbuf);
out:
	return bytes_written;
}

static const struct file_operations mp_file_op = {
	.owner = THIS_MODULE,
	.read = mp_read,
	.write = mp_write,
};

int __init mp_init(void) {
	int error = 0;

	mp_dir = proc_mkdir(DIRECTORY, NULL);
	if (mp_dir == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY " creation failed\n");
		goto out;
	}

	status_file = proc_create(FILENAME, 0666, mp_dir, &mp_file_op);
	if (status_file == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY "/" FILENAME " creation failed\n");
		goto out;
	}

out:
	return error;
}

void __exit mp_exit(void) {
	remove_proc_entry(FILENAME, mp_dir);
	remove_proc_entry(DIRECTORY, NULL);
}

// Register init and exit funtions
module_init(mp_init);
module_exit(mp_exit);
