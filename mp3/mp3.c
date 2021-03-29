#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/slab_def.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP3");

#define DIRECTORY "mp3"
#define FILENAME "status"
static struct proc_dir_entry *mp_dir, *status_file;
static LIST_HEAD(process_list);
static DEFINE_SPINLOCK(process_list_lock);
static struct workqueue_struct *wq;
static void update_mem_status(struct work_struct *work);
static DECLARE_DELAYED_WORK(mp_work, update_mem_status);

struct mp3_task_struct {
	pid_t pid;
	struct task_struct *linux_task;
	unsigned long utilization;
	unsigned long major_faults;
	unsigned long minor_faults;
	struct list_head elem;
};

static void update_mem_status(struct work_struct *work) {
	unsigned long flags;

	spin_lock_irqsave(&process_list_lock, flags);
	if (!list_empty(&process_list)) {
		queue_delayed_work(wq, &mp_work, msecs_to_jiffies(50));
	}
	// TODO update memory status of every process
	spin_unlock_irqrestore(&process_list_lock, flags);
	printk("workqueue work run\n");
}

static ssize_t mp_read(struct file *file, char __user *buffer, size_t count, loff_t *offp) {
	ssize_t bytes_read;
	char *kbuf;
	unsigned long flags;
	struct mp3_task_struct *curr;

	if (!access_ok(VERIFY_WRITE, buffer, count)) {
		bytes_read = -EINVAL;
		goto out;
	}

	if (*offp) {
		bytes_read = 0;
		goto out;
	}

	kbuf = kmalloc(count, GFP_KERNEL);
	if (kbuf == NULL) {
		bytes_read = -ENOMEM;
		goto out;
	}

	bytes_read = 0;
	spin_lock_irqsave(&process_list_lock, flags);
	list_for_each_entry(curr, &process_list, elem) {
		bytes_read += scnprintf(kbuf + bytes_read, count - bytes_read, "%d\n", curr->pid);
		if (bytes_read >= count)
			break;
	}
	spin_unlock_irqrestore(&process_list_lock, flags);

	bytes_read -= copy_to_user(buffer, kbuf, bytes_read);
	*offp += bytes_read;
	kfree(kbuf);

out:
	return bytes_read;
}

static bool mp3_register(char *input) {
	pid_t pid;
	struct task_struct *linux_task;
	struct mp3_task_struct *task;
	bool success;
	unsigned long flags;

	success = false;
	if (sscanf(input, "R%d", &pid) < 1) {
		goto out;
	}

	linux_task = find_task_by_pid(pid);
	if (linux_task == NULL) {
		goto out;
	}

	task = kmalloc(sizeof(struct mp3_task_struct), GFP_KERNEL);
	task->pid = pid;
	task->linux_task = linux_task;

	spin_lock_irqsave(&process_list_lock, flags);
	if (list_empty(&process_list)) {
		queue_delayed_work(wq, &mp_work, msecs_to_jiffies(50));
	}
	list_add_tail(&task->elem, &process_list);
	spin_unlock_irqrestore(&process_list_lock, flags);
	success = true;

out:
	return success;
}

static bool mp3_unregister(char *input) {
	pid_t pid;
	unsigned long flags;
	struct mp3_task_struct *curr, *tmp;
	bool success = false;

	if (sscanf(input, "U%d", &pid) < 1) {
		goto out;
	}

	spin_lock_irqsave(&process_list_lock, flags);
	list_for_each_entry_safe(curr, tmp, &process_list, elem) {
		if (curr->pid == pid) {
			list_del(&curr->elem);
			kfree(curr);
			break;
		}
	}
	spin_unlock_irqrestore(&process_list_lock, flags);
	success = true;

out:
	return success;
}

static ssize_t mp_write(struct file *file, const char __user *buffer, size_t count, loff_t *offp) {
	ssize_t bytes_written;
	char *kbuf;
	bool success = true;

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

	if (bytes_written == 0)
		goto free_and_out;

	switch (*kbuf) {
		case 'R':
			success = mp3_register(kbuf);
			break;
		case 'U':
			success = mp3_unregister(kbuf);
			break;
		default:
			success = false;
			break;
	}

free_and_out:
	kfree(kbuf);
out:
	return (success) ? bytes_written : -EINVAL;
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
		goto out;
	}

	status_file = proc_create(FILENAME, 0666, mp_dir, &mp_file_op);
	if (status_file == NULL) {
		error = -ENOMEM;
		goto out;
	}

	wq = create_workqueue("mp3");

out:
	return error;
}

void __exit mp_exit(void) {
	struct mp3_task_struct *curr, *tmp;

	remove_proc_entry(FILENAME, mp_dir);
	remove_proc_entry(DIRECTORY, NULL);
	list_for_each_entry_safe(curr, tmp, &process_list, elem) {
		list_del(&curr->elem);
		kfree(curr);
	}
	flush_workqueue(wq);
	destroy_workqueue(wq);
}

// Register init and exit funtions
module_init(mp_init);
module_exit(mp_exit);
