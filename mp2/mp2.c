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
#include "mp2_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP2");

#define DIRECTORY "mp2"
#define FILENAME "status"
static struct proc_dir_entry *mp_dir, *status_file;
static LIST_HEAD(process_list);
static DEFINE_SPINLOCK(process_list_lock);
static struct kmem_cache *kmem_cache;
static struct task_struct *dispatching_thread;
static struct mp2_task_struct *current_task;

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
	ssize_t bytes_read;
	char *kbuf;
	struct mp2_task_struct *curr;
	unsigned long flags;

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
		bytes_read += scnprintf(kbuf + bytes_read, count - bytes_read, "%d: %lu, %lu\n", curr->pid, curr->period_ms, curr->runtime_ms);
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

static int wake_up_task(void *arg) {
	unsigned long flags;
	struct mp2_task_struct *curr, *task;
	struct sched_param sparam;
	while (!kthread_should_stop()) {
		set_current_state(TASK_RUNNING);
		task = NULL;
		spin_lock_irqsave(&process_list_lock, flags);
		list_for_each_entry(curr, &process_list, elem) {
			if (curr->state == READY) {
				task = curr;
				break;
			}
		}
		spin_unlock_irqrestore(&process_list_lock, flags);

		if (task != NULL) {
			task->state = RUNNING;
			wake_up_process(task->linux_task);
			sparam.sched_priority = 99;
			sched_setscheduler(task->linux_task, SCHED_FIFO, &sparam);
		}

		if (current_task != NULL) {
			current_task->state = READY;
			sparam.sched_priority = 0;
			sched_setscheduler(current_task->linux_task, SCHED_NORMAL, &sparam);
		}

		current_task = task;
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return 0;
}

static void wake_up_timer(unsigned long arg) {
	struct mp2_task_struct *task = arg;
	task->state = READY;
	mod_timer(&task->wakeup_timer, jiffies + msecs_to_jiffies(task->period_ms));
	set_task_state(dispatching_thread, TASK_RUNNING);
}

static bool mp2_register(char *input) {
	pid_t pid;
	unsigned long period_ms, runtime_ms;
	struct task_struct *linux_task;
	struct mp2_task_struct *task, *curr;
	bool success;
	unsigned long flags;

	if (sscanf(input, "R,%d,%lu,%lu", &pid, &period_ms, &runtime_ms) < 3) {
		success = false;
		goto out;
	}

	linux_task = find_task_by_pid(pid);
	if (linux_task == NULL) {
		success = false;
		goto out;
	}

	task = kmem_cache_alloc(kmem_cache, GFP_KERNEL);
	task->pid = pid;
	task->linux_task = linux_task;
	setup_timer(&task->wakeup_timer, wake_up_timer, (unsigned long) task);
	task->period_ms = period_ms;
	task->runtime_ms = runtime_ms;
	task->state = SLEEPING;

	spin_lock_irqsave(&process_list_lock, flags);
	if (list_empty(&process_list)) {
		list_add(&task->elem, &process_list);
	}
	else if (list_last_entry(&process_list, struct mp2_task_struct, elem)->period_ms <= period_ms) {
		list_add_tail(&task->elem, &process_list);
	}
	else {
		// Keep list sorted so scheduling takes O(1)
		list_for_each_entry(curr, &process_list, elem) {
			if (curr->period_ms > period_ms) {
				list_add_tail(&task->elem, &curr->elem);
				break;
			}
		}
	}
	spin_unlock_irqrestore(&process_list_lock, flags);
	success = true;
out:
	return success;
}

static bool mp2_yield(char *input) {
	return true;
}

static bool mp2_deregister(char *input) {
	bool success;
	pid_t pid;
	unsigned long flags;
	struct mp2_task_struct *curr, *tmp;

	if (sscanf(input, "D,%d", &pid) < 1) {
		success = false;
		goto out;
	}

	spin_lock_irqsave(&process_list_lock, flags);
	list_for_each_entry_safe(curr, tmp, &process_list, elem) {
		if (curr->pid == pid) {
			list_del(&curr->elem);
			del_timer(&curr->wakeup_timer);
			kmem_cache_free(kmem_cache, curr);
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
		case 'D':
		case 'd':
			success = mp2_deregister(kbuf);
			break;
		case 'R':
		case 'r':
			success = mp2_register(kbuf);
			break;
		case 'Y':
		case 'y':
			success = mp2_yield(kbuf);
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
		printk(KERN_ALERT "/proc/" DIRECTORY " creation failed\n");
		goto out;
	}

	status_file = proc_create(FILENAME, 0666, mp_dir, &mp_file_op);
	if (status_file == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY "/" FILENAME " creation failed\n");
		goto out;
	}

	kmem_cache = kmem_cache_create(DIRECTORY, sizeof(struct mp2_task_struct), 0, 0, NULL);
	dispatching_thread = kthread_run(wake_up_task, NULL, "Dispatching thread");
out:
	return error;
}

void __exit mp_exit(void) {
	struct mp2_task_struct *curr, *tmp;

	remove_proc_entry(FILENAME, mp_dir);
	remove_proc_entry(DIRECTORY, NULL);
	list_for_each_entry_safe(curr, tmp, &process_list, elem) {
		list_del(&curr->elem);
		del_timer(&curr->wakeup_timer);
		kmem_cache_free(kmem_cache, curr);
	}
	kmem_cache_destroy(kmem_cache);
	kthread_stop(dispatching_thread);
}

// Register init and exit funtions
module_init(mp_init);
module_exit(mp_exit);
