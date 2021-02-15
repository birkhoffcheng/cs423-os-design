#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "mp1_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP1");

#define DIRECTORY "mp1"
#define FILENAME "status"
static struct proc_dir_entry *mp1_dir, *status_file;
LIST_HEAD(mp1_process_list);
struct mp1_process {
	pid_t pid;
	unsigned long cpu_use;
	struct list_head elem;
};

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data) {
	return 0;
}

static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
	ssize_t bytes_written;
	pid_t pid;
	int error;
	struct mp1_process *proc;
	char *kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (kbuf == NULL) {
		bytes_written = -ENOMEM;
		goto out;
	}

	bytes_written = count - copy_from_user(kbuf, buffer, count);
	kbuf[count] = '\0';
	if ((error = kstrtoint(kbuf, 10, &pid))) {
		bytes_written = error;
		goto free_and_out;
	}

	proc = kmalloc(sizeof(struct mp1_process), GFP_KERNEL);
	proc->pid = pid;
	proc->cpu_use = 0;
	list_add_tail(&proc->elem, &mp1_process_list);

free_and_out:
	kfree(kbuf);
out:
	return bytes_written;
}

static const struct file_operations mp1_file = {
	.owner = THIS_MODULE,
	.read = mp1_read,
	.write = mp1_write,
};

// mp1_init - Called when module is loaded
int __init mp1_init(void)
{
	int error = 0;

	mp1_dir = proc_mkdir(DIRECTORY, NULL);
	if (mp1_dir == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY " creation failed\n");
		goto out;
	}

	status_file = proc_create(FILENAME, 0666, mp1_dir, &mp1_file);
	if (status_file == NULL) {
		error = -ENOMEM;
		printk(KERN_ALERT "/proc/" DIRECTORY "/" FILENAME " creation failed\n");
		goto out;
	}

out:
	return error;
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
	struct mp1_process *proc, *tmp;

	list_for_each_entry_safe(proc, tmp, &mp1_process_list, elem) {
		list_del(&proc->elem);
		kfree(proc);
	}

	remove_proc_entry("status", mp1_dir);
	remove_proc_entry("mp1", NULL);
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);
