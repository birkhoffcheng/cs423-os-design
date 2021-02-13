#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include "mp1_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhiqic2");
MODULE_DESCRIPTION("CS-423 MP1");

#define DIRECTORY "mp1"
#define FILENAME "status"
static struct proc_dir_entry *mp1_dir, *status_file;

static ssize_t mp1_read(struct file *file, char __user *buffer, size_t count, loff_t *data) {
	return 0;
}

static ssize_t mp1_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
	return 0;
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
	#ifdef DEBUG
	printk("MP1 MODULE LOADING\n");
	#endif

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

	#ifdef DEBUG
	printk("MP1 MODULE LOADED\n");
	#endif
out:
	return error;
}

// mp1_exit - Called when module is unloaded
void __exit mp1_exit(void)
{
	#ifdef DEBUG
	printk("MP1 MODULE UNLOADING\n");
	#endif

	remove_proc_entry("status", mp1_dir);
	remove_proc_entry("mp1", NULL);

	#ifdef DEBUG
	printk("MP1 MODULE UNLOADED\n");
	#endif
}

// Register init and exit funtions
module_init(mp1_init);
module_exit(mp1_exit);
