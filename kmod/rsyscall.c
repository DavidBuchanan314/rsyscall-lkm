#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <asm/syscall.h>

#include "../include/rsyscall.h"

#define DRIVER_AUTHOR "David Buchanan <d@vidbuchanan.co.uk>"
#define DRIVER_DESC   "rsyscall - a remote syscall interface"

#define DEV_NAME      "rsyscall"


#define SUCCESS 0
#define FAILURE -1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define SYS_ARGS_AS_STRUCT
#endif


// TODO: move global state into some struct?
static dev_t devt;
static struct class *class;
static struct cdev cdev;
static int dev_created;

#define sys_call_table __sys_call_table

/* at some point, the way args are passed to sycalls changed */
#ifdef SYS_ARGS_AS_STRUCT
	static long (**sys_call_table)(struct pt_regs *regs);
#else
	static long (**sys_call_table)(long, long, long, long, long, long);
#endif

static struct task_struct * (*__switch_to)(struct task_struct *prev, struct task_struct *next);


/* stub */
static int device_open(struct inode *inode, struct file *file)
{
	return 0;
}

/* stub */
static int device_release(struct inode *inode, struct file *file)
{
	return 0;
}

/* stub */
static ssize_t device_read(
	struct file *f,
	char __user *buf,
	size_t len,
	loff_t *off)
{
	return 0;
}

/* stub */
static ssize_t device_write(
	struct file *f,
	const char __user *buf,
	size_t len,
	loff_t *off)
{
	return len;
}

long device_ioctl(
	struct file *file,
	unsigned int ioctl_num,
	unsigned long ioctl_param)
{
	struct rsyscall_args rsargs;
#ifdef SYS_ARGS_AS_STRUCT
	struct pt_regs regs;
#endif
	struct pid *target_pid;
	struct task_struct *target_task, *orig_task;
	
	if (ioctl_num != IOCTL_RSYSCALL) {
		return FAILURE;
	}
	
	if (copy_from_user(&rsargs, (void *)ioctl_param, sizeof(rsargs)) != 0) {
		return -EACCES;
	}
	
	target_pid = find_vpid(rsargs.pid);
	if (!target_pid) return -EINVAL;
	target_task = pid_task(target_pid, PIDTYPE_PID);
	if (!target_task) return -EINVAL;
	
	orig_task = current;
	
	// XXX there's probably some kinda lock etc. that we need to acquire before
	// doing this. YOLO.
	__switch_to(orig_task, target_task);
	
	/* do the syscall!!! */
	if (rsargs.sysno < NR_syscalls) {
#ifdef SYS_ARGS_AS_STRUCT
		memset(&regs, 0, sizeof(regs));
		regs.di  = rsargs.args[0];
		regs.si  = rsargs.args[1];
		regs.dx  = rsargs.args[2];
		regs.r10 = rsargs.args[3];
		regs.r8  = rsargs.args[4];
		regs.r9  = rsargs.args[5];
		rsargs.retval = sys_call_table[rsargs.sysno](&regs);
#else
		rsargs.retval = sys_call_table[rsargs.sysno](
			rsargs.args[0], rsargs.args[1], rsargs.args[2],
			rsargs.args[3], rsargs.args[4], rsargs.args[5]);
#endif
	} else {
		return -EINVAL;
	}
	
	__switch_to(target_task, orig_task);
	
	if (copy_to_user((void *)ioctl_param, &rsargs, sizeof(rsargs)) != 0) {
		return -EACCES;
	}
	
	return SUCCESS;
}

const struct file_operations fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = device_ioctl,
	.open           = device_open,
	.release        = device_release,
	.read           = device_read,
	.write          = device_write
};

static char *rsyscall_devnode(struct device *dev, umode_t *mode)
{
	if (mode) *mode = 0666; // rw-rw-rw-
	return NULL;
}

/* __exit annotation removed so this function can be called from init_rsyscall() */
static void cleanup_rsyscall(void)
{
	if (dev_created) {
		device_destroy(class, devt);
		cdev_del(&cdev);
	}
	
	if (class) {
		class_destroy(class);
	}
	
	if (devt >= 0) {
		unregister_chrdev_region(devt, 1);
	}
	
	printk(KERN_INFO "goodbye rsyscall\n");
}

static int __init init_rsyscall(void)
{
	printk(KERN_INFO "hello rsyscall\n");
	
	if (alloc_chrdev_region(&devt, 0, 1, DEV_NAME) < 0) {
		printk(KERN_ALERT "alloc_chrdev_region failed\n");
		return FAILURE;
	}
	
	if ((class = class_create(THIS_MODULE, DEV_NAME)) == NULL) {
		printk(KERN_ALERT "class_create failed\n");
		cleanup_rsyscall();
		return FAILURE;
	}
	
	class->devnode = rsyscall_devnode;
	
	if (device_create(class, NULL, devt, NULL, DEV_NAME) == NULL) {
		printk(KERN_ALERT "device_create failed\n");
		cleanup_rsyscall();
		return FAILURE;
	}
	
	dev_created = 1;
	
	cdev_init(&cdev, &fops);
	if (cdev_add(&cdev, devt, 1) < 0) {
		printk(KERN_ALERT "cdev_add failed\n");
		cleanup_rsyscall();
		return FAILURE;
	}
	
	sys_call_table = (void*)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		printk(KERN_ALERT "Failed to lookup sys_call_table symbol\n");
		cleanup_rsyscall();
		return FAILURE;
	}
	
	__switch_to = (void*)kallsyms_lookup_name("__switch_to");
	if (!__switch_to) {
		printk(KERN_ALERT "Failed to lookup __switch_to symbol\n");
		cleanup_rsyscall();
		return FAILURE;
	}
	
	printk(KERN_INFO "rsyscall init success\n");
	
	return SUCCESS;
}


module_init(init_rsyscall);
module_exit(cleanup_rsyscall);


MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
