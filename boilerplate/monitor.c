#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME "container_monitor"
#define CHECK_INTERVAL_SEC 1

struct monitored_proc {
    pid_t pid;
    char container_id[MONITOR_NAME_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    bool soft_warned;
    struct list_head list;
};

static LIST_HEAD(monitored_list);
static DEFINE_MUTEX(monitored_lock);

static struct timer_list monitor_timer;
static dev_t dev_num;
static struct cdev c_dev;
static struct class *cl;

static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -1;
    }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);

    return rss_pages * PAGE_SIZE;
}

static void log_soft_limit_event(const char *container_id,
                                 pid_t pid,
                                 unsigned long limit_bytes,
                                 long rss_bytes)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

static void kill_process(const char *container_id,
                         pid_t pid,
                         unsigned long limit_bytes,
                         long rss_bytes)
{
    struct task_struct *task;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task)
        send_sig(SIGKILL, task, 1);
    rcu_read_unlock();

    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d rss=%ld limit=%lu\n",
           container_id, pid, rss_bytes, limit_bytes);
}

static void timer_callback(struct timer_list *t)
{
    struct monitored_proc *entry;
    struct monitored_proc *tmp;

    (void)t;

    mutex_lock(&monitored_lock);
    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        long rss = get_rss_bytes(entry->pid);

        if (rss < 0) {
            list_del(&entry->list);
            kfree(entry);
            continue;
        }

        if (!entry->soft_warned && rss > (long)entry->soft_limit_bytes) {
            log_soft_limit_event(entry->container_id,
                                 entry->pid,
                                 entry->soft_limit_bytes,
                                 rss);
            entry->soft_warned = true;
        }

        if (rss > (long)entry->hard_limit_bytes) {
            kill_process(entry->container_id,
                         entry->pid,
                         entry->hard_limit_bytes,
                         rss);
            list_del(&entry->list);
            kfree(entry);
        }
    }
    mutex_unlock(&monitored_lock);

    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

static long monitor_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct monitor_request req;

    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;

    if (copy_from_user(&req, (struct monitor_request __user *)arg, sizeof(req)))
        return -EFAULT;

    req.container_id[MONITOR_NAME_LEN - 1] = '\0';

    if (cmd == MONITOR_REGISTER) {
        struct monitored_proc *entry;
        struct monitored_proc *existing;

        if (req.pid <= 0 || req.soft_limit_bytes == 0 || req.hard_limit_bytes == 0)
            return -EINVAL;
        if (req.soft_limit_bytes > req.hard_limit_bytes)
            return -EINVAL;

        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry)
            return -ENOMEM;

        entry->pid = req.pid;
        entry->soft_limit_bytes = req.soft_limit_bytes;
        entry->hard_limit_bytes = req.hard_limit_bytes;
        entry->soft_warned = false;
        strscpy(entry->container_id, req.container_id, sizeof(entry->container_id));

        mutex_lock(&monitored_lock);
        list_for_each_entry(existing, &monitored_list, list) {
            if (existing->pid == req.pid) {
                existing->soft_limit_bytes = req.soft_limit_bytes;
                existing->hard_limit_bytes = req.hard_limit_bytes;
                existing->soft_warned = false;
                strscpy(existing->container_id, req.container_id, sizeof(existing->container_id));
                mutex_unlock(&monitored_lock);
                kfree(entry);
                printk(KERN_INFO
                       "[container_monitor] Updated container=%s pid=%d soft=%lu hard=%lu\n",
                       req.container_id,
                       req.pid,
                       req.soft_limit_bytes,
                       req.hard_limit_bytes);
                return 0;
            }
        }

        list_add_tail(&entry->list, &monitored_list);
        mutex_unlock(&monitored_lock);

        printk(KERN_INFO
               "[container_monitor] Registering container=%s pid=%d soft=%lu hard=%lu\n",
               req.container_id,
               req.pid,
               req.soft_limit_bytes,
               req.hard_limit_bytes);

        return 0;
    }

    printk(KERN_INFO
           "[container_monitor] Unregister request container=%s pid=%d\n",
           req.container_id,
           req.pid);

    mutex_lock(&monitored_lock);
    {
        struct monitored_proc *entry;
        struct monitored_proc *tmp;

        list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
            bool pid_match = (req.pid > 0 && entry->pid == req.pid);
            bool id_match = (req.container_id[0] != '\0' &&
                             strncmp(entry->container_id,
                                     req.container_id,
                                     sizeof(entry->container_id)) == 0);

            if (pid_match || id_match) {
                list_del(&entry->list);
                kfree(entry);
                mutex_unlock(&monitored_lock);
                return 0;
            }
        }
    }
    mutex_unlock(&monitored_lock);

    return -ENOENT;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    cl = class_create(DEVICE_NAME);
#else
    cl = class_create(THIS_MODULE, DEVICE_NAME);
#endif
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO "[container_monitor] Module loaded. Device: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit monitor_exit(void)
{
    struct monitored_proc *entry;
    struct monitored_proc *tmp;

    del_timer_sync(&monitor_timer);

    mutex_lock(&monitored_lock);
    list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    mutex_unlock(&monitored_lock);

    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Supervised multi-container memory monitor");
