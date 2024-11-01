#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/blk-cgroup.h>
#include <linux/cgroup-defs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/sched/cputime.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/atomic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SP");
MODULE_DESCRIPTION("Kernel module to read cgroup memory、CPU、io usage");
MODULE_VERSION("1.0");

#define DEV_NAME                "monitor"
#define MONITOR_IO              0xAE
#define MONITOR_SET             _IOW(MONITOR_IO, 0x00, int)


#define for_each_process(p) \
        for (p = &init_task ; (p = next_task(p)) != &init_task ; )

static LIST_HEAD(users_header);
/* Timer */
#define SCANNER_PERIOD  3000 /* 1000ms -> 1s */
static struct timer_list h3c_scanner;

struct user_node {
    	struct list_head list;
    	int uid;
    	u64 stime;
    	u64 ptime;
    	u64 io;
    	struct css_set __rcu *cgroups;
} node;

static int register_user(uid_t uid)
{
        struct user_node *node = kmalloc(sizeof(*node), GFP_KERNEL | __GFP_ZERO);
        struct task_struct *task;
	struct cred *cred;
        node->uid = uid;
        if (node->uid == 0){
                printk("cannot monitor root!");
                return -EINVAL;
        }
	for_each_process(task) {
                cred = get_task_cred(task);
                if (from_kuid(&init_user_ns, cred->uid) == node->uid) {
                	node->cgroups = task->cgroups;
		}
        }

        list_add(&node->list, &users_header);
        printk("add uid: %d\n", uid);
        return 0;
}

static long monitor_ioctl(struct file *filp,
                        unsigned int ioctl, unsigned long arg)
{
        switch (ioctl) {
        case MONITOR_SET:
                printk("try to register user");
                return register_user(arg);
        default:
                break;
        }
        return 0;
}

static struct cgroup_subsys *find_cgroup_subsys(const char *name, struct css_set __rcu *cgroups) {
    	int i;
    	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        	if (!strcmp(cgroups->subsys[i]->ss->name, name)) {
            		return cgroups->subsys[i]->ss;
        	}
    	}
    	return NULL;
}

static struct cgroup_subsys_state *find_cgroup_css(const char *name, struct css_set __rcu *cgroups) {
    	int i;
    	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        	if (!strcmp(cgroups->subsys[i]->ss->name, name)) {
            		return cgroups->subsys[i];
        	}
    	}
    	return NULL;
}


static long int read_memory_usage (struct user_node *np) {
	struct mem_cgroup *memcg;
	struct cgroup_subsys_state *mem_css;
	long int mem;
	mem_css = find_cgroup_css("memory", np->cgroups);
	memcg = mem_cgroup_from_css(mem_css);
	mem = page_counter_read(&memcg->memory);
	//mem = memcg->memory.usage;
	return mem;
}

static u64 get_total_idletime(void){
	struct kernel_cpustat kstat;
        u64 sum = 0;
        int i;

        for_each_possible_cpu(i) {
		kcpustat_cpu_fetch(&kstat, i);
                sum += kstat.cpustat[CPUTIME_IDLE];
        }

        return sum;

}

static u64 get_total_runtime(void){
	struct task_cputime cputime;
	typedef void (*target_func_type)(struct task_cputime *cputime); // root_cgroup_cputime
	static target_func_type cg_cputime = NULL;
	u64 total_idletime;

	total_idletime = get_total_idletime();
	cg_cputime = (target_func_type)kallsyms_lookup_name("root_cgroup_cputime");
	if (cg_cputime) 
		cg_cputime(&cputime);

	return cputime.sum_exec_runtime + total_idletime;
}

/*
static long account_task_io(struct task_struct *tsk)
{
        struct signal_struct *sig = tsk->signal;
        struct task_io_accounting acct;
        struct task_struct *t;
        unsigned long flags;
        unsigned int seq = 1;
        int result;

        result = down_read_killable(&tsk->signal->exec_update_lock);
        if (result)
                return result;

        rcu_read_lock();
        do {
                seq++; 
                flags = read_seqbegin_or_lock_irqsave(&sig->stats_lock, &seq);

                acct = sig->ioac;
                __for_each_thread(sig, t)
                task_io_accounting_add(&acct, &t->ioac);

        } while (need_seqretry(&sig->stats_lock, seq));
        done_seqretry_irqrestore(&sig->stats_lock, seq, flags);
        rcu_read_unlock();
        up_read(&tsk->signal->exec_update_lock);

        return acct.write_bytes;
}
*/

static long long int account_io_usage(struct user_node *np)
{
        struct blkcg *blkcg;
	struct cgroup_subsys_state *blk_css;
	struct blkcg_gq *blkg;
	long long int total=0;
	rcu_read_lock();
	
	blk_css = find_cgroup_css("io", np->cgroups);
	blkcg = css_to_blkcg(blk_css);
	
	hlist_for_each_entry_rcu(blkg, &blkcg->blkg_list, blkcg_node) {
        	struct blkg_iostat_set stats = blkg->iostat;
        	total += stats.cur.bytes[BLKG_IOSTAT_READ];
        	total += stats.cur.bytes[BLKG_IOSTAT_WRITE];
        }

	rcu_read_unlock();
        return total;
}

/*
static long account_io_usage(struct user_node *np)
{
        struct task_struct *task;
        long total;
        struct cred *cred;
        for_each_process(task) {
                cred = get_task_cred(task);
                if (from_kuid(&init_user_ns, cred->uid) == np->uid) {
                        total += account_task_io(task);
                }
        }

        return total;
}*/

static int compute_cpu_usage(struct user_node *np){
	u64 ptime;
        u64 stime;
	int cpu_usage;
	struct cgroup *cgrp = find_cgroup_css("cpu", np->cgroups)->cgroup;
	typedef void (*target_func_type)(struct cgroup *cgrp); // cgroup_rstat_flush_hold
	typedef void (*target_func_type2)(void); // cgroup_rstat_flush_release
	static target_func_type flush_hold = NULL;
	static target_func_type2 flush_release = NULL;
	stime = get_total_runtime();
        if (!np->stime)
                np->stime = stime;
			
	flush_hold = (target_func_type)kallsyms_lookup_name("cgroup_rstat_flush_hold");
	flush_release = (target_func_type2)kallsyms_lookup_name("cgroup_rstat_flush_release");
	
	flush_hold(cgrp);
	ptime = cgrp->bstat.cputime.sum_exec_runtime;
	flush_release();
	if (!np->ptime)
		np->ptime = ptime;

	stime -= np->stime;
        ptime -= np->ptime;
	if (stime)
		cpu_usage = ptime * 100 / stime;

	np->stime = get_total_runtime();
        np->ptime = cgrp->bstat.cputime.sum_exec_runtime;
	
	return cpu_usage;
}



static void timer_handler (struct timer_list *unused) {
    struct user_node *np;
        /* SCANNER */
        list_for_each_entry(np, &users_header, list) {
                printk("user %d:\n", np->uid);
		/* CPU */
		int cpu_usage;
                cpu_usage = compute_cpu_usage(np);
                printk("CPU: %d%%\n", cpu_usage);

                /* MEMORY */
                long int memory_usage;
                memory_usage = read_memory_usage(np);
                printk("MEM: %ldpages\n", memory_usage);
		
		/* IO */
		long long int io_usage;
		u64 io;
                io = account_io_usage(np);
                //printk("IO: %lldbytes\n",io);
                if (!np->io)
                        np->io = io;

                io -= np->io;
                io_usage = io / SCANNER_PERIOD * 1000;
		printk("IO: %lldbytes per sec\n",io);
                np->io =  account_io_usage(np);
        }

        mod_timer(&h3c_scanner,
                jiffies + msecs_to_jiffies(SCANNER_PERIOD));

}

static struct file_operations monitor_fops = {
        .owner          = THIS_MODULE,
        .unlocked_ioctl = monitor_ioctl,
};

static struct miscdevice monitor_drv = {
        .minor  = MISC_DYNAMIC_MINOR,
        .name   = DEV_NAME,
        .fops   = &monitor_fops,
};

static int __init monitor_init(void)
{
        int ret;
        timer_setup(&h3c_scanner, timer_handler, 0);
        ret = mod_timer(&h3c_scanner,
                jiffies + msecs_to_jiffies(SCANNER_PERIOD));
        if (ret) {
                printk(KERN_ERR "mod timer failed, ret: %d\n", ret);
        }
        misc_register(&monitor_drv);
        return 0;
}

static void __exit monitor_exit(void)
{
        del_timer(&h3c_scanner);
        misc_deregister(&monitor_drv);
}

module_init(monitor_init);
module_exit(monitor_exit);

