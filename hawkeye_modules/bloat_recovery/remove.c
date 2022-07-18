#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <asm/pgtable.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>

int pid = 0;
module_param(pid, int, 0640);
int sleep = 120000;
module_param(sleep, int, 0640);

unsigned long distance = 0;
struct task_struct *task;

/* declaration for kernel functions exported manually */
struct page *follow_page_custom(struct vm_area_struct *vma,
		unsigned long addr, unsigned int foll_flags);
void zap_page_range(struct vm_area_struct *vma, unsigned long start,
                unsigned long size);

static void print_recovery_info(unsigned long nr_to_free, unsigned long nr_recovered)
{
	pr_crit("target: %ld recovered: %ld", nr_to_free, nr_recovered);
}

static unsigned long count_pages_to_free(void)
{
	struct pglist_data *pgdat;
	struct zone *zone;
	unsigned long managed = 0, free = 0;

	pgdat = first_online_pgdat();
	for_each_zone(zone) {
		if (zone->zone_pgdat != pgdat)
			continue;
		managed += atomic64_read(&zone->managed_pages);
		free += atomic_long_read(&zone->vm_stat[0]);
	}

	if (free < ((managed*15)/100))
		return (managed*30)/100 - free;
	return 0;
}

static bool is_page_zero(u8 *addr)
{
	u8 *ptr_curr = (u8 *)addr;
	u8 *ptr_end = ptr_curr + PAGE_SIZE;
	u8 val;

	while (ptr_curr < ptr_end) {
		val = *ptr_curr;
		if (val)
			return false;
		ptr_curr++;
	}
	return true;
}

/*
 * hpage must be a transparent huge page
 */
static int remove_zero_pages(struct page *hpage, struct vm_area_struct *vma,
					unsigned long start)
{
	void *haddr;
	u8 *hstart, *hend, *addr;
	int nr_recovered = 0;

	haddr = kmap_atomic(hpage);
	hstart = (u8 *)haddr;
	hend = hstart + HPAGE_PMD_SIZE;
	/* zero checking logic */
	for (addr = hstart; addr < hend; addr += PAGE_SIZE, start += PAGE_SIZE) {
		if (is_page_zero(addr)) {
			zap_page_range(vma, start, PAGE_SIZE);
			nr_recovered++;
		}
	}
	kunmap_atomic(haddr);
	return nr_recovered;
}

/*
 * Traverse each page of given task and see how many pages
 * contain only-zeroes---this gives us a good enough indication.
 * on the upper bound of memory bloat.
 */
static bool remove_bloat(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = NULL;
	struct page *page;
	unsigned long nr_recovered = 0, nr_to_free = 0;
	unsigned long start, end, addr;

	mm = get_task_mm(task);
	if (!mm)
		goto out;

	nr_to_free = count_pages_to_free();
	/* traverse the list of all vma regions */
	for(vma = mm->mmap; vma && nr_to_free; vma = vma->vm_next) {
		start = (vma->vm_start + ~HPAGE_PMD_MASK) & HPAGE_PMD_MASK;
		end = vma->vm_end & HPAGE_PMD_MASK;

		/* examine each huge page region */
		for (addr = start; addr < end;) {
			page = follow_page_custom(vma, addr, FOLL_GET);
			if (!page) {
				addr += PAGE_SIZE;
				continue;
			}
			if (!PageTransHuge(page)) {
				put_page(page);
				addr += PAGE_SIZE;
				continue;
			}
			nr_recovered += remove_zero_pages(page, vma, addr);
			put_page(page);
			addr += PAGE_SIZE * 512;
			if (nr_recovered > nr_to_free)
				goto inner_break;
			
		}
	}
inner_break:
	mmput(mm);
	print_recovery_info(nr_to_free, nr_recovered);
	return true;

out:
	pr_warn("Unable to locate task mm for pid: %d", task->pid);
	return  false;
}

static int check_process_bloat(void *)
{
	struct task_struct *task = NULL;
	struct pid *pid_struct = NULL;

	while (!kthread_should_stop()) {
		pid_struct = find_get_pid(pid);
		if (!pid_struct)
			goto out;

		task = pid_task(pid_struct, PIDTYPE_PID);
		if (!task)
			goto out;

		/* Calculate bloat. */
		remove_bloat(task);
		msleep(sleep);
		
	}
	return 0;
out:
	pr_warn("Unable to find task: %d\n", pid);
	return -1;
}

static int __init debloat_init(void)
{
	task = kthread_run(check_process_bloat, NULL, "hwk_debloat");
	if (!task || IS_ERR(task)) {
		return -ENOMEM;
	}
	return 0;
}

static void __exit debloat_cleanup(void)
{
	printk(KERN_INFO"Module Exiting\n");
	if (task) {
		kthread_stop(task);
	}
}

module_init(debloat_init);
module_exit(debloat_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashish Panwar");
