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

int pid = 0;
module_param(pid, int, 0640);

unsigned long distance = 0;

struct page *follow_page_custom(struct vm_area_struct *vma,
		unsigned long addr, unsigned int foll_flags);

static void print_bloat_info(unsigned long nr_total, unsigned long nr_zero)
{
	unsigned long nr_non_zero = nr_total - nr_zero;

	if (nr_total == 0)
		nr_total = 1;

	pr_crit("total: %ld zero: %ld fraction: %ld \
		distance: %ld non-zero: %ld", nr_total, nr_zero,
		(nr_zero * 100) / nr_total, distance, nr_non_zero);
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

static int non_zero_distance(u8 *start)
{
	u8 *curr = start;
	u8 *end = curr + PAGE_SIZE;
	int val;

	while (curr < end)
	{
		val = *curr;
		if (val)
			break;
		else
			curr++;
	}
	/* we need to read atleast 1 byte and hence
	 * the cost is never zero
	 * */
	return (curr - start) + 1;
}

/*
 * hpage must be a transparent huge page
 */
static int count_zero_pages(struct page *hpage)
{
	void *haddr;
	u8 *hstart, *hend, *addr;
	int nr_zero_pages = 0;

	haddr = kmap_atomic(hpage);
	hstart = (u8 *)haddr;
	hend = hstart + HPAGE_PMD_SIZE;
	/* zero checking logic */
	for (addr = hstart; addr < hend; addr += PAGE_SIZE) {
		if (is_page_zero(addr))
			nr_zero_pages += 1;
		else
			distance += non_zero_distance(addr);
	}
	kunmap_atomic(haddr);
	return nr_zero_pages;
}

/*
 * Traverse each page of given task and see how many pages
 * contain only-zeroes---this gives us a good enough indication.
 * on the upper bound of memory bloat.
 */
static bool calc_bloat(struct task_struct *task)
{
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = NULL;
	struct page *page;
	unsigned long nr_total = 0;
	unsigned long nr_zero = 0;
	unsigned long start, end, addr;

	mm = get_task_mm(task);
	if (!mm)
		goto out;

	/* traverse the list of all vma regions */
	for(vma = mm->mmap; vma; vma = vma->vm_next) {
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
			nr_zero += count_zero_pages(page);
			nr_total += 512;
			put_page(page);
			addr += HPAGE_PMD_SIZE;
		}
	}
	print_bloat_info(nr_total, nr_zero);
	mmput(mm);
	return true;

out:
	pr_warn("Unable to locate task mm for pid: %d", task->pid);
	return  false;
}

static int check_process_bloat(void)
{
	struct task_struct *task = NULL;
	struct pid *pid_struct = NULL;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		goto out;

	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto out;

	/* Calculate bloat. */
	calc_bloat(task);
	return 0;
out:
	pr_warn("Unable to find task: %d\n", pid);
	return -1;
}

static int __init detect_init(void)
{
	check_process_bloat();
	return 0;
}

static void __exit detect_cleanup(void)
{
	printk(KERN_INFO"Module Exiting\n");
}

module_init(detect_init);
module_exit(detect_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashish Panwar");
