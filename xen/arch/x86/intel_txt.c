#include <xen/types.h>
#include <asm/e820.h>
#include <xen/string.h>
#include <asm/page.h>
#include <asm/intel_txt.h>
#include <xen/init.h>
#include <xen/mm.h>

static uint64_t __initdata txt_heap_base, txt_heap_size;

unsigned long __initdata sl_status;

#define PREBUILT_MAP_LIMIT (1 << L2_PAGETABLE_SHIFT)

/*
 * These helper functions are used to (un)map memory using L2 page tables by
 * aligning mapped regions to 2MB. This way page allocator (which at this point
 * isn't yet initialized) isn't needed for creating new L1 mappings. Functions
 * also check and skip memory already mapped by the prebuilt tables.
 *
 * There are no tests against multiple mappings in the same superpage, in such
 * case first call to unmap_l2() destroys all mappings to given memory range.
 */
static int map_l2(unsigned long paddr, unsigned long size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);
    pages += (1ULL << L2_PAGETABLE_SHIFT) - 1;
    pages &= ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    pages >>= PAGE_SHIFT;

    if ( (aligned_paddr + pages * PAGE_SIZE) <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT ) {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return map_pages_to_xen((unsigned long)__va(aligned_paddr),
                            maddr_to_mfn(aligned_paddr),
                            pages, PAGE_HYPERVISOR);
}

static int unmap_l2(unsigned long paddr, unsigned long size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);
    pages += (1ULL << L2_PAGETABLE_SHIFT) - 1;
    pages &= ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    pages >>= PAGE_SHIFT;

    if ( (aligned_paddr + pages * PAGE_SIZE) <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT ) {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return destroy_xen_mappings(aligned_paddr,
                                aligned_paddr + pages * PAGE_SIZE);
}

void __init protect_txt_mem_regions(void)
{
    uint64_t sinit_base, sinit_size;
    int rc;

    map_l2(TXT_PUB_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);

    txt_heap_base = txt_heap_size = sinit_base = sinit_size = 0;
    /* TXT Heap */
    memcpy(&txt_heap_base, __va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_BASE),
           sizeof(txt_heap_base));
    memcpy(&txt_heap_size, __va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_SIZE),
           sizeof(txt_heap_size));
    /* SINIT */
    memcpy(&sinit_base, __va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_BASE),
           sizeof(sinit_base));
    memcpy(&sinit_size, __va(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_SIZE),
           sizeof(sinit_size));

    /* Remove mapping of TXT register space. */
    unmap_l2(TXT_PUB_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);

    /* TXT Heap */
    if ( txt_heap_base != 0 ) {
        printk("SLAUNCH: reserving TXT heap (%#lx - %#lx)\n", txt_heap_base,
               txt_heap_base + txt_heap_size);
        rc = e820_change_range_type(&e820, txt_heap_base,
                                    txt_heap_base + txt_heap_size,
                                    E820_RESERVED, E820_UNUSABLE);
        if ( !rc )
            return;
    }

    /* SINIT */
    if ( sinit_base != 0 ) {
        printk("SLAUNCH: reserving SINIT memory (%#lx - %#lx)\n", sinit_base,
               sinit_base + sinit_size);
        rc = e820_change_range_type(&e820, sinit_base,
                                    sinit_base + sinit_size,
                                    E820_RESERVED, E820_UNUSABLE);
        if ( !rc )
            return;
    }

    /* TXT Private Space */
    rc = e820_change_range_type(&e820, TXT_PRIV_CONFIG_REGS_BASE,
                 TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
                 E820_RESERVED, E820_UNUSABLE);
    return;
}
