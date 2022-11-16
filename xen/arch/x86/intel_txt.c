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

    map_l2(TXT_PUB_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);

    txt_heap_base = txt_heap_size = sinit_base = sinit_size = 0;

    /* TXT Heap */
    txt_heap_base = read_txt_reg(TXTCR_HEAP_BASE);
    txt_heap_size = read_txt_reg(TXTCR_HEAP_SIZE);
    /* SINIT */
    sinit_base = read_txt_reg(TXTCR_SINIT_BASE);
    sinit_size = read_txt_reg(TXTCR_SINIT_SIZE);

    /* Remove mapping of TXT register space. */
    unmap_l2(TXT_PUB_CONFIG_REGS_BASE, NR_TXT_CONFIG_PAGES * PAGE_SIZE);

    /* TXT Heap */
    if ( txt_heap_base != 0 ) {
        struct txt_os_mle_data *os_mle;

        printk("SLAUNCH: reserving TXT heap (%#lx - %#lx)\n", txt_heap_base,
               txt_heap_base + txt_heap_size);
        e820_change_range_type(&e820_raw, txt_heap_base,
                               txt_heap_base + txt_heap_size,
                               E820_RAM, E820_RESERVED);

        /* TXT TPM Event Log */
        map_l2(txt_heap_base, txt_heap_size);
        os_mle = txt_os_mle_data_start(__va(txt_heap_base));

        if ( os_mle->evtlog_addr != 0 ) {
            printk("SLAUNCH: reserving event log (%#lx - %#lx)\n", os_mle->evtlog_addr,
                   os_mle->evtlog_addr + os_mle->evtlog_size);
            e820_change_range_type(&e820_raw, os_mle->evtlog_addr,
                                   os_mle->evtlog_addr + os_mle->evtlog_size,
                                   E820_RAM, E820_RESERVED);
        }

        unmap_l2(txt_heap_base, txt_heap_size);
    }

    /* SINIT */
    if ( sinit_base != 0 ) {
        printk("SLAUNCH: reserving SINIT memory (%#lx - %#lx)\n", sinit_base,
               sinit_base + sinit_size);
        e820_change_range_type(&e820_raw, sinit_base,
                               sinit_base + sinit_size,
                               E820_RAM, E820_RESERVED);
    }

    /* TXT Private Space */
    e820_change_range_type(&e820_raw, TXT_PRIV_CONFIG_REGS_BASE,
                 TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
                 E820_RAM, E820_UNUSABLE);
}

void __init txt_restore_mtrrs(bool e820_verbose)
{
    struct txt_os_mle_data *os_mle;
    int os_mle_size;
    uint64_t mtrr_cap, mtrr_def, base, mask;
    unsigned int i;

    map_l2(txt_heap_base, txt_heap_size);

    os_mle_size = txt_os_mle_data_size(__va(txt_heap_base));
    os_mle = txt_os_mle_data_start(__va(txt_heap_base));

    if ( os_mle_size < sizeof(*os_mle) )
        panic("OS-MLE too small\n");

    rdmsrl(MSR_MTRRcap, mtrr_cap);
    rdmsrl(MSR_MTRRdefType, mtrr_def);

    if ( e820_verbose ) {
        printk("MTRRs set previously for SINIT ACM:\n");
        printk(" MTRR cap: %"PRIx64" type: %"PRIx64"\n", mtrr_cap, mtrr_def);

        for ( i = 0; i < (uint8_t)mtrr_cap; i++ )
        {
            rdmsrl(MSR_IA32_MTRR_PHYSBASE(i), base);
            rdmsrl(MSR_IA32_MTRR_PHYSMASK(i), mask);

            printk(" MTRR[%d]: base %"PRIx64" mask %"PRIx64"\n",
                   i, base, mask);
        }
    }

    if ( (mtrr_cap & 0xFF) != os_mle->saved_bsp_mtrrs.mtrr_vcnt ) {
        printk("Bootloader saved %ld MTRR values, but there should be %ld\n",
               os_mle->saved_bsp_mtrrs.mtrr_vcnt, mtrr_cap & 0xFF);
        /* Choose the smaller one to be on the safe side. */
        mtrr_cap = (mtrr_cap & 0xFF) > os_mle->saved_bsp_mtrrs.mtrr_vcnt ?
                   os_mle->saved_bsp_mtrrs.mtrr_vcnt : mtrr_cap;
    }

    /* Restore MTRRs saved by bootloader. */
    wrmsrl(MSR_MTRRdefType, os_mle->saved_bsp_mtrrs.default_mem_type);

    for ( i = 0; i < (uint8_t)mtrr_cap; i++ )
    {
        base = os_mle->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physbase;
        mask = os_mle->saved_bsp_mtrrs.mtrr_pair[i].mtrr_physmask;
        wrmsrl(MSR_IA32_MTRR_PHYSBASE(i), base);
        wrmsrl(MSR_IA32_MTRR_PHYSMASK(i), mask);
    }

    unmap_l2(txt_heap_base, txt_heap_size);

    if ( e820_verbose )
        printk("Restored MTRRs:\n"); /* Printed by caller, mtrr_top_of_ram(). */
}
