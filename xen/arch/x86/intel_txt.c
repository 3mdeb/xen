#include <xen/types.h>
#include <asm/e820.h>
#include <xen/string.h>
#include <asm/page.h>
#include <asm/intel_txt.h>

void __init protect_txt_mem_regions(void)
{
    uint64_t txt_heap_base, txt_heap_size;
    uint64_t sinit_base, sinit_size;
    int rc;
    const unsigned int l2e_off = l2_linear_offset(TXT_PUB_CONFIG_REGS_BASE);
    l2_pgentry_t *l2e = &l2_bootmap[l2e_off];

    if ( l2e_get_flags(*l2e) & _PAGE_PRESENT )
        panic("Memory for TXT register space already mapped\n");

    /* Create new L2 page table entry covering TXT register space. */
    l2e->l2 = (TXT_PUB_CONFIG_REGS_BASE & ~((1ULL << L2_PAGETABLE_SHIFT) - 1))
              | __PAGE_HYPERVISOR_UC | _PAGE_PSE;
    asm volatile ( "invlpg %0" : :
                    "m" (*(const char *)TXT_PUB_CONFIG_REGS_BASE)
                    : "memory" );

    txt_heap_base = txt_heap_size = sinit_base = sinit_size = 0;
    /* TXT Heap */
    memcpy((void *)(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_BASE),
           &txt_heap_base , sizeof(txt_heap_base));
    memcpy((void *)(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_SIZE),
           &txt_heap_size , sizeof(txt_heap_size));
    /* SINIT */
    memcpy((void *)(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_BASE),
           &sinit_base , sizeof(sinit_base));
    memcpy((void *)(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_SIZE),
           &sinit_size , sizeof(sinit_size));

    /* Remove mapping of TXT register space. */
    l2e->l2 = 0;
    asm volatile ( "invlpg %0" : :
                    "m" (*(const char *)TXT_PUB_CONFIG_REGS_BASE)
                    : "memory" );

    /* TXT Heap */
    if ( txt_heap_base == 0 )
        return;

    printk("SLAUNCH: reserving TXT heap (%#lx - %#lx)\n", txt_heap_base,
           txt_heap_base + txt_heap_size);
    rc = e820_change_range_type(&e820, txt_heap_base,
                                txt_heap_base + txt_heap_size,
                                E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return;

    /* SINIT */
    if ( sinit_base == 0 )
        return;

    printk("SLAUNCH: reserving SINIT memory (%#lx - %#lx)\n", sinit_base,
           sinit_base + sinit_size);
    rc = e820_change_range_type(&e820, sinit_base,
                                sinit_base + sinit_size,
                                E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return;

    /* TXT Private Space */
    rc = e820_change_range_type(&e820, TXT_PRIV_CONFIG_REGS_BASE,
                 TXT_PRIV_CONFIG_REGS_BASE + NR_TXT_CONFIG_PAGES * PAGE_SIZE,
                 E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return;

    return;
}
