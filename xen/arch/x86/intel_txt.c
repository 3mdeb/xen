#include <xen/types.h>
#include <asm/e820.h>
#include <xen/string.h>
#include <asm/page.h>

#include <asm/intel_txt.h>

void protect_txt_mem_regions(void)
{
    uint64_t txt_heap_base, txt_heap_size;
    uint64_t sinit_base, sinit_size;
    int rc;

    txt_heap_base = txt_heap_size = sinit_base = sinit_size = 0;
    /* TXT Heap */
    memcpy(maddr_to_virt(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_BASE),
           &txt_heap_base , sizeof(txt_heap_base));
    memcpy(maddr_to_virt(TXT_PUB_CONFIG_REGS_BASE + TXTCR_HEAP_SIZE),
           &txt_heap_size , sizeof(txt_heap_size));
    /* SINIT */
    memcpy(maddr_to_virt(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_BASE),
           &sinit_base , sizeof(sinit_base));
    memcpy(maddr_to_virt(TXT_PUB_CONFIG_REGS_BASE + TXTCR_SINIT_SIZE),
           &sinit_size , sizeof(sinit_size));

    /* TXT Heap */
    if ( txt_heap_base == 0 )
        return;

    rc = e820_change_range_type(&e820, txt_heap_base,
                                txt_heap_base + txt_heap_size,
                                E820_RESERVED, E820_UNUSABLE);
    if ( !rc )
        return;

    /* SINIT */
    if ( sinit_base == 0 )
        return;
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
