/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#include <xen/compiler.h>
#include <xen/efi.h>
#include <xen/init.h>
#include <xen/macros.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <asm/bootinfo.h>
#include <asm/e820.h>
#include <asm/intel-txt.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/slaunch.h>
#include <asm/tpm.h>

/* SLB is 64k, 64k-aligned */
#define SKINIT_SLB_SIZE   0x10000
#define SKINIT_SLB_ALIGN  0x10000

/*
 * These variables are assigned to by the code near Xen's entry point.
 *
 * slaunch_active is not __initdata to allow checking for an active Secure
 * Launch boot at any point.
 */
bool slaunch_active;
uint32_t __initdata slaunch_slrt; /* physical address */

/* Using slaunch_active in head.S assumes it's a single byte in size, so enforce
 * this assumption. */
static void __maybe_unused compile_time_checks(void)
{
    BUILD_BUG_ON(sizeof(slaunch_active) != 1);
}

struct slr_table *__init slaunch_get_slrt(void)
{
    static struct slr_table *slrt;

    if (slrt == NULL) {
        int rc;
        bool intel_cpu = (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL);
        uint16_t slrt_architecture = intel_cpu ? SLR_INTEL_TXT : SLR_AMD_SKINIT;

        slrt = __va(slaunch_slrt);

        rc = slaunch_map_l2(slaunch_slrt, PAGE_SIZE);
        BUG_ON(rc != 0);

        if ( slrt->magic != SLR_TABLE_MAGIC )
            panic("SLRT has invalid magic value: %#08x!\n", slrt->magic);
        /* XXX: are newer revisions allowed? */
        if ( slrt->revision != SLR_TABLE_REVISION )
            panic("SLRT is of unsupported revision: %#04x!\n", slrt->revision);
        if ( slrt->architecture != slrt_architecture )
            panic("SLRT is for unexpected architecture: %#04x != %#04x!\n",
                  slrt->architecture, slrt_architecture);
        if ( slrt->size > slrt->max_size )
            panic("SLRT is larger than its max size: %#08x > %#08x!\n",
                  slrt->size, slrt->max_size);

        if ( slrt->size > PAGE_SIZE )
        {
            rc = slaunch_map_l2(slaunch_slrt, slrt->size);
            BUG_ON(rc != 0);
        }
    }

    return slrt;
}

static uint32_t __init get_slb_start(void)
{
    /*
     * The runtime computation relies on size being a power of 2 and equal to
     * alignment. Make sure these assumptions hold.
     */
    BUILD_BUG_ON(SKINIT_SLB_SIZE != SKINIT_SLB_ALIGN);
    BUILD_BUG_ON(SKINIT_SLB_SIZE == 0);
    BUILD_BUG_ON((SKINIT_SLB_SIZE & (SKINIT_SLB_SIZE - 1)) != 0);

    /*
     * Rounding any address within SLB down to alignment gives SLB base and
     * SLRT is inside SLB on AMD.
     */
    return slaunch_slrt & ~(SKINIT_SLB_SIZE - 1);
}

void __init slaunch_map_mem_regions(void)
{
    int rc;
    void *evt_log_addr;
    uint32_t evt_log_size;

    rc = slaunch_map_l2(TPM_TIS_BASE, TPM_TIS_SIZE);
    BUG_ON(rc != 0);

    /* Vendor-specific part. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        txt_map_mem_regions();
    else if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        slaunch_map_l2(get_slb_start(), SKINIT_SLB_SIZE);

    find_evt_log(slaunch_get_slrt(), &evt_log_addr, &evt_log_size);
    if ( evt_log_addr != NULL )
    {
        rc = slaunch_map_l2((uintptr_t)evt_log_addr, evt_log_size);
        BUG_ON(rc != 0);
    }
}

void __init slaunch_reserve_mem_regions(void)
{
    int rc;

    void *evt_log_addr;
    uint32_t evt_log_size;

    /* Vendor-specific part. */
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
    {
        txt_reserve_mem_regions();
    }
    else if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
    {
        uint64_t slb_start = get_slb_start();
        uint64_t slb_end = slb_start + SKINIT_SLB_SIZE;
        printk("SLAUNCH: reserving SLB (%#lx - %#lx)\n", slb_start, slb_end);
        rc = reserve_e820_ram(&e820_raw, slb_start, slb_end);
        BUG_ON(rc == 0);
    }

    find_evt_log(slaunch_get_slrt(), &evt_log_addr, &evt_log_size);
    if ( evt_log_addr != NULL )
    {
        printk("SLAUNCH: reserving event log (%#lx - %#lx)\n",
               (uint64_t)evt_log_addr,
               (uint64_t)evt_log_addr + evt_log_size);
        rc = reserve_e820_ram(&e820_raw, (uint64_t)evt_log_addr,
                              (uint64_t)evt_log_addr + evt_log_size);
        BUG_ON(rc == 0);
    }
}

void __init slaunch_measure_slrt(void)
{
    struct slr_table *slrt = slaunch_get_slrt();

    if ( slrt->revision == 1 )
    {
        /*
         * In revision one of the SLRT, only platform-specific info table is
         * measured.
         */
        if ( boot_cpu_data.x86_vendor == X86_VENDOR_INTEL )
        {
            struct slr_entry_intel_info tmp;
            struct slr_entry_intel_info *entry;

            entry = (struct slr_entry_intel_info *)
                slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_INTEL_INFO);
            if ( entry == NULL )
                panic("SLRT is missing Intel-specific information!\n");

            tmp = *entry;
            tmp.boot_params_base = 0;
            tmp.txt_heap = 0;

            tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)&tmp,
                            sizeof(tmp), DLE_EVTYPE_SLAUNCH, NULL, 0);
        }
        else if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        {
            struct slr_entry_amd_info tmp;
            struct slr_entry_amd_info *entry;

            entry = (struct slr_entry_amd_info *)
                slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_AMD_INFO);
            if ( entry == NULL )
                panic("SLRT is missing AMD-specific information!\n");

            tmp = *entry;
            tmp.next = 0;
            tmp.slrt_base = 0;
            tmp.boot_params_base = 0;

            tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR, (uint8_t *)&tmp,
                            sizeof(tmp), DLE_EVTYPE_SLAUNCH, NULL, 0);
        }
    }
    else
    {
        /*
         * slaunch_get_slrt() checks that the revision is valid, so we must not get
         * here unless the code is wrong.
         */
        panic("Unhandled SLRT revision: %d!\n", slrt->revision);
    }
}

static const struct slr_entry_policy *__init
slr_get_policy(const struct slr_table *slrt)
{
    struct slr_entry_policy *policy;

    policy = (struct slr_entry_policy *)
        slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_DRTM_POLICY);
    if (policy == NULL)
        panic("SLRT is missing DRTM policy!\n");

    /* XXX: are newer revisions allowed? */
    if ( policy->revision != SLR_POLICY_REVISION )
        panic("DRTM policy in SLRT is of unsupported revision: %#04x!\n",
              slrt->revision);

    return policy;
}

static void __init
check_slrt_policy_entry(struct slr_policy_entry *policy_entry,
                        int idx,
                        const struct slr_table *slrt)
{
    if ( policy_entry->entity_type != SLR_ET_SLRT )
        panic("Expected DRTM policy entry #%d to describe SLRT, got %#04x!\n",
              idx, policy_entry->entity_type);
    if ( policy_entry->pcr != DRTM_DATA_PCR )
        panic("SLRT was measured to PCR-%d instead of PCR-%d!\n", DRTM_DATA_PCR,
              policy_entry->pcr);
    if ( policy_entry->entity != (uint64_t)__pa(slrt) )
        panic("SLRT address (%#08lx) differs from its DRTM entry (%#08lx)\n",
              __pa(slrt), policy_entry->entity);
}

/* Returns number of policy entries that were already measured. */
static unsigned int __init
check_drtm_policy(const struct slr_table *slrt,
                  const struct slr_entry_policy *policy,
                  struct slr_policy_entry *policy_entry,
                  const struct boot_info *bi)
{
    uint32_t i;
    uint32_t num_mod_entries;
    int min_entries;

    min_entries = efi_enabled(EFI_BOOT) ? 1 : 2;
    if ( policy->nr_entries < min_entries )
    {
        panic("DRTM policy in SLRT contains less than %d entries (%d)!\n",
              min_entries, policy->nr_entries);
    }

    if ( efi_enabled(EFI_BOOT) )
    {
        check_slrt_policy_entry(&policy_entry[0], 0, slrt);
        /* SLRT was measured in tpm_measure_slrt(). */
        return 1;
    }

    /* This must be legacy MultiBoot2 boot. */

    /*
     * MBI policy entry must be the first one, so that measuring order matches
     * policy order.
     */
    if ( policy_entry[0].entity_type != SLR_ET_MULTIBOOT2_INFO )
        panic("First entry of DRTM policy in SLRT is not MBI: %#04x!\n",
              policy_entry[0].entity_type);
    if ( policy_entry[0].pcr != DRTM_DATA_PCR )
        panic("MBI was measured to %d instead of %d PCR!\n", DRTM_DATA_PCR,
              policy_entry[0].pcr);

    /* SLRT policy entry must be the second one. */
    check_slrt_policy_entry(&policy_entry[1], 1, slrt);

    for ( i = 0; i < bi->nr_modules; i++ )
    {
        uint16_t j;
        const struct boot_module *mod = &bi->mods[i];

        if (mod->arch.relocated || mod->arch.released)
        {
            panic("Multiboot module \"%s\" (at %d) was consumed before measurement\n",
                  (const char *)__va(mod->arch.cmdline_pa), i);
        }

        for ( j = 2; j < policy->nr_entries; j++ )
        {
            if ( policy_entry[j].entity_type != SLR_ET_MULTIBOOT2_MODULE )
                continue;

            if ( policy_entry[j].entity == mod->start &&
                 policy_entry[j].size == mod->size )
                break;
        }

        if ( j >= policy->nr_entries )
        {
            panic("Couldn't find Multiboot module \"%s\" (at %d) in DRTM of Secure Launch\n",
                  (const char *)__va(mod->arch.cmdline_pa), i);
        }
    }

    num_mod_entries = 0;
    for ( i = 0; i < policy->nr_entries; i++ )
    {
        if ( policy_entry[i].entity_type == SLR_ET_MULTIBOOT2_MODULE )
            num_mod_entries++;
    }

    if ( bi->nr_modules != num_mod_entries )
    {
        panic("Unexpected number of Multiboot modules: %d instead of %d\n",
              (int)bi->nr_modules, (int)num_mod_entries);
    }

    /*
     * MBI was measured in tpm_extend_mbi().
     * SLRT was measured in tpm_measure_slrt().
     */
    return 2;
}

void __init slaunch_process_drtm_policy(const struct boot_info *bi)
{
    const struct slr_table *slrt;
    const struct slr_entry_policy *policy;
    struct slr_policy_entry *policy_entry;
    int rc;
    uint16_t i;
    unsigned int measured;

    slrt = slaunch_get_slrt();

    policy = slr_get_policy(slrt);
    policy_entry = (void *)policy + sizeof(*policy);

    measured = check_drtm_policy(slrt, policy, policy_entry, bi);
    for ( i = 0; i < measured; i++ )
        policy_entry[i].flags |= SLR_POLICY_FLAG_MEASURED;

    for ( i = measured; i < policy->nr_entries; i++ )
    {
        uint64_t start = policy_entry[i].entity;
        uint64_t size = policy_entry[i].size;

        /* No already measured entries are expected here. */
        if ( policy_entry[i].flags & SLR_POLICY_FLAG_MEASURED )
            panic("DRTM entry at %d was measured out of order!\n", i);

        switch ( policy_entry[i].entity_type )
        {
        case SLR_ET_MULTIBOOT2_INFO:
            panic("Duplicated MBI entry in DRTM of Secure Launch at %d\n", i);
        case SLR_ET_SLRT:
            panic("Duplicated SLRT entry in DRTM of Secure Launch at %d\n", i);

        case SLR_ET_UNSPECIFIED:
        case SLR_ET_BOOT_PARAMS:
        case SLR_ET_SETUP_DATA:
        case SLR_ET_CMDLINE:
        case SLR_ET_UEFI_MEMMAP:
        case SLR_ET_RAMDISK:
        case SLR_ET_MULTIBOOT2_MODULE:
        case SLR_ET_TXT_OS2MLE:
            /* Measure this entry below. */
            break;

        case SLR_ET_UNUSED:
            /* Skip this entry. */
            continue;
        }

        if ( policy_entry[i].flags & SLR_POLICY_IMPLICIT_SIZE )
            panic("Unexpected implicitly-sized DRTM entry of Secure Launch at %d (type %d, info: %s)\n",
                  i, policy_entry[i].entity_type, policy_entry[i].evt_info);

        rc = slaunch_map_l2(start, size);
        BUG_ON(rc != 0);

        tpm_hash_extend(DRTM_LOC, policy_entry[i].pcr, __va(start), size,
                        DLE_EVTYPE_SLAUNCH, (uint8_t *)policy_entry[i].evt_info,
                        strnlen(policy_entry[i].evt_info,
                                TPM_EVENT_INFO_LENGTH));

        policy_entry[i].flags |= SLR_POLICY_FLAG_MEASURED;
    }

    /*
     * On x86 EFI platforms Xen reads its command-line options and kernel/initrd
     * from configuration files (several can be chained). Bootloader can't know
     * contents of the configuration beforehand without parsing it, so there
     * will be no corresponding policy entries. Instead, measure command-line
     * and all modules here.
     */
    if ( efi_enabled(EFI_BOOT) )
    {
#define LOG_DATA(str) (uint8_t *)(str), (sizeof(str) - 1)

        tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR,
                        (const uint8_t *)bi->cmdline, strlen(bi->cmdline),
                        DLE_EVTYPE_SLAUNCH, LOG_DATA("Xen's command line"));

        for ( i = 0; i < bi->nr_modules; i++ )
        {
            const struct boot_module *mod = &bi->mods[i];

            paddr_t string = mod->arch.cmdline_pa;
            paddr_t start = mod->start;
            size_t size = mod->size;

            if ( mod->arch.relocated || mod->arch.released )
            {
                panic("A module \"%s\" (#%d) was consumed before measurement\n",
                      (const char *)__va(string), i);
            }

            /*
             * Measuring module's name separately because module's command-line
             * parameters are appended to its name when present.
             *
             * 2 MiB is minimally mapped size and it should more than suffice.
             */
            rc = slaunch_map_l2(string, 2 * 1024 * 1024);
            BUG_ON(rc != 0);

            tpm_hash_extend(DRTM_LOC, DRTM_DATA_PCR,
                            __va(string), strlen(__va(string)),
                            DLE_EVTYPE_SLAUNCH, LOG_DATA("MB module string"));

            rc = slaunch_map_l2(start, size);
            BUG_ON(rc != 0);

            tpm_hash_extend(DRTM_LOC, DRTM_CODE_PCR, __va(start), size,
                            DLE_EVTYPE_SLAUNCH, LOG_DATA("MB module"));
        }

#undef LOG_DATA
    }
}

int __init slaunch_map_l2(unsigned long paddr, unsigned long size)
{
    unsigned long aligned_paddr = paddr & ~((1ULL << L2_PAGETABLE_SHIFT) - 1);
    unsigned long pages = ((paddr + size) - aligned_paddr);
    pages = ROUNDUP(pages, 1ULL << L2_PAGETABLE_SHIFT) >> PAGE_SHIFT;

    if ( aligned_paddr + pages * PAGE_SIZE <= PREBUILT_MAP_LIMIT )
        return 0;

    if ( aligned_paddr < PREBUILT_MAP_LIMIT )
    {
        pages -= (PREBUILT_MAP_LIMIT - aligned_paddr) >> PAGE_SHIFT;
        aligned_paddr = PREBUILT_MAP_LIMIT;
    }

    return map_pages_to_xen((uintptr_t)__va(aligned_paddr),
                            maddr_to_mfn(aligned_paddr),
                            pages, PAGE_HYPERVISOR);
}
