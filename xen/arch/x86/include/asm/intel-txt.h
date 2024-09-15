/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Intel TXT is an implementation of DRTM in CPUs made by Intel (although CPU
 * alone isn't enough, chipset must support TXT as well).
 *
 * Overview:
 *   https://www.intel.com/content/www/us/en/support/articles/000025873/processors.html
 * Software Development Guide (SDG):
 *   https://www.intel.com/content/www/us/en/content-details/315168/
 */

#ifndef X86_INTEL_TXT_H
#define X86_INTEL_TXT_H

/*
 * TXT configuration registers (offsets from TXT_{PUB, PRIV}_CONFIG_REGS_BASE)
 */
#define TXT_PUB_CONFIG_REGS_BASE        0xfed30000U
#define TXT_PRIV_CONFIG_REGS_BASE       0xfed20000U

/*
 * The same set of registers is exposed twice (with different permissions) and
 * they are allocated continuously with page alignment.
 */
#define TXT_CONFIG_SPACE_SIZE \
    (TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE)

/* Offsets from pub/priv config space. */
#define TXTCR_STS                       0x0000
#define TXTCR_ESTS                      0x0008
#define TXTCR_ERRORCODE                 0x0030
#define TXTCR_CMD_RESET                 0x0038
#define TXTCR_CMD_CLOSE_PRIVATE         0x0048
#define TXTCR_DIDVID                    0x0110
#define TXTCR_VER_EMIF                  0x0200
#define TXTCR_CMD_UNLOCK_MEM_CONFIG     0x0218
#define TXTCR_SINIT_BASE                0x0270
#define TXTCR_SINIT_SIZE                0x0278
#define TXTCR_MLE_JOIN                  0x0290
#define TXTCR_HEAP_BASE                 0x0300
#define TXTCR_HEAP_SIZE                 0x0308
#define TXTCR_SCRATCHPAD                0x0378
#define TXTCR_CMD_OPEN_LOCALITY1        0x0380
#define TXTCR_CMD_CLOSE_LOCALITY1       0x0388
#define TXTCR_CMD_OPEN_LOCALITY2        0x0390
#define TXTCR_CMD_CLOSE_LOCALITY2       0x0398
#define TXTCR_CMD_SECRETS               0x08e0
#define TXTCR_CMD_NO_SECRETS            0x08e8
#define TXTCR_E2STS                     0x08f0

/*
 * Secure Launch Defined Error Codes used in MLE-initiated TXT resets.
 *
 * TXT Specification
 * Appendix I ACM Error Codes
 */
#define SLAUNCH_ERROR_GENERIC                0xc0008001U
#define SLAUNCH_ERROR_TPM_INIT               0xc0008002U
#define SLAUNCH_ERROR_TPM_INVALID_LOG20      0xc0008003U
#define SLAUNCH_ERROR_TPM_LOGGING_FAILED     0xc0008004U
#define SLAUNCH_ERROR_REGION_STRADDLE_4GB    0xc0008005U
#define SLAUNCH_ERROR_TPM_EXTEND             0xc0008006U
#define SLAUNCH_ERROR_MTRR_INV_VCNT          0xc0008007U
#define SLAUNCH_ERROR_MTRR_INV_DEF_TYPE      0xc0008008U
#define SLAUNCH_ERROR_MTRR_INV_BASE          0xc0008009U
#define SLAUNCH_ERROR_MTRR_INV_MASK          0xc000800aU
#define SLAUNCH_ERROR_MSR_INV_MISC_EN        0xc000800bU
#define SLAUNCH_ERROR_INV_AP_INTERRUPT       0xc000800cU
#define SLAUNCH_ERROR_INTEGER_OVERFLOW       0xc000800dU
#define SLAUNCH_ERROR_HEAP_WALK              0xc000800eU
#define SLAUNCH_ERROR_HEAP_MAP               0xc000800fU
#define SLAUNCH_ERROR_REGION_ABOVE_4GB       0xc0008010U
#define SLAUNCH_ERROR_HEAP_INVALID_DMAR      0xc0008011U
#define SLAUNCH_ERROR_HEAP_DMAR_SIZE         0xc0008012U
#define SLAUNCH_ERROR_HEAP_DMAR_MAP          0xc0008013U
#define SLAUNCH_ERROR_HI_PMR_BASE            0xc0008014U
#define SLAUNCH_ERROR_HI_PMR_SIZE            0xc0008015U
#define SLAUNCH_ERROR_LO_PMR_BASE            0xc0008016U
#define SLAUNCH_ERROR_LO_PMR_SIZE            0xc0008017U
#define SLAUNCH_ERROR_LO_PMR_MLE             0xc0008018U
#define SLAUNCH_ERROR_INITRD_TOO_BIG         0xc0008019U
#define SLAUNCH_ERROR_HEAP_ZERO_OFFSET       0xc000801aU
#define SLAUNCH_ERROR_WAKE_BLOCK_TOO_SMALL   0xc000801bU
#define SLAUNCH_ERROR_MLE_BUFFER_OVERLAP     0xc000801cU
#define SLAUNCH_ERROR_BUFFER_BEYOND_PMR      0xc000801dU
#define SLAUNCH_ERROR_OS_SINIT_BAD_VERSION   0xc000801eU
#define SLAUNCH_ERROR_EVENTLOG_MAP           0xc000801fU
#define SLAUNCH_ERROR_TPM_NUMBER_ALGS        0xc0008020U
#define SLAUNCH_ERROR_TPM_UNKNOWN_DIGEST     0xc0008021U
#define SLAUNCH_ERROR_TPM_INVALID_EVENT      0xc0008022U

#define SLAUNCH_BOOTLOADER_MAGIC             0x4c534254

#define TXT_AP_BOOT_CS                  0x0030
#define TXT_AP_BOOT_DS                  0x0038

/* EAX value for GETSEC leaf functions. Intel SDM: GETSEC[CAPABILITIES] */
#define GETSEC_CAPABILITIES             0
/* Intel SDM: GETSEC Capability Result Encoding */
#define GETSEC_CAP_TXT_CHIPSET          1

#ifndef __ASSEMBLY__

#include <xen/slr-table.h>

/* Need to differentiate between pre- and post paging enabled. */
#ifdef __EARLY_SLAUNCH__
#include <xen/macros.h>
#define _txt(x) _p(x)
#else
#include <xen/types.h>
#include <asm/page.h>   // __va()
#define _txt(x) __va(x)
#endif

extern char txt_ap_entry[];
extern uint32_t trampoline_gdt[];

/*
 * Always use private space as some of registers are either read-only or not
 * present in public space.
 */
static inline uint64_t txt_read(unsigned int reg_no)
{
    volatile uint64_t *reg = _txt(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
    return *reg;
}

static inline void txt_write(unsigned int reg_no, uint64_t val)
{
    volatile uint64_t *reg = _txt(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
    *reg = val;
}

static inline void noreturn txt_reset(uint32_t error)
{
    txt_write(TXTCR_ERRORCODE, error);
    txt_write(TXTCR_CMD_NO_SECRETS, 1);
    txt_write(TXTCR_CMD_UNLOCK_MEM_CONFIG, 1);
    /*
     * This serves as TXT register barrier after writing to
     * TXTCR_CMD_UNLOCK_MEM_CONFIG. Must be done to ensure that any future
     * chipset operations see the write.
     */
    (void)txt_read(TXTCR_ESTS);
    txt_write(TXTCR_CMD_RESET, 1);
    unreachable();
}

/*
 * Secure Launch defined OS/MLE TXT Heap table
 */
struct txt_os_mle_data {
    uint32_t version;
    uint32_t reserved;
    uint64_t slrt;
    uint64_t txt_info;
    uint32_t ap_wake_block;
    uint32_t ap_wake_block_size;
    uint8_t mle_scratch[64];
} __packed;

/*
 * TXT specification defined BIOS data TXT Heap table
 */
struct txt_bios_data {
    uint32_t version; /* Currently 5 for TPM 1.2 and 6 for TPM 2.0 */
    uint32_t bios_sinit_size;
    uint64_t reserved1;
    uint64_t reserved2;
    uint32_t num_logical_procs;
    /* Versions >= 3 && < 5 */
    uint32_t sinit_flags;
    /* Versions >= 5 with updates in version 6 */
    uint32_t mle_flags;
    /* Versions >= 4 */
    /* Ext Data Elements */
} __packed;

/*
 * TXT specification defined OS/SINIT TXT Heap table
 */
struct txt_os_sinit_data {
    uint32_t version;       /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
    uint32_t flags;         /* Reserved in version 6 */
    uint64_t mle_ptab;
    uint64_t mle_size;
    uint64_t mle_hdr_base;
    uint64_t vtd_pmr_lo_base;
    uint64_t vtd_pmr_lo_size;
    uint64_t vtd_pmr_hi_base;
    uint64_t vtd_pmr_hi_size;
    uint64_t lcp_po_base;
    uint64_t lcp_po_size;
    uint32_t capabilities;
    /* Version = 5 */
    uint64_t efi_rsdt_ptr;  /* RSD*P* in versions >= 6 */
    /* Versions >= 6 */
    /* Ext Data Elements */
} __packed;

/*
 * TXT specification defined SINIT/MLE TXT Heap table
 */
struct txt_sinit_mle_data {
    uint32_t version;  /* Current values are 6 through 9 */
    /* Versions <= 8, fields until lcp_policy_control must be 0 for >= 9 */
    uint8_t bios_acm_id[20];
    uint32_t edx_senter_flags;
    uint64_t mseg_valid;
    uint8_t sinit_hash[20];
    uint8_t mle_hash[20];
    uint8_t stm_hash[20];
    uint8_t lcp_policy_hash[20];
    uint32_t lcp_policy_control;
    /* Versions >= 7 */
    uint32_t rlp_wakeup_addr;
    uint32_t reserved;
    uint32_t num_of_sinit_mdrs;
    uint32_t sinit_mdrs_table_offset;
    uint32_t sinit_vtd_dmar_table_size;
    uint32_t sinit_vtd_dmar_table_offset;
    /* Versions >= 8 */
    uint32_t processor_scrtm_status;
    /* Versions >= 9 */
    /* Ext Data Elements */
} __packed;

/* Types of extended data. */
#define TXT_HEAP_EXTDATA_TYPE_END                    0
#define TXT_HEAP_EXTDATA_TYPE_BIOS_SPEC_VER          1
#define TXT_HEAP_EXTDATA_TYPE_ACM                    2
#define TXT_HEAP_EXTDATA_TYPE_STM                    3
#define TXT_HEAP_EXTDATA_TYPE_CUSTOM                 4
#define TXT_HEAP_EXTDATA_TYPE_MADT                   6
#define TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1   8
#define TXT_HEAP_EXTDATA_TYPE_MCFG                   9
#define TXT_HEAP_EXTDATA_TYPE_TPR_REQ               13
#define TXT_HEAP_EXTDATA_TYPE_DTPR                  14
#define TXT_HEAP_EXTDATA_TYPE_CEDT                  15

/*
 * Self-describing data structure that is used for extensions to TXT heap
 * tables.
 */
struct txt_ext_data_element {
    uint32_t type;   /* One of TXT_HEAP_EXTDATA_TYPE_*. */
    uint32_t size;
    uint8_t data[0]; /* size bytes. */
} __packed;

/*
 * Extended data describing TPM 2.0 log.
 */
struct heap_event_log_pointer_element2_1 {
    uint64_t physical_address;
    uint32_t allocated_event_container_size;
    uint32_t first_record_offset;
    uint32_t next_record_offset;
} __packed;

/*
 * Functions to extract data from the Intel TXT Heap Memory.
 *
 * The layout of the heap is dictated by TXT. It's a set of variable-sized
 * tables that appear in pre-defined order:
 *
 *   +------------------------------------+
 *   | Size of Bios Data table (uint64_t) |
 *   +------------------------------------+
 *   | Bios Data table                    |
 *   +------------------------------------+
 *   | Size of OS MLE table (uint64_t)    |
 *   +------------------------------------+
 *   | OS MLE table                       |
 *   +--------------------------------    +
 *   | Size of OS SINIT table (uint64_t)  |
 *   +------------------------------------+
 *   | OS SINIT table                     |
 *   +------------------------------------+
 *   | Size of SINIT MLE table (uint64_t) |
 *   +------------------------------------+
 *   | SINIT MLE table                    |
 *   +------------------------------------+
 *
 * NOTE: the table size fields include the 8 byte size field itself.
 *
 * NOTE: despite SDG mentioning 8-byte alignment, at least some BIOS ACM modules
 *       were observed to violate this requirement for Bios Data table, so not
 *       enforcing any alignment.
 */
static inline uint64_t txt_bios_data_size(const void *heap)
{
    return *(const uint64_t *)heap - sizeof(uint64_t);
}

static inline void *txt_bios_data_start(const void *heap)
{
    return (void *)heap + sizeof(uint64_t);
}

static inline uint64_t txt_os_mle_data_size(const void *heap)
{
    return *(const uint64_t *)(txt_bios_data_start(heap) +
                               txt_bios_data_size(heap)) -
           sizeof(uint64_t);
}

static inline void *txt_os_mle_data_start(const void *heap)
{
    return txt_bios_data_start(heap) + txt_bios_data_size(heap) +
           sizeof(uint64_t);
}

static inline uint64_t txt_os_sinit_data_size(const void *heap)
{
    return *(const uint64_t *)(txt_os_mle_data_start(heap) +
                               txt_os_mle_data_size(heap)) -
           sizeof(uint64_t);
}

static inline void *txt_os_sinit_data_start(const void *heap)
{
    return txt_os_mle_data_start(heap) + txt_os_mle_data_size(heap) +
           sizeof(uint64_t);
}

static inline uint64_t txt_sinit_mle_data_size(const void *heap)
{
    return *(const uint64_t *)(txt_os_sinit_data_start(heap) +
                               txt_os_sinit_data_size(heap)) -
           sizeof(uint64_t);
}

static inline void *txt_sinit_mle_data_start(const void *heap)
{
    return txt_os_sinit_data_start(heap) + txt_os_sinit_data_size(heap) +
           sizeof(uint64_t);
}

static inline void *txt_init(void)
{
    void *txt_heap;

    /* Clear the TXT error register for a clean start of the day. */
    txt_write(TXTCR_ERRORCODE, 0);

    txt_heap = _p(txt_read(TXTCR_HEAP_BASE));

    if ( txt_os_mle_data_size(txt_heap) < sizeof(struct txt_os_mle_data) ||
         txt_os_sinit_data_size(txt_heap) < sizeof(struct txt_os_sinit_data) )
        txt_reset(SLAUNCH_ERROR_GENERIC);

    return txt_heap;
}

static inline int is_in_pmr(const struct txt_os_sinit_data *os_sinit,
                            uint64_t base, uint32_t size, int check_high)
{
    /* Check for size overflow. */
    if ( base + size < base )
        txt_reset(SLAUNCH_ERROR_INTEGER_OVERFLOW);

    /* Low range always starts at 0, so its size is also end address. */
    if ( base >= os_sinit->vtd_pmr_lo_base &&
         base + size <= os_sinit->vtd_pmr_lo_size )
        return 1;

    if ( check_high && os_sinit->vtd_pmr_hi_size != 0 )
    {
        if ( os_sinit->vtd_pmr_hi_base + os_sinit->vtd_pmr_hi_size <
             os_sinit->vtd_pmr_hi_size )
            txt_reset(SLAUNCH_ERROR_INTEGER_OVERFLOW);
        if ( base >= os_sinit->vtd_pmr_hi_base &&
             base + size <= os_sinit->vtd_pmr_hi_base +
                            os_sinit->vtd_pmr_hi_size )
            return 1;
    }

    return 0;
}

static inline void txt_verify_pmr_ranges(
    const struct txt_os_mle_data *os_mle,
    const struct txt_os_sinit_data *os_sinit,
    const struct slr_entry_intel_info *info,
    uint32_t load_base_addr,
    uint32_t tgt_base_addr,
    uint32_t xen_size)
{
    int check_high_pmr = 0;

    /* Verify the value of the low PMR base. It should always be 0. */
    if ( os_sinit->vtd_pmr_lo_base != 0 )
        txt_reset(SLAUNCH_ERROR_LO_PMR_BASE);

    /*
     * Low PMR size should not be 0 on current platforms. There is an ongoing
     * transition to TPR-based DMA protection instead of PMR-based; this is not
     * yet supported by the code.
     */
    if ( os_sinit->vtd_pmr_lo_size == 0 )
        txt_reset(SLAUNCH_ERROR_LO_PMR_SIZE);

    /* Check if regions overlap. Treat regions with no hole between as error. */
    if ( os_sinit->vtd_pmr_hi_size != 0 &&
         os_sinit->vtd_pmr_hi_base <= os_sinit->vtd_pmr_lo_size )
        txt_reset(SLAUNCH_ERROR_HI_PMR_BASE);

    /* All regions accessed by 32b code must be below 4G. */
    if ( os_sinit->vtd_pmr_hi_base + os_sinit->vtd_pmr_hi_size <=
         0x100000000ULL )
        check_high_pmr = 1;

    /*
     * ACM checks that TXT heap and MLE memory is protected against DMA. We have
     * to check if MBI and whole Xen memory is protected. The latter is done in
     * case bootloader failed to set whole image as MLE and to make sure that
     * both pre- and post-relocation code is protected.
     */

    /* Check if all of Xen before relocation is covered by PMR. */
    if ( !is_in_pmr(os_sinit, load_base_addr, xen_size, check_high_pmr) )
        txt_reset(SLAUNCH_ERROR_LO_PMR_MLE);

    /* Check if all of Xen after relocation is covered by PMR. */
    if ( load_base_addr != tgt_base_addr &&
         !is_in_pmr(os_sinit, tgt_base_addr, xen_size, check_high_pmr) )
        txt_reset(SLAUNCH_ERROR_LO_PMR_MLE);

    /*
     * If present, check that MBI is covered by PMR. MBI starts with 'uint32_t
     * total_size'.
     */
    if ( info->boot_params_base != 0 &&
         !is_in_pmr(os_sinit, info->boot_params_base,
                    *(uint32_t *)(uintptr_t)info->boot_params_base,
                    check_high_pmr) )
        txt_reset(SLAUNCH_ERROR_BUFFER_BEYOND_PMR);

    /* Check if TPM event log (if present) is covered by PMR. */
    /*
     * FIXME: currently commented out as GRUB allocates it in a hole between
     * PMR and reserved RAM, due to 2MB resolution of PMR. There are no other
     * easy-to-use DMA protection mechanisms that would allow to protect that
     * part of memory. TPR (TXT DMA Protection Range) gives 1MB resolution, but
     * it still wouldn't be enough.
     *
     * One possible solution would be for GRUB to allocate log at lower address,
     * but this would further increase memory space fragmentation. Another
     * option is to align PMR up instead of down, making PMR cover part of
     * reserved region, but it is unclear what the consequences may be.
     *
     * In tboot this issue was resolved by reserving leftover chunks of memory
     * in e820 and/or UEFI memory map. This is also a valid solution, but would
     * require more changes to GRUB than the ones listed above, as event log is
     * allocated much earlier than PMRs.
     */
    /*
    if ( os_mle->evtlog_addr != 0 && os_mle->evtlog_size != 0 &&
         !is_in_pmr(os_sinit, os_mle->evtlog_addr, os_mle->evtlog_size,
                    check_high_pmr) )
        txt_reset(SLAUNCH_ERROR_BUFFER_BEYOND_PMR);
    */
}

/* Prepares for accesses to TXT-specific memory. */
void txt_map_mem_regions(void);

/* Marks TXT-specific memory as used to avoid its corruption. */
void txt_reserve_mem_regions(void);

/* Restores original MTRR values saved by a bootloader before starting DRTM. */
void txt_restore_mtrrs(bool e820_verbose);

#endif /* __ASSEMBLY__ */

#endif /* X86_INTEL_TXT_H */
