/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Main Secure Launch header file.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#ifndef _XEN_SLAUNCH_H
#define _XEN_SLAUNCH_H

/*
 * Secure Launch Defined State Flags
 */
#define SL_FLAG_ACTIVE		0x00000001
#define SL_FLAG_ARCH_SKINIT	0x00000002
#define SL_FLAG_ARCH_TXT	0x00000004

/*
 * Secure Launch CPU Type
 */
#define SL_CPU_AMD	1
#define SL_CPU_INTEL	2

#define __SL32_CS	0x0008
#define __SL32_DS	0x0010

/*
 * Intel Safer Mode Extensions (SMX)
 *
 * Intel SMX provides a programming interface to establish a Measured Launched
 * Environment (MLE). The measurement and protection mechanisms supported by the
 * capabilities of an Intel Trusted Execution Technology (TXT) platform. SMX is
 * the processor’s programming interface in an Intel TXT platform.
 *
 * See Intel SDM Volume 2 - 6.1 "Safer Mode Extensions Reference"
 */

/*
 * SMX GETSEC Leaf Functions
 */
#define SMX_X86_GETSEC_SEXIT	5
#define SMX_X86_GETSEC_SMCTRL	7
#define SMX_X86_GETSEC_WAKEUP	8

/*
 * Intel Trusted Execution Technology MMIO Registers Banks
 */
#define TXT_PUB_CONFIG_REGS_BASE	0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000
#define TXT_NR_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE - \
				  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

/*
 * Intel Trusted Execution Technology (TXT) Registers
 */
#define TXT_CR_STS			0x0000
#define TXT_CR_ESTS			0x0008
#define TXT_CR_ERRORCODE		0x0030
#define TXT_CR_CMD_RESET		0x0038
#define TXT_CR_CMD_CLOSE_PRIVATE	0x0048
#define TXT_CR_DIDVID			0x0110
#define TXT_CR_VER_EMIF			0x0200
#define TXT_CR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXT_CR_SINIT_BASE		0x0270
#define TXT_CR_SINIT_SIZE		0x0278
#define TXT_CR_MLE_JOIN			0x0290
#define TXT_CR_HEAP_BASE		0x0300
#define TXT_CR_HEAP_SIZE		0x0308
#define TXT_CR_SCRATCHPAD		0x0378
#define TXT_CR_CMD_OPEN_LOCALITY1	0x0380
#define TXT_CR_CMD_CLOSE_LOCALITY1	0x0388
#define TXT_CR_CMD_OPEN_LOCALITY2	0x0390
#define TXT_CR_CMD_CLOSE_LOCALITY2	0x0398
#define TXT_CR_CMD_SECRETS		0x08e0
#define TXT_CR_CMD_NO_SECRETS		0x08e8
#define TXT_CR_E2STS			0x08f0

/* TXT default register value */
#define TXT_REGVALUE_ONE		0x1ULL

/* TXTCR_STS status bits */
#define TXT_SENTER_DONE_STS		(1<<0)
#define TXT_SEXIT_DONE_STS		(1<<1)

/*
 * SINIT/MLE Capabilities Field Bit Definitions
 */
#define TXT_SINIT_MLE_CAP_WAKE_GETSEC	0
#define TXT_SINIT_MLE_CAP_WAKE_MONITOR	1

/*
 * OS/MLE Secure Launch Specific Definitions
 */
#define TXT_OS_MLE_STRUCT_VERSION	1
#define TXT_OS_MLE_MAX_VARIABLE_MTRRS	32

/*
 * TXT Heap Table Enumeration
 */
#define TXT_BIOS_DATA_TABLE		1
#define TXT_OS_MLE_DATA_TABLE		2
#define TXT_OS_SINIT_DATA_TABLE		3
#define TXT_SINIT_MLE_DATA_TABLE	4
#define TXT_SINIT_TABLE_MAX		TXT_SINIT_MLE_DATA_TABLE

/*
 * Secure Launch Defined Error Codes used in MLE-initiated TXT resets.
 *
 * TXT Specification
 * Appendix I ACM Error Codes
 */
#define SL_ERROR_GENERIC		0xc0008001
#define SL_ERROR_TPM_INIT		0xc0008002
#define SL_ERROR_TPM_INVALID_LOG20	0xc0008003
#define SL_ERROR_TPM_LOGGING_FAILED	0xc0008004
#define SL_ERROR_REGION_STRADDLE_4GB	0xc0008005
#define SL_ERROR_TPM_EXTEND		0xc0008006
#define SL_ERROR_MTRR_INV_VCNT		0xc0008007
#define SL_ERROR_MTRR_INV_DEF_TYPE	0xc0008008
#define SL_ERROR_MTRR_INV_BASE		0xc0008009
#define SL_ERROR_MTRR_INV_MASK		0xc000800a
#define SL_ERROR_MSR_INV_MISC_EN	0xc000800b
#define SL_ERROR_INV_AP_INTERRUPT	0xc000800c
#define SL_ERROR_INTEGER_OVERFLOW	0xc000800d
#define SL_ERROR_HEAP_WALK		0xc000800e
#define SL_ERROR_HEAP_MAP		0xc000800f
#define SL_ERROR_REGION_ABOVE_4GB	0xc0008010
#define SL_ERROR_HEAP_INVALID_DMAR	0xc0008011
#define SL_ERROR_HEAP_DMAR_SIZE		0xc0008012
#define SL_ERROR_HEAP_DMAR_MAP		0xc0008013
#define SL_ERROR_HI_PMR_BASE		0xc0008014
#define SL_ERROR_HI_PMR_SIZE		0xc0008015
#define SL_ERROR_LO_PMR_BASE		0xc0008016
#define SL_ERROR_LO_PMR_MLE		0xc0008017
#define SL_ERROR_INITRD_TOO_BIG		0xc0008018
#define SL_ERROR_HEAP_ZERO_OFFSET	0xc0008019
#define SL_ERROR_WAKE_BLOCK_TOO_SMALL	0xc000801a
#define SL_ERROR_MLE_BUFFER_OVERLAP	0xc000801b
#define SL_ERROR_BUFFER_BEYOND_PMR	0xc000801c
#define SL_ERROR_OS_SINIT_BAD_VERSION	0xc000801d
#define SL_ERROR_EVENTLOG_MAP		0xc000801e
#define SL_ERROR_TPM_NUMBER_ALGS	0xc000801f
#define SL_ERROR_TPM_UNKNOWN_DIGEST	0xc0008020
#define SL_ERROR_TPM_INVALID_EVENT	0xc0008021

/*
 * Secure Launch Defined Limits
 */
#define TXT_MAX_CPUS		512
#define TXT_BOOT_STACK_SIZE	24

/*
 * Secure Launch event log entry type. The TXT specification defines the
 * base event value as 0x400 for DRTM values.
 */
#define TXT_EVTYPE_BASE			0x400
#define TXT_EVTYPE_SLAUNCH		(TXT_EVTYPE_BASE + 0x102)
#define TXT_EVTYPE_SLAUNCH_START	(TXT_EVTYPE_BASE + 0x103)
#define TXT_EVTYPE_SLAUNCH_END		(TXT_EVTYPE_BASE + 0x104)

/*
 * Measured Launch PCRs
 */
#define SL_DEF_DLME_DETAIL_PCR17	17
#define SL_DEF_DLME_AUTHORITY_PCR18	18
#define SL_ALT_DLME_AUTHORITY_PCR19	19
#define SL_ALT_DLME_DETAIL_PCR20	20

/*
 * MLE scratch area offsets
 */
#define SL_SCRATCH_AP_EBX		0
#define SL_SCRATCH_AP_JMP_OFFSET	4
#define SL_SCRATCH_AP_PAUSE		8

#ifndef __ASSEMBLY__

/*
 * Secure Launch AP wakeup information fetched in SMP boot code.
 */
struct sl_ap_wake_info {
	uint32_t ap_wake_block;
	uint32_t ap_wake_block_size;
	uint32_t ap_jmp_offset;
};

/*
 * TXT heap extended data elements.
 */
struct txt_heap_ext_data_element {
	uint32_t type;
	uint32_t size;
	/* Data */
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_END			0

struct txt_heap_end_element {
	uint32_t type;
	uint32_t size;
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_TPM_EVENT_LOG_PTR		5

struct txt_heap_event_log_element {
	uint64_t event_log_phys_addr;
} __packed;

#define TXT_HEAP_EXTDATA_TYPE_EVENT_LOG_POINTER2_1	8

struct txt_heap_event_log_pointer2_1_element {
	uint64_t phys_addr;
	uint32_t allocated_event_container_size;
	uint32_t first_record_offset;
	uint32_t next_record_offset;
} __packed;

/*
 * Secure Launch defined MTRR saving structures
 */
struct txt_mtrr_pair {
	uint64_t mtrr_physbase;
	uint64_t mtrr_physmask;
} __packed;

struct txt_mtrr_state {
	uint64_t default_mem_type;
	uint64_t mtrr_vcnt;
	struct txt_mtrr_pair mtrr_pair[TXT_OS_MLE_MAX_VARIABLE_MTRRS];
} __packed;

/*
 * Secure Launch defined OS/MLE TXT Heap table
 */
struct txt_os_mle_data {
	uint32_t version;
	uint32_t boot_params_addr;
	uint64_t saved_misc_enable_msr;
	struct txt_mtrr_state saved_bsp_mtrrs;
	uint32_t ap_wake_block;
	uint32_t ap_wake_block_size;
	uint64_t evtlog_addr;
	uint32_t evtlog_size;
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
	/* Versions >= 5 with updates in version 6 */
	uint32_t sinit_flags;
	uint32_t mle_flags;
	/* Versions >= 4 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT specification defined OS/SINIT TXT Heap table
 */
struct txt_os_sinit_data {
	uint32_t version; /* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
	uint32_t flags;
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
	uint64_t efi_rsdt_ptr;
	/* Versions >= 6 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT specification defined SINIT/MLE TXT Heap table
 */
struct txt_sinit_mle_data {
	uint32_t version;             /* Current values are 6 through 9 */
	/* Versions <= 8 */
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

/*
 * TXT data reporting structure for memory types
 */
struct txt_sinit_memory_descriptor_record {
	uint64_t address;
	uint64_t length;
	uint8_t type;
	uint8_t reserved[7];
} __packed;

/*
 * TXT data structure used by a responsive local processor (RLP) to start
 * execution in response to a GETSEC[WAKEUP].
 */
struct smx_rlp_mle_join {
	uint32_t rlp_gdt_limit;
	uint32_t rlp_gdt_base;
	uint32_t rlp_seg_sel;     /* cs (ds, es, ss are seg_sel+8) */
	uint32_t rlp_entry_point; /* phys addr */
} __packed;

/*
 * Functions to extract data from the Intel TXT Heap Memory. The layout
 * of the heap is as follows:
 *  +----------------------------+
 *  | Size Bios Data table (uint64_t) |
 *  +----------------------------+
 *  | Bios Data table            |
 *  +----------------------------+
 *  | Size OS MLE table (uint64_t)    |
 *  +----------------------------+
 *  | OS MLE table               |
 *  +--------------------------- +
 *  | Size OS SINIT table (uint64_t)  |
 *  +----------------------------+
 *  | OS SINIT table             |
 *  +----------------------------+
 *  | Size SINIT MLE table (uint64_t) |
 *  +----------------------------+
 *  | SINIT MLE table            |
 *  +----------------------------+
 *
 *  NOTE: the table size fields include the 8 byte size field itself.
 */
static inline uint64_t txt_bios_data_size(void *heap)
{
	return *((uint64_t *)heap);
}

static inline void *txt_bios_data_start(void *heap)
{
	return heap + sizeof(uint64_t);
}

static inline uint64_t txt_os_mle_data_size(void *heap)
{
	return *((uint64_t *)(heap + txt_bios_data_size(heap)));
}

static inline void *txt_os_mle_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) + sizeof(uint64_t);
}

static inline uint64_t txt_os_sinit_data_size(void *heap)
{
	return *((uint64_t *)(heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap)));
}

static inline void *txt_os_sinit_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) + sizeof(uint64_t);
}

static inline uint64_t txt_sinit_mle_data_size(void *heap)
{
	return *((uint64_t *)(heap + txt_bios_data_size(heap) +
			txt_os_mle_data_size(heap) +
			txt_os_sinit_data_size(heap)));
}

static inline void *txt_sinit_mle_data_start(void *heap)
{
	return heap + txt_bios_data_size(heap) +
		txt_os_mle_data_size(heap) +
		txt_sinit_mle_data_size(heap) + sizeof(uint64_t);
}

/*
 * External functions avalailable in compressed kernel.
 */
extern uint32_t slaunch_get_cpu_type(void);

/*
 * External functions avalailable in mainline kernel.
 */
extern void slaunch_setup_txt(void);
extern uint32_t slaunch_get_flags(void);
extern struct sl_ap_wake_info *slaunch_get_ap_wake_info(void);
extern struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar);
extern void slaunch_txt_reset(void *txt, const char *msg, uint64_t error);
extern void slaunch_finalize(int do_sexit);

#endif /* !__ASSEMBLY__ */

#endif /* _XEN_SLAUNCH_H */
