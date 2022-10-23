/*
 * TXT configuration registers (offsets from TXT_{PUB, PRIV}_CONFIG_REGS_BASE)
 */

#define TXT_PUB_CONFIG_REGS_BASE	0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE	0xfed20000

#define NR_TXT_CONFIG_PAGES	((TXT_PUB_CONFIG_REGS_BASE - \
				  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

#define TXTCR_STS			0x0000
#define TXTCR_ESTS			0x0008
#define TXTCR_ERRORCODE			0x0030
#define TXTCR_CMD_RESET			0x0038
#define TXTCR_CMD_CLOSE_PRIVATE		0x0048
#define TXTCR_DIDVID			0x0110
#define TXTCR_VER_EMIF			0x0200
#define TXTCR_CMD_UNLOCK_MEM_CONFIG	0x0218
#define TXTCR_SINIT_BASE		0x0270
#define TXTCR_SINIT_SIZE		0x0278
#define TXTCR_MLE_JOIN			0x0290
#define TXTCR_HEAP_BASE			0x0300
#define TXTCR_HEAP_SIZE			0x0308
#define TXTCR_SCRATCHPAD		0x0378
#define TXTCR_CMD_OPEN_LOCALITY1	0x0380
#define TXTCR_CMD_CLOSE_LOCALITY1	0x0388
#define TXTCR_CMD_OPEN_LOCALITY2	0x0390
#define TXTCR_CMD_CLOSE_LOCALITY2	0x0398
#define TXTCR_CMD_SECRETS		0x08e0
#define TXTCR_CMD_NO_SECRETS		0x08e8
#define TXTCR_E2STS			0x08f0

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

#define TXT_OS_MLE_MAX_VARIABLE_MTRRS	32

#define SLAUNCH_BOOTLOADER_MAGIC	0x4c534254

#ifndef __ASSEMBLY__

extern unsigned long sl_status;

/*
 * Always use private space as some of registers are either read-only or not
 * present in public space.
 */
static inline volatile uint32_t read_txt_reg(int reg_no)
{
	volatile uint32_t *reg = _p(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
	return *reg;
}

static inline void write_txt_reg(int reg_no, uint32_t val)
{
	volatile uint32_t *reg = _p(TXT_PRIV_CONFIG_REGS_BASE + reg_no);
	*reg = val;
	/* This serves as TXT register barrier */
	(void)read_txt_reg(TXTCR_ESTS);
}

static inline void txt_reset(uint32_t error)
{
	write_txt_reg(TXTCR_ERRORCODE, error);
	write_txt_reg(TXTCR_CMD_NO_SECRETS, 1);
	write_txt_reg(TXTCR_CMD_UNLOCK_MEM_CONFIG, 1);
	write_txt_reg(TXTCR_CMD_RESET, 1);
	while (1);
}

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
	uint32_t version;	/* Currently 6 for TPM 1.2 and 7 for TPM 2.0 */
	uint32_t flags;		/* Reserved in version 6 */
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
	uint64_t efi_rsdt_ptr;	/* RSD*P* in versions >= 6 */
	/* Versions >= 6 */
	/* Ext Data Elements */
} __packed;

/*
 * TXT specification defined SINIT/MLE TXT Heap table
 */
struct txt_sinit_mle_data {
	uint32_t version;	/* Current values are 6 through 9 */
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

/*
 * Functions to extract data from the Intel TXT Heap Memory. The layout
 * of the heap is as follows:
 *  +---------------------------------+
 *  | Size Bios Data table (uint64_t) |
 *  +---------------------------------+
 *  | Bios Data table                 |
 *  +---------------------------------+
 *  | Size OS MLE table (uint64_t)    |
 *  +---------------------------------+
 *  | OS MLE table                    |
 *  +-------------------------------- +
 *  | Size OS SINIT table (uint64_t)  |
 *  +---------------------------------+
 *  | OS SINIT table                  |
 *  +---------------------------------+
 *  | Size SINIT MLE table (uint64_t) |
 *  +---------------------------------+
 *  | SINIT MLE table                 |
 *  +---------------------------------+
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

extern void protect_txt_mem_regions(void);
extern void txt_restore_mtrrs(bool e820_verbose);

#endif /* __ASSEMBLY__ */
