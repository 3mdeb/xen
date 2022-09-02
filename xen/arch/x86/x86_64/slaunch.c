// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch late validation/setup and finalization support.
 *
 * Copyright (c) 2022, Oracle and/or its affiliates.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <xen/compiler.h>
#include <xen/init.h>
#include <asm/page.h>
#include <asm/slaunch.h>

static uint32_t sl_flags;
static struct sl_ap_wake_info ap_wake_info;
static uint64_t evtlog_addr;
static uint32_t evtlog_size;
static uint64_t vtd_pmr_lo_size;

/* This should be plenty of room */
static uint8_t txt_dmar[PAGE_SIZE] __aligned(16);

uint32_t slaunch_get_flags(void)
{
	return sl_flags;
}
EXPORT_SYMBOL(slaunch_get_flags);

struct sl_ap_wake_info *slaunch_get_ap_wake_info(void)
{
	return &ap_wake_info;
}

struct acpi_table_header *slaunch_get_dmar_table(struct acpi_table_header *dmar)
{
	/* The DMAR is only stashed and provided via TXT on Intel systems */
	if (memcmp(txt_dmar, "DMAR", 4))
		return dmar;

	return (struct acpi_table_header *)(&txt_dmar[0]);
}

void slaunch_txt_reset(void *txt,
				  const char *msg, uint64_t error)
{
	uint64_t one = 1, val;

	pr_err("%s", msg);

	/*
	 * This performs a TXT reset with a sticky error code. The reads of
	 * TXT_CR_E2STS act as barriers.
	 */
	memcpy_toio(txt + TXT_CR_ERRORCODE, &error, sizeof(error));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_NO_SECRETS, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_RESET, &one, sizeof(one));

	for ( ; ; )
		asm volatile ("hlt");

	unreachable();
}

/*
 * The TXT heap is too big to map all at once with early_ioremap
 * so it is done a table at a time.
 */
static void __init *txt_early_get_heap_table(void *txt, uint32_t type,
					     uint32_t bytes)
{
	uint64_t base, size, offset = 0;
	void *heap;
	int i;

	if (type > TXT_SINIT_TABLE_MAX)
		slaunch_txt_reset(txt,
			"Error invalid table type for early heap walk\n",
			SL_ERROR_HEAP_WALK);

	memcpy_fromio(&base, txt + TXT_CR_HEAP_BASE, sizeof(base));
	memcpy_fromio(&size, txt + TXT_CR_HEAP_SIZE, sizeof(size));

	/* Iterate over heap tables looking for table of "type" */
	for (i = 0; i < type; i++) {
		base += offset;
		heap = early_memremap(base, sizeof(uint64_t));
		if (!heap)
			slaunch_txt_reset(txt,
				"Error early_memremap of heap for heap walk\n",
				SL_ERROR_HEAP_MAP);

		offset = *((uint64_t *)heap);

		/*
		 * After the first iteration, any offset of zero is invalid and
		 * implies the TXT heap is corrupted.
		 */
		if (!offset)
			slaunch_txt_reset(txt,
				"Error invalid 0 offset in heap walk\n",
				SL_ERROR_HEAP_ZERO_OFFSET);

		early_memunmap(heap, sizeof(uint64_t));
	}

	/* Skip the size field at the head of each table */
	base += sizeof(uint64_t);
	heap = early_memremap(base, bytes);
	if (!heap)
		slaunch_txt_reset(txt,
				  "Error early_memremap of heap section\n",
				  SL_ERROR_HEAP_MAP);

	return heap;
}

static void __init txt_early_put_heap_table(void *addr, unsigned long size)
{
	early_memunmap(addr, size);
}

/*
 * TXT uses a special set of VTd registers to protect all of memory from DMA
 * until the IOMMU can be programmed to protect memory. There is the low
 * memory PMR that can protect all memory up to 4G. The high memory PRM can
 * be setup to protect all memory beyond 4Gb. Validate that these values cover
 * what is expected.
 */
static void __init slaunch_verify_pmrs(void *txt)
{
	struct txt_os_sinit_data *os_sinit_data;
	uint32_t field_offset, err = 0;
	const char *errmsg = "";
	unsigned long last_pfn;

	field_offset = offsetof(struct txt_os_sinit_data, lcp_po_base);
	os_sinit_data = txt_early_get_heap_table(txt, TXT_OS_SINIT_DATA_TABLE,
						 field_offset);

	/* Save a copy */
	vtd_pmr_lo_size = os_sinit_data->vtd_pmr_lo_size;

	last_pfn = e820__end_of_ram_pfn();

	/*
	 * First make sure the hi PMR covers all memory above 4G. In the
	 * unlikely case where there is < 4G on the system, the hi PMR will
	 * not be set.
	 */
	if (os_sinit_data->vtd_pmr_hi_base != 0x0ULL) {
		if (os_sinit_data->vtd_pmr_hi_base != 0x100000000ULL) {
			err = SL_ERROR_HI_PMR_BASE;
			errmsg =  "Error hi PMR base\n";
			goto out;
		}

		if (PFN_PHYS(last_pfn) > os_sinit_data->vtd_pmr_hi_base +
		    os_sinit_data->vtd_pmr_hi_size) {
			err = SL_ERROR_HI_PMR_SIZE;
			errmsg = "Error hi PMR size\n";
			goto out;
		}
	}

	/*
	 * Lo PMR base should always be 0. This was already checked in
	 * early stub.
	 */

	/*
	 * Check that if the kernel was loaded below 4G, that it is protected
	 * by the lo PMR. Note this is the decompressed kernel. The ACM would
	 * have ensured the compressed kernel (the MLE image) was protected.
	 */
	if ((__pa_symbol(_end) < 0x100000000ULL) &&
	    (__pa_symbol(_end) > os_sinit_data->vtd_pmr_lo_size)) {
		err = SL_ERROR_LO_PMR_MLE;
		errmsg = "Error lo PMR does not cover MLE kernel\n";
	}

	/*
	 * Other regions of interest like boot param, AP wake block, cmdline
	 * already checked for PMR coverage in the early stub code.
	 */

out:
	txt_early_put_heap_table(os_sinit_data, field_offset);

	if (err)
		slaunch_txt_reset(txt, errmsg, err);
}

static void __init slaunch_txt_reserve_range(uint64_t base, uint64_t size)
{
	int type;

	type = e820__get_entry_type(base, base + size - 1);
	if (type == E820_TYPE_RAM) {
		pr_info("memblock reserve base: %llx size: %llx\n", base, size);
		memblock_reserve(base, size);
	}
}

/*
 * For Intel, certain regions of memory must be marked as reserved by putting
 * them on the memblock reserved list if they are not already e820 reserved.
 * This includes:
 *  - The TXT HEAP
 *  - The ACM area
 *  - The TXT private register bank
 *  - The MDR list sent to the MLE by the ACM (see TXT specification)
 *  (Normally the above are properly reserved by firmware but if it was not
 *  done, reserve them now)
 *  - The AP wake block
 *  - TPM log external to the TXT heap
 *
 * Also if the low PMR doesn't cover all memory < 4G, any RAM regions above
 * the low PMR must be reservered too.
 */
static void __init slaunch_txt_reserve(void *txt)
{
	struct txt_sinit_memory_descriptor_record *mdr;
	struct txt_sinit_mle_data *sinit_mle_data;
	uint64_t base, size, heap_base, heap_size;
	uint32_t mdrnum, mdroffset, mdrslen;
	uint32_t field_offset, i;
	void *mdrs;

	base = TXT_PRIV_CONFIG_REGS_BASE;
	size = TXT_PUB_CONFIG_REGS_BASE - TXT_PRIV_CONFIG_REGS_BASE;
	slaunch_txt_reserve_range(base, size);

	memcpy_fromio(&heap_base, txt + TXT_CR_HEAP_BASE, sizeof(heap_base));
	memcpy_fromio(&heap_size, txt + TXT_CR_HEAP_SIZE, sizeof(heap_size));
	slaunch_txt_reserve_range(heap_base, heap_size);

	memcpy_fromio(&base, txt + TXT_CR_SINIT_BASE, sizeof(base));
	memcpy_fromio(&size, txt + TXT_CR_SINIT_SIZE, sizeof(size));
	slaunch_txt_reserve_range(base, size);

	field_offset = offsetof(struct txt_sinit_mle_data,
				sinit_vtd_dmar_table_size);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
						  field_offset);

	mdrnum = sinit_mle_data->num_of_sinit_mdrs;
	mdroffset = sinit_mle_data->sinit_mdrs_table_offset;

	txt_early_put_heap_table(sinit_mle_data, field_offset);

	if (!mdrnum)
		goto nomdr;

	mdrslen = mdrnum * sizeof(struct txt_sinit_memory_descriptor_record);

	mdrs = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					mdroffset + mdrslen - 8);

	mdr = mdrs + mdroffset - 8;

	for (i = 0; i < mdrnum; i++, mdr++) {
		/* Spec says some entries can have length 0, ignore them */
		if (mdr->type > 0 && mdr->length > 0)
			slaunch_txt_reserve_range(mdr->address, mdr->length);
	}

	txt_early_put_heap_table(mdrs, mdroffset + mdrslen - 8);

nomdr:
	slaunch_txt_reserve_range(ap_wake_info.ap_wake_block,
				  ap_wake_info.ap_wake_block_size);

	/*
	 * Earlier checks ensured that the event log was properly situated
	 * either inside the TXT heap or outside. This is a check to see if the
	 * event log needs to be reserved. If it is in the TXT heap, it is
	 * already reserved.
	 */
	if (evtlog_addr < heap_base || evtlog_addr > (heap_base + heap_size))
		slaunch_txt_reserve_range(evtlog_addr, evtlog_size);

	for (i = 0; i < e820_table->nr_entries; i++) {
		base = e820_table->entries[i].addr;
		size = e820_table->entries[i].size;
		if ((base >= vtd_pmr_lo_size) && (base < 0x100000000ULL))
			slaunch_txt_reserve_range(base, size);
		else if ((base < vtd_pmr_lo_size) &&
			 (base + size > vtd_pmr_lo_size))
			slaunch_txt_reserve_range(vtd_pmr_lo_size,
						  base + size - vtd_pmr_lo_size);
	}
}

/*
 * TXT stashes a safe copy of the DMAR ACPI table to prevent tampering.
 * It is stored in the TXT heap. Fetch it from there and make it available
 * to the IOMMU driver.
 */
static void __init slaunch_copy_dmar_table(void *txt)
{
	struct txt_sinit_mle_data *sinit_mle_data;
	uint32_t field_offset, dmar_size, dmar_offset;
	void *dmar;

	memset(&txt_dmar, 0, PAGE_SIZE);

	field_offset = offsetof(struct txt_sinit_mle_data,
				processor_scrtm_status);
	sinit_mle_data = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
						  field_offset);

	dmar_size = sinit_mle_data->sinit_vtd_dmar_table_size;
	dmar_offset = sinit_mle_data->sinit_vtd_dmar_table_offset;

	txt_early_put_heap_table(sinit_mle_data, field_offset);

	if (!dmar_size || !dmar_offset)
		slaunch_txt_reset(txt,
				  "Error invalid DMAR table values\n",
				  SL_ERROR_HEAP_INVALID_DMAR);

	if (unlikely(dmar_size > PAGE_SIZE))
		slaunch_txt_reset(txt,
				  "Error DMAR too big to store\n",
				  SL_ERROR_HEAP_DMAR_SIZE);


	dmar = txt_early_get_heap_table(txt, TXT_SINIT_MLE_DATA_TABLE,
					dmar_offset + dmar_size - 8);
	if (!dmar)
		slaunch_txt_reset(txt,
				  "Error early_ioremap of DMAR\n",
				  SL_ERROR_HEAP_DMAR_MAP);

	memcpy(&txt_dmar[0], dmar + dmar_offset - 8, dmar_size);

	txt_early_put_heap_table(dmar, dmar_offset + dmar_size - 8);
}

/*
 * The location of the safe AP wake code block is stored in the TXT heap.
 * Fetch it here in the early init code for later use in SMP startup.
 *
 * Also get the TPM event log values that may have to be put on the
 * memblock reserve list later.
 */
static void __init slaunch_fetch_os_mle_fields(void *txt)
{
	struct txt_os_mle_data *os_mle_data;
	uint8_t *jmp_offset;

	os_mle_data = txt_early_get_heap_table(txt, TXT_OS_MLE_DATA_TABLE,
					       sizeof(*os_mle_data));

	ap_wake_info.ap_wake_block = os_mle_data->ap_wake_block;
	ap_wake_info.ap_wake_block_size = os_mle_data->ap_wake_block_size;

	jmp_offset = os_mle_data->mle_scratch + SL_SCRATCH_AP_JMP_OFFSET;
	ap_wake_info.ap_jmp_offset = *((uint32_t *)jmp_offset);

	evtlog_addr = os_mle_data->evtlog_addr;
	evtlog_size = os_mle_data->evtlog_size;

	txt_early_put_heap_table(os_mle_data, sizeof(*os_mle_data));
}

/*
 * Intel TXT specific late stub setup and validation.
 */
void __init slaunch_setup_txt(void)
{
	uint64_t one = TXT_REGVALUE_ONE, val;
	void *txt;

	if (!boot_cpu_has(X86_FEATURE_SMX))
		return;

	/*
	 * If booted through secure launch entry point, the loadflags
	 * option will be set.
	 */
	if (!(boot_params.hdr.loadflags & SLAUNCH_FLAG))
		return;

	/*
	 * See if SENTER was done by reading the status register in the
	 * public space. If the public register space cannot be read, TXT may
	 * be disabled.
	 */
	txt = early_ioremap(TXT_PUB_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt)
		return;

	memcpy_fromio(&val, txt + TXT_CR_STS, sizeof(val));
	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	/* SENTER should have been done */
	if (!(val & TXT_SENTER_DONE_STS))
		panic("Error TXT.STS SENTER_DONE not set\n");

	/* SEXIT should have been cleared */
	if (val & TXT_SEXIT_DONE_STS)
		panic("Error TXT.STS SEXIT_DONE set\n");

	/* Now we want to use the private register space */
	txt = early_ioremap(TXT_PRIV_CONFIG_REGS_BASE,
			    TXT_NR_CONFIG_PAGES * PAGE_SIZE);
	if (!txt) {
		/* This is really bad, no where to go from here */
		panic("Error early_ioremap of TXT priv registers\n");
	}

	/*
	 * Try to read the Intel VID from the TXT private registers to see if
	 * TXT measured launch happened properly and the private space is
	 * available.
	 */
	memcpy_fromio(&val, txt + TXT_CR_DIDVID, sizeof(val));
	if ((val & 0xffff) != 0x8086) {
		/*
		 * Can't do a proper TXT reset since it appears something is
		 * wrong even though SENTER happened and it should be in SMX
		 * mode.
		 */
		panic("Invalid TXT vendor ID, not in SMX mode\n");
	}

	/* Set flags so subsequent code knows the status of the launch */
	sl_flags |= (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT);

	/*
	 * Reading the proper DIDVID from the private register space means we
	 * are in SMX mode and private registers are open for read/write.
	 */

	/* On Intel, have to handle TPM localities via TXT */
	memcpy_toio(txt + TXT_CR_CMD_SECRETS, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));
	memcpy_toio(txt + TXT_CR_CMD_OPEN_LOCALITY1, &one, sizeof(one));
	memcpy_fromio(&val, txt + TXT_CR_E2STS, sizeof(val));

	slaunch_fetch_os_mle_fields(txt);

	slaunch_verify_pmrs(txt);

	slaunch_txt_reserve(txt);

	slaunch_copy_dmar_table(txt);

	early_iounmap(txt, TXT_NR_CONFIG_PAGES * PAGE_SIZE);

	pr_info("Intel TXT setup complete\n");
}

static inline void smx_getsec_sexit(void)
{
	asm volatile (".byte 0x0f,0x37\n"
		      : : "a" (SMX_X86_GETSEC_SEXIT));
}

void slaunch_finalize(int do_sexit)
{
	uint64_t one = TXT_REGVALUE_ONE, val;
	void *config;

	if ((slaunch_get_flags() & (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT)) !=
	    (SL_FLAG_ACTIVE | SL_FLAG_ARCH_TXT))
		return;

	config = ioremap(TXT_PRIV_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("Error SEXIT failed to ioremap TXT private reqs\n");
		return;
	}

	/* Clear secrets bit for SEXIT */
	memcpy_toio(config + TXT_CR_CMD_NO_SECRETS, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/* Unlock memory configurations */
	memcpy_toio(config + TXT_CR_CMD_UNLOCK_MEM_CONFIG, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/* Close the TXT private register space */
	memcpy_toio(config + TXT_CR_CMD_CLOSE_PRIVATE, &one, sizeof(one));
	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	/*
	 * Calls to iounmap are not being done because of the state of the
	 * system this late in the kexec process. Local IRQs are disabled and
	 * iounmap causes a TLB flush which in turn causes a warning. Leaving
	 * thse mappings is not an issue since the next kernel is going to
	 * completely re-setup memory management.
	 */

	/* Map public registers and do a final read fence */
	config = ioremap(TXT_PUB_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
			 PAGE_SIZE);
	if (!config) {
		pr_emerg("Error SEXIT failed to ioremap TXT public reqs\n");
		return;
	}

	memcpy_fromio(&val, config + TXT_CR_E2STS, sizeof(val));

	pr_emerg("TXT clear secrets bit and unlock memory complete.\n");

	if (!do_sexit)
		return;

	if (smp_processor_id() != 0)
		panic("Error TXT SEXIT must be called on CPU 0\n");

	/* Disable SMX mode */
	cr4_set_bits(X86_CR4_SMXE);

	/* Do the SEXIT SMX operation */
	smx_getsec_sexit();

	pr_info("TXT SEXIT complete.\n");
}
