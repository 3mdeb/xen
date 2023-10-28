/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (c) 2022-2025 3mdeb Sp. z o.o. All rights reserved.
 */

#ifndef X86_SLAUNCH_H
#define X86_SLAUNCH_H

#include <xen/slr-table.h>
#include <xen/types.h>

#define DRTM_LOC                   2
#define DRTM_CODE_PCR              17
#define DRTM_DATA_PCR              18

/*
 * Secure Launch event log entry types. The TXT specification defines the base
 * event value as 0x400 for DRTM values, use it regardless of the DRTM for
 * consistency.
 */
#define DLE_EVTYPE_BASE            0x400
#define DLE_EVTYPE_SLAUNCH         (DLE_EVTYPE_BASE + 0x102)
#define DLE_EVTYPE_SLAUNCH_START   (DLE_EVTYPE_BASE + 0x103)
#define DLE_EVTYPE_SLAUNCH_END     (DLE_EVTYPE_BASE + 0x104)

struct boot_info;

/* Indicates an active Secure Launch boot. */
extern bool slaunch_active;

/*
 * Holds physical address of SLRT.  Use slaunch_get_slrt() to access SLRT
 * instead of mapping where this points to.
 */
extern uint32_t slaunch_slrt;

/*
 * evt_log is assigned a physical address and the caller must map it to
 * virtual, if needed.
 */
static inline void find_evt_log(const struct slr_table *slrt, void **evt_log,
                                uint32_t *evt_log_size)
{
    const struct slr_entry_log_info *log_info;

    log_info = (const struct slr_entry_log_info *)
        slr_next_entry_by_tag(slrt, NULL, SLR_ENTRY_LOG_INFO);
    if ( log_info != NULL )
    {
        *evt_log = _p(log_info->addr);
        *evt_log_size = log_info->size;
    }
    else
    {
        *evt_log = NULL;
        *evt_log_size = 0;
    }
}

/*
 * Retrieves pointer to SLRT.  Checks table's validity and maps it as necessary.
 */
struct slr_table *slaunch_get_slrt(void);

/*
 * Prepares for accesses to essential data structures setup by boot environment.
 */
void slaunch_map_mem_regions(void);

/* Marks regions of memory as used to avoid their corruption. */
void slaunch_reserve_mem_regions(void);

/* Measures essential parts of SLR table before making use of them. */
void slaunch_measure_slrt(void);

/*
 * Takes measurements of DRTM policy entries except for MBI and SLRT which
 * should have been measured by the time this is called. Also performs sanity
 * checks of the policy and panics on failure. In particular, the function
 * verifies that DRTM is consistent with modules obtained from MultibootInfo
 * (MBI) and written to struct boot_info in setup.c.
 */
void slaunch_process_drtm_policy(const struct boot_info *bi);

/*
 * This helper function is used to map memory using L2 page tables by aligning
 * mapped regions to 2MB. This way page allocator (which at this point isn't
 * yet initialized) isn't needed for creating new L1 mappings. The function
 * also checks and skips memory already mapped by the prebuilt tables.
 *
 * There is no unmap_l2() because the function is meant to be used by the code
 * that accesses DRTM-related memory soon after which Xen rebuilds memory maps,
 * effectively dropping all existing mappings.
 */
int slaunch_map_l2(unsigned long paddr, unsigned long size);

#endif /* X86_SLAUNCH_H */
