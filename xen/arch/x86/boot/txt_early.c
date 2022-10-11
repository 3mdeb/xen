/*
 * Copyright (c) 2022 3mdeb Sp. z o.o. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with Xen base at
 * 0x4(%esp). A pointer to MBI is returned in %eax.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  txt_early_tests          \n"
    );

#include "defs.h"
#include "../include/asm/intel_txt.h"

static void verify_os_mle_struct(struct txt_os_mle_data *os_mle,
                                 struct txt_os_sinit_data *os_sinit,
                                 uint32_t mle_base)
{
    /* Verify the value of the low PMR base. It should always be 0. */
    if (os_sinit->vtd_pmr_lo_base != 0)
        txt_reset(SL_ERROR_LO_PMR_BASE);

    /* Check for size overflow (should be caught by SINIT during page walk). */
    if (mle_base + os_sinit->mle_size < mle_base)
        txt_reset(SL_ERROR_INTEGER_OVERFLOW);

    /* TODO: AP wake block size and PMR low size, if needed */
}

uint32_t __stdcall txt_early_tests(uint32_t mle_base)
{
    void *txt_heap;
    struct txt_os_mle_data *os_mle;
    struct txt_os_sinit_data *os_sinit;

    /* Clear the TXT error registers for a clean start of day */
    write_txt_reg(TXTCR_ERRORCODE, 0);

    txt_heap = _p(read_txt_reg(TXTCR_HEAP_BASE));

    if (txt_os_mle_data_size(txt_heap) < sizeof(*os_mle) ||
        txt_os_sinit_data_size(txt_heap) < sizeof(*os_sinit))
        txt_reset(SL_ERROR_GENERIC);

    os_mle = txt_os_mle_data_start(txt_heap);
    os_sinit = txt_os_sinit_data_start(txt_heap);

    verify_os_mle_struct(os_mle, os_sinit, mle_base);

    /* TODO: store mle_base in OS-MLE scratch for APs? */

    return os_mle->boot_params_addr;
}
