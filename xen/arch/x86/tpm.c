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

#ifdef __EARLY_TPM__
/*
 * This entry point is entered from xen/arch/x86/boot/head.S with MBI base at
 * 0x4(%esp).
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    jmp  tpm_extend_mbi           \n"
    );

#include "boot/defs.h"
#include "include/asm/intel_txt.h"
#ifdef __va
#error "__va defined in non-paged mode!"
#endif
#define __va(x)     (x)

#else   /* __EARLY_TPM__ */

#include <xen/types.h>
#include <asm/intel_txt.h>

#endif  /* __EARLY_TPM__ */

#define TPM_TIS_BASE            0xFED40000
#define TPM_LOC_REG(loc, reg)   (0x1000 * (loc) + (reg))

#define TPM_ACCESS_(x)          TPM_LOC_REG(x, 0x00)
#define ACCESS_REQUEST_USE       (1 << 1)
#define ACCESS_ACTIVE_LOCALITY   (1 << 5)
#define TPM_INTF_CAPABILITY_(x) TPM_LOC_REG(x, 0x14)
#define INTF_VERSION_MASK        0x70000000
#define TPM_STS_(x)             TPM_LOC_REG(x, 0x18)
#define TPM_FAMILY_MASK          0x0C000000
#define STS_DATA_AVAIL           (1 << 4)
#define STS_TPM_GO               (1 << 5)
#define STS_COMMAND_READY        (1 << 6)
#define STS_VALID                (1 << 7)
#define TPM_DATA_FIFO_(x)       TPM_LOC_REG(x, 0x24)

#define swap16(x)       __builtin_bswap16(x)
#define swap32(x)       __builtin_bswap32(x)
#define memcpy(d, s, n) __builtin_memcpy(d, s, n)

static inline volatile uint32_t tis_read32(unsigned reg)
{
    return *(volatile uint32_t *)__va(TPM_TIS_BASE + reg);
}

static inline volatile uint8_t tis_read8(unsigned reg)
{
    return *(volatile uint8_t *)__va(TPM_TIS_BASE + reg);
}

static inline void tis_write8(unsigned reg, uint8_t val)
{
    *(volatile uint8_t *)__va(TPM_TIS_BASE + reg) = val;
}

/* TODO: check if locality was actually activated. */
static inline void request_locality(unsigned loc)
{
    tis_write8(TPM_ACCESS_(loc), ACCESS_REQUEST_USE);
}

static inline void relinquish_locality(unsigned loc)
{
    tis_write8(TPM_ACCESS_(loc), ACCESS_ACTIVE_LOCALITY);
}

static void send_cmd(unsigned loc, uint8_t *buf, unsigned i_size,
                     unsigned *o_size)
{
    unsigned i;

    tis_write8(TPM_STS_(loc), STS_COMMAND_READY);

    for ( i = 0; i < i_size; i++ )
        tis_write8(TPM_DATA_FIFO_(loc), buf[i]);

    tis_write8(TPM_STS_(loc), STS_TPM_GO);

    while ( (tis_read8(TPM_STS_(loc)) & STS_DATA_AVAIL) == 0 );

    for ( i = 0; i < *o_size && tis_read8(TPM_STS_(loc)) & STS_DATA_AVAIL; i++ )
        buf[i] = tis_read8(TPM_DATA_FIFO_(loc));

    if ( i < *o_size )
        *o_size = i;

    tis_write8(TPM_STS_(loc), STS_COMMAND_READY);
}

static inline bool is_tpm12(void)
{
    /*
     * If either INTF_CAPABILITY_x.interfaceVersion is 0 (TIS <= 1.21) or
     * STS_x.tpmFamily is 0 we're dealing with TPM1.2.
     */
     return ((tis_read32(TPM_INTF_CAPABILITY_(0)) & INTF_VERSION_MASK) == 0 ||
             (tis_read32(TPM_STS_(0)) & TPM_FAMILY_MASK) == 0);
}

/****************************** TPM1.2 specific *******************************/
#define TPM_ORD_SHA1Start           0x000000A0
#define TPM_ORD_SHA1Update          0x000000A1
#define TPM_ORD_SHA1CompleteExtend  0x000000A3

#define TPM_TAG_RQU_COMMAND         0x00C1
#define TPM_TAG_RSP_COMMAND         0x00C4

/* All fields of following structs are big endian. */
struct tpm_cmd_hdr {
    uint16_t    tag;
    uint32_t    paramSize;
    uint32_t    ordinal;
} __packed;

struct tpm_rsp_hdr {
    uint16_t    tag;
    uint32_t    paramSize;
    uint32_t    returnCode;
} __packed;

struct sha1_start_cmd {
    struct tpm_cmd_hdr h;
} __packed;

struct sha1_start_rsp {
    struct tpm_rsp_hdr h;
    uint32_t maxNumBytes;
} __packed;

struct sha1_update_cmd {
    struct tpm_cmd_hdr h;
    uint32_t numBytes;          /* Must be a multiple of 64 */
    uint8_t hashData[];
} __packed;

struct sha1_update_rsp {
    struct tpm_rsp_hdr h;
} __packed;

struct sha1_complete_extend_cmd {
    struct tpm_cmd_hdr h;
    uint32_t pcrNum;
    uint32_t hashDataSize;      /* 0-64, inclusive */
    uint8_t hashData[];
} __packed;

struct sha1_complete_extend_rsp {
    struct tpm_rsp_hdr h;
    uint8_t hashValue[SHA1_DIGEST_SIZE];
    uint8_t outDigest[SHA1_DIGEST_SIZE];
} __packed;

/*
 * TPM1.2 is required to support commands of up to 1101 bytes, vendors rarely
 * go above that. Limit maximum size of block of data to be hashed to 1024.
 */
#define MAX_HASH_BLOCK      1024
#define CMD_RSP_BUF_SIZE    (sizeof(struct sha1_update_cmd) + MAX_HASH_BLOCK)

union cmd_rsp {
    struct sha1_start_cmd start_c;
    struct sha1_start_rsp start_r;
    struct sha1_update_cmd update_c;
    struct sha1_update_rsp update_r;
    struct sha1_complete_extend_cmd finish_c;
    struct sha1_complete_extend_rsp finish_r;
    uint8_t buf[CMD_RSP_BUF_SIZE];
};

/*
 * FIXME: when TPM does the hashing, we're heavily limited by bus bandwidth and
 * number of sync cycles sent by TPM. In case of typical LPC running at 33MHz
 * maximal theoretical bandwidth is 2.56MB/s, assuming there are no sync cycles
 * above allowed minimum of one cycle. For 50MB kernel + initrd this adds at
 * least 20 seconds to boot time. However, in testing TPM parses data slower,
 * and just sending the data takes ~500s... In order to fix this, a hashing
 * function must be implemented on host side, and extend command must be used.
 */
void tpm_hash_extend(unsigned loc, uint8_t *buf, unsigned size, unsigned pcr)
{
    union cmd_rsp cmd_rsp;
    unsigned max_bytes = MAX_HASH_BLOCK;
    unsigned o_size = sizeof(cmd_rsp);

    request_locality(loc);

    cmd_rsp.start_c = (struct sha1_start_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct sha1_start_cmd)),
        .h.ordinal = swap32(TPM_ORD_SHA1Start),
    };

    send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_start_cmd), &o_size);

    // assert (o_size >= sizeof(struct sha1_start_rsp));

    if ( max_bytes > swap32(cmd_rsp.start_r.maxNumBytes) )
        max_bytes = swap32(cmd_rsp.start_r.maxNumBytes);

    while ( size > 64 ) {
        if ( size < max_bytes )
            max_bytes = size & ~(64 - 1);

        o_size = sizeof(cmd_rsp);

        cmd_rsp.update_c = (struct sha1_update_cmd){
            .h.tag = swap16(TPM_TAG_RQU_COMMAND),
            .h.paramSize = swap32(sizeof(struct sha1_update_cmd) + max_bytes),
            .h.ordinal = swap32(TPM_ORD_SHA1Update),
            .numBytes = swap32(max_bytes),
        };
        memcpy(cmd_rsp.update_c.hashData, buf, max_bytes);

        send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_update_cmd) + max_bytes,
                 &o_size);

        // assert (o_size >= sizeof(struct sha1_update_rsp));

        size -= max_bytes;
        buf += max_bytes;
    }

    o_size = sizeof(cmd_rsp);

    cmd_rsp.finish_c = (struct sha1_complete_extend_cmd) {
        .h.tag = swap16(TPM_TAG_RQU_COMMAND),
        .h.paramSize = swap32(sizeof(struct sha1_complete_extend_cmd) + size),
        .h.ordinal = swap32(TPM_ORD_SHA1CompleteExtend),
        .pcrNum = swap32(pcr),
        .hashDataSize = swap32(size),
    };
    memcpy(cmd_rsp.finish_c.hashData, buf, size);

    send_cmd(loc, cmd_rsp.buf, sizeof(struct sha1_complete_extend_cmd) + size,
             &o_size);

    // assert (o_size >= sizeof(struct sha1_complete_extend_rsp));

    relinquish_locality(loc);

    /* TODO: figure out what to do with cmd_rsp.finish_r.hashValue. */
}

/************************** end of TPM1.2 specific ****************************/

#ifdef __EARLY_TPM__
void __stdcall tpm_extend_mbi(uint32_t *mbi)
{
    /*
     * TODO: after TPM2 is implemented, we should halt rather than continue
     * without measurements.
     */
    if ( is_tpm12() ) {
        /* MBI starts with uint32_t total_size. */
        tpm_hash_extend(DRTM_LOC, (uint8_t *)mbi, *mbi, DRTM_DATA_PCR);
    }
}
#endif
