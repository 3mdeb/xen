// SPDX-License-Identifier: GPL-2.0
/*
 * Secure Launch late validation/setup, securityfs exposure and
 * finalization support.
 *
 * Copyright (c) 2022 Apertus Solutions, LLC
 * Copyright (c) 2021 Assured Information Security, Inc.
 * Copyright (c) 2022, Oracle and/or its affiliates.
 *
 * Author(s):
 *     Daniel P. Smith <dpsmith@apertussolutions.com>
 *     Garnet T. Grimm <grimmg@ainfosec.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/*
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/memblock.h>
#include <asm/segment.h>
#include <asm/sections.h>
#include <crypto/sha2.h>
#include <linux/slaunch.h>
*/

#include <asm/types.h>
#include <asm/tboot.h>
#include <xen/mm.h>
#include <xen/lib.h>

#define TXT_PUB_CONFIG_REGS_BASE       0xfed30000
#define TXT_PRIV_CONFIG_REGS_BASE      0xfed20000

/* # pages for each config regs space - used by fixmap */
#define NR_TXT_CONFIG_PAGES     ((TXT_PUB_CONFIG_REGS_BASE -                \
                                  TXT_PRIV_CONFIG_REGS_BASE) >> PAGE_SHIFT)

#define loff_t long int
#define memcpy_fromio memcpy
#define __init
#define __iomem


#ifndef size_t
#define size_t long unsigned int
#endif
signed long simple_read_from_buffer(void *to, size_t count, loff_t *ppos,
				const void *from, size_t available)
{
	loff_t pos = *ppos;
	//size_t ret;

	if (pos < 0)
		return -EINVAL;
	if (pos >= available || !count)
		return 0;
	if (count > available - pos)
		count = available - pos;
	/*
	ret = memcpy(to, from + pos, count);
	if (ret == count)
		return -EFAULT;
	count -= ret;
	*/
	memcpy(to, from + pos, count);
	*ppos = pos + count;
	return count;
}

#define DECLARE_TXT_PUB_READ_U(size, fmt, msg_size)			\
static ssize_t txt_pub_read_u##size(unsigned int offset,		\
		loff_t *read_offset,					\
		size_t read_len,					\
		char __user *buf)					\
{									\
	void __iomem *txt;						\
	char msg_buffer[msg_size];					\
	u##size reg_value = 0;						\
	txt = ioremap(TXT_PUB_CONFIG_REGS_BASE,				\
			NR_TXT_CONFIG_PAGES * PAGE_SIZE);		\
	if (!txt)						\
		return -EFAULT;					\
	memcpy_fromio(&reg_value, txt + offset, sizeof(u##size));	\
	iounmap(txt);							\
	snprintf(msg_buffer, msg_size, fmt, reg_value);			\
	return simple_read_from_buffer(buf, read_len, read_offset,	\
			&msg_buffer, msg_size);				\
}

DECLARE_TXT_PUB_READ_U(8, "%#04x\n", 6);
DECLARE_TXT_PUB_READ_U(32, "%#010x\n", 12);
DECLARE_TXT_PUB_READ_U(64, "%#018lx\n", 20);

#define DECLARE_TXT_FOPS(reg_name, reg_offset, reg_size)		\
static ssize_t txt_##reg_name##_read(struct file *flip,			\
		char __user *buf, size_t read_len, loff_t *read_offset)	\
{									\
	return txt_pub_read_u##reg_size(reg_offset, read_offset,	\
			read_len, buf);					\
}									\
static const struct file_operations reg_name##_ops = {			\
	.read = txt_##reg_name##_read,					\
}

DECLARE_TXT_FOPS(sts, TXT_CR_STS, 64);
DECLARE_TXT_FOPS(ests, TXT_CR_ESTS, 8);
DECLARE_TXT_FOPS(errorcode, TXT_CR_ERRORCODE, 32);
DECLARE_TXT_FOPS(didvid, TXT_CR_DIDVID, 64);
DECLARE_TXT_FOPS(e2sts, TXT_CR_E2STS, 64);
DECLARE_TXT_FOPS(ver_emif, TXT_CR_VER_EMIF, 32);
DECLARE_TXT_FOPS(scratchpad, TXT_CR_SCRATCHPAD, 64);

/*
 * Securityfs exposure
 */
struct memfile {
	char *name;
	void *addr;
	size_t size;
};

static struct memfile sl_evtlog = {"eventlog", 0, 0};
static void *txt_heap;
static struct txt_heap_event_log_pointer2_1_element __iomem *evtlog20;
static DEFINE_MUTEX(sl_evt_log_mutex);

static ssize_t sl_evtlog_read(struct file *file, char __user *buf,
			      size_t count, loff_t *pos)
{
	ssize_t size;

	if (!sl_evtlog.addr)
		return 0;

	mutex_lock(&sl_evt_log_mutex);
	size = simple_read_from_buffer(buf, count, pos, sl_evtlog.addr,
				       sl_evtlog.size);
	mutex_unlock(&sl_evt_log_mutex);

	return size;
}

static ssize_t sl_evtlog_write(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	ssize_t result;
	char *data;

	if (!sl_evtlog.addr)
		return 0;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	data = memdup_user(buf, datalen);
	if (IS_ERR(data)) {
		result = PTR_ERR(data);
		goto out;
	}

	mutex_lock(&sl_evt_log_mutex);
	if (evtlog20)
		result = tpm20_log_event(evtlog20, sl_evtlog.addr,
					 sl_evtlog.size, datalen, data);
	else
		result = tpm12_log_event(sl_evtlog.addr, sl_evtlog.size,
					 datalen, data);
	mutex_unlock(&sl_evt_log_mutex);

	kfree(data);
out:
	return result;
}

static const struct file_operations sl_evtlog_ops = {
	.read = sl_evtlog_read,
	.write = sl_evtlog_write,
	.llseek	= default_llseek,
};

struct sfs_file {
	const char *name;
	const struct file_operations *fops;
};

#define SL_TXT_ENTRY_COUNT	7
static const struct sfs_file sl_txt_files[] = {
	{ "sts", &sts_ops },
	{ "ests", &ests_ops },
	{ "errorcode", &errorcode_ops },
	{ "didvid", &didvid_ops },
	{ "ver_emif", &ver_emif_ops },
	{ "scratchpad", &scratchpad_ops },
	{ "e2sts", &e2sts_ops }
};

/* sysfs file handles */
static struct dentry *slaunch_dir;
static struct dentry *event_file;
static struct dentry *txt_dir;
static struct dentry *txt_entries[SL_TXT_ENTRY_COUNT];

static long slaunch_expose_securityfs(void)
{
	long ret = 0;
	int i;

	slaunch_dir = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(slaunch_dir))
		return PTR_ERR(slaunch_dir);

	if (slaunch_get_flags() & SL_FLAG_ARCH_TXT) {
		txt_dir = securityfs_create_dir("txt", slaunch_dir);
		if (IS_ERR(txt_dir)) {
			ret = PTR_ERR(txt_dir);
			goto remove_slaunch;
		}

		for (i = 0; i < ARRAY_SIZE(sl_txt_files); i++) {
			txt_entries[i] = securityfs_create_file(
						sl_txt_files[i].name, 0440,
						txt_dir, NULL,
						sl_txt_files[i].fops);
			if (IS_ERR(txt_entries[i])) {
				ret = PTR_ERR(txt_entries[i]);
				goto remove_files;
			}
		}

	}

	if (sl_evtlog.addr > 0) {
		event_file = securityfs_create_file(
					sl_evtlog.name, 0440,
					slaunch_dir, NULL,
					&sl_evtlog_ops);
		if (IS_ERR(event_file)) {
			ret = PTR_ERR(event_file);
			goto remove_files;
		}
	}

	return 0;

remove_files:
	if (slaunch_get_flags() & SL_FLAG_ARCH_TXT) {
		while (--i >= 0)
			securityfs_remove(txt_entries[i]);
		securityfs_remove(txt_dir);
	}
remove_slaunch:
	securityfs_remove(slaunch_dir);

	return ret;
}

static void slaunch_teardown_securityfs(void)
{
	int i;

	securityfs_remove(event_file);
	if (sl_evtlog.addr) {
		memunmap(sl_evtlog.addr);
		sl_evtlog.addr = NULL;
	}
	sl_evtlog.size = 0;

	if (slaunch_get_flags() & SL_FLAG_ARCH_TXT) {
		for (i = 0; i < ARRAY_SIZE(sl_txt_files); i++)
			securityfs_remove(txt_entries[i]);

		securityfs_remove(txt_dir);

		if (txt_heap) {
			memunmap(txt_heap);
			txt_heap = NULL;
		}
	}

	securityfs_remove(slaunch_dir);
}

static void slaunch_intel_evtlog(void __iomem *txt)
{
	struct txt_os_mle_data *params;
	void *os_sinit_data;
	u64 base, size;

	memcpy_fromio(&base, txt + TXT_CR_HEAP_BASE, sizeof(base));
	memcpy_fromio(&size, txt + TXT_CR_HEAP_SIZE, sizeof(size));

	/* now map TXT heap */
	txt_heap = memremap(base, size, MEMREMAP_WB);
	if (!txt_heap)
		slaunch_txt_reset(txt,
			"Error failed to memremap TXT heap\n",
			SL_ERROR_HEAP_MAP);

	params = (struct txt_os_mle_data *)txt_os_mle_data_start(txt_heap);

	sl_evtlog.size = params->evtlog_size;
	sl_evtlog.addr = memremap(params->evtlog_addr, params->evtlog_size,
				  MEMREMAP_WB);
	if (!sl_evtlog.addr)
		slaunch_txt_reset(txt,
			"Error failed to memremap TPM event log\n",
			SL_ERROR_EVENTLOG_MAP);

	/* Determine if this is TPM 1.2 or 2.0 event log */
	if (memcmp(sl_evtlog.addr + sizeof(struct tcg_pcr_event),
		    TCG_SPECID_SIG, sizeof(TCG_SPECID_SIG)))
		return; /* looks like it is not 2.0 */

	/* For TPM 2.0 logs, the extended heap element must be located */
	os_sinit_data = txt_os_sinit_data_start(txt_heap);

	evtlog20 = tpm20_find_log2_1_element(os_sinit_data);

	/*
	 * If this fails, things are in really bad shape. Any attempt to write
	 * events to the log will fail.
	 */
	if (!evtlog20)
		slaunch_txt_reset(txt,
			"Error failed to find TPM20 event log element\n",
			SL_ERROR_TPM_INVALID_LOG20);
}

static void slaunch_tpm20_extend_event(struct tpm_chip *tpm, void __iomem *txt,
				       struct tcg_pcr_event2_head *event)
{
	u16 *alg_id_field = (u16 *)((u8 *)event +
				    sizeof(struct tcg_pcr_event2_head));
	struct tpm_digest *digests;
	u8 *dptr;
	int ret;
	u32 i, j;

	digests = kcalloc(tpm->nr_allocated_banks, sizeof(*digests),
			  GFP_KERNEL);
	if (!digests)
		slaunch_txt_reset(txt,
			"Failed to allocate array of digests\n",
			SL_ERROR_GENERIC);

	for (i = 0; i < tpm->nr_allocated_banks; i++)
		digests[i].alg_id = tpm->allocated_banks[i].alg_id;


	/* Early SL code ensured there was a max count of 2 digests */
	for (i = 0; i < event->count; i++) {
		dptr = (u8 *)alg_id_field + sizeof(u16);

		for (j = 0; j < tpm->nr_allocated_banks; j++) {
			if (digests[j].alg_id != *alg_id_field)
				continue;

			switch (digests[j].alg_id) {
			case TPM_ALG_SHA256:
				memcpy(&digests[j].digest[0], dptr,
				       SHA256_DIGEST_SIZE);
				alg_id_field = (u16 *)((u8 *)alg_id_field +
					SHA256_DIGEST_SIZE + sizeof(u16));
				break;
			case TPM_ALG_SHA1:
				memcpy(&digests[j].digest[0], dptr,
				       SHA1_DIGEST_SIZE);
				alg_id_field = (u16 *)((u8 *)alg_id_field +
					SHA1_DIGEST_SIZE + sizeof(u16));
			default:
				break;
			}
		}
	}

	ret = tpm_pcr_extend(tpm, event->pcr_idx, digests);
	if (ret) {
		pr_err("Error extending TPM20 PCR, result: %d\n", ret);
		slaunch_txt_reset(txt,
			"Failed to extend TPM20 PCR\n",
			SL_ERROR_TPM_EXTEND);
	}

	kfree(digests);
}

static void slaunch_tpm20_extend(struct tpm_chip *tpm, void __iomem *txt)
{
	struct tcg_pcr_event *event_header;
	struct tcg_pcr_event2_head *event;
	int start = 0, end = 0, size;

	event_header = (struct tcg_pcr_event *)(sl_evtlog.addr +
						evtlog20->first_record_offset);

	/* Skip first TPM 1.2 event to get to first TPM 2.0 event */
	event = (struct tcg_pcr_event2_head *)((u8 *)event_header +
						sizeof(struct tcg_pcr_event) +
						event_header->event_size);

	while ((void  *)event < sl_evtlog.addr + evtlog20->next_record_offset) {
		size = __calc_tpm2_event_size(event, event_header, false);
		if (!size)
			slaunch_txt_reset(txt,
				"TPM20 invalid event in event log\n",
				SL_ERROR_TPM_INVALID_EVENT);

		/*
		 * Marker events indicate where the Secure Launch early stub
		 * started and ended adding post launch events.
		 */
		if (event->event_type == TXT_EVTYPE_SLAUNCH_END) {
			end = 1;
			break;
		} else if (event->event_type == TXT_EVTYPE_SLAUNCH_START) {
			start = 1;
			goto next;
		}

		if (start)
			slaunch_tpm20_extend_event(tpm, txt, event);

next:
		event = (struct tcg_pcr_event2_head *)((u8 *)event + size);
	}

	if (!start || !end)
		slaunch_txt_reset(txt,
			"Missing start or end events for extending TPM20 PCRs\n",
			SL_ERROR_TPM_EXTEND);
}

static void slaunch_tpm12_extend(struct tpm_chip *tpm, void __iomem *txt)
{
	struct tpm12_event_log_header *event_header;
	struct tcg_pcr_event *event;
	struct tpm_digest digest;
	int start = 0, end = 0;
	int size, ret;

	event_header = (struct tpm12_event_log_header *)sl_evtlog.addr;
	event = (struct tcg_pcr_event *)((u8 *)event_header +
				sizeof(struct tpm12_event_log_header));

	while ((void  *)event < sl_evtlog.addr + event_header->next_event_offset) {
		size = sizeof(struct tcg_pcr_event) + event->event_size;

		/*
		 * Marker events indicate where the Secure Launch early stub
		 * started and ended adding post launch events.
		 */
		if (event->event_type == TXT_EVTYPE_SLAUNCH_END) {
			end = 1;
			break;
		} else if (event->event_type == TXT_EVTYPE_SLAUNCH_START) {
			start = 1;
			goto next;
		}

		if (start) {
			memset(&digest.digest[0], 0, TPM_MAX_DIGEST_SIZE);
			digest.alg_id = TPM_ALG_SHA1;
			memcpy(&digest.digest[0], &event->digest[0],
			       SHA1_DIGEST_SIZE);

			ret = tpm_pcr_extend(tpm, event->pcr_idx, &digest);
			if (ret) {
				pr_err("Error extending TPM12 PCR, result: %d\n", ret);
				slaunch_txt_reset(txt,
					"Failed to extend TPM12 PCR\n",
					SL_ERROR_TPM_EXTEND);
			}
		}

next:
		event = (struct tcg_pcr_event *)((u8 *)event + size);
	}

	if (!start || !end)
		slaunch_txt_reset(txt,
			"Missing start or end events for extending TPM12 PCRs\n",
			SL_ERROR_TPM_EXTEND);
}

static void slaunch_pcr_extend(void __iomem *txt)
{
	struct tpm_chip *tpm;

	tpm = tpm_default_chip();
	if (!tpm)
		slaunch_txt_reset(txt,
			"Could not get default TPM chip\n",
			SL_ERROR_TPM_INIT);
	if (evtlog20)
		slaunch_tpm20_extend(tpm, txt);
	else
		slaunch_tpm12_extend(tpm, txt);
}

static int __init slaunch_module_init(void)
{
	void __iomem *txt;

	/* Check to see if Secure Launch happened */
	if ((slaunch_get_flags() & (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT)) !=
	    (SL_FLAG_ACTIVE|SL_FLAG_ARCH_TXT))
		return 0;

	txt = ioremap(TXT_PRIV_CONFIG_REGS_BASE, TXT_NR_CONFIG_PAGES *
		      PAGE_SIZE);
	if (!txt)
		panic("Error ioremap of TXT priv registers\n");

	/* Only Intel TXT is supported at this point */
	slaunch_intel_evtlog(txt);

	slaunch_pcr_extend(txt);

	iounmap(txt);

	return slaunch_expose_securityfs();
}

static void __exit slaunch_module_exit(void)
{
	slaunch_teardown_securityfs();
}

late_initcall(slaunch_module_init);

__exitcall(slaunch_module_exit);
