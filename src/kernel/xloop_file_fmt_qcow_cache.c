// SPDX-License-Identifier: GPL-2.0
/*
 * xloop_file_fmt_qcow_cache.c
 *
 * QCOW file format driver for the xloop device module.
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * L2/refcount table cache for the QCOW2 format.
 *
 * The copyright (C) 2010 of the original code is owned by
 * Kevin Wolf <kwolf@redhat.com>
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/math64.h>

#include "xloop_file_fmt_qcow_main.h"
#include "xloop_file_fmt_qcow_cache.h"

static inline void *__xloop_file_fmt_qcow_cache_get_table_addr(struct xloop_file_fmt_qcow_cache *c, int table)
{
	return (u8 *)c->table_array + (size_t)table * c->table_size;
}

static inline int __xloop_file_fmt_qcow_cache_get_table_idx(struct xloop_file_fmt_qcow_cache *c, void *table)
{
	ptrdiff_t table_offset = (u8 *)table - (u8 *)c->table_array;
	int idx = div_s64(table_offset, c->table_size);

#ifdef ASSERT
	s32 rem_table_offset_mod_table_size;

	div_s64_rem(table_offset, c->table_size, &rem_table_offset_mod_table_size);
	ASSERT(idx >= 0 && idx < c->size && rem_table_offset_mod_table_size == 0);
#endif

	return idx;
}

static inline const char *__xloop_file_fmt_qcow_cache_get_name(struct xloop_file_fmt *xlo_fmt,
							       struct xloop_file_fmt_qcow_cache *c)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	if (c == qcow_data->refcount_block_cache) {
		return "refcount block";
	} else if (c == qcow_data->l2_table_cache) {
		return "L2 table";
	} else {
		/* do not abort, because this is not critical */
		return "unknown";
	}
}

struct xloop_file_fmt_qcow_cache *xloop_file_fmt_qcow_cache_create(struct xloop_file_fmt *xlo_fmt, int num_tables,
								   unsigned int table_size)
{
#ifdef CONFIG_DEBUG_DRIVER
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
#endif
	struct xloop_file_fmt_qcow_cache *c;

	ASSERT(num_tables > 0);
	ASSERT(is_power_of_2(table_size));
	ASSERT(table_size >= (1 << QCOW_MIN_CLUSTER_BITS));
	ASSERT(table_size <= qcow_data->cluster_size);

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return NULL;

	c->size = num_tables;
	c->table_size = table_size;
	c->entries = vzalloc(sizeof(struct xloop_file_fmt_qcow_cache_table) * num_tables);
	c->table_array = vzalloc(num_tables * c->table_size);

	if (!c->entries || !c->table_array) {
		vfree(c->table_array);
		vfree(c->entries);
		kfree(c);
		c = NULL;
	}

	return c;
}

void xloop_file_fmt_qcow_cache_destroy(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_file_fmt_qcow_cache *c = qcow_data->l2_table_cache;
	int i;

	for (i = 0; i < c->size; i++)
		ASSERT(c->entries[i].ref == 0);

	vfree(c->table_array);
	vfree(c->entries);
	kfree(c);
}

static int __xloop_file_fmt_qcow_cache_entry_flush(struct xloop_file_fmt *xlo_fmt, struct xloop_file_fmt_qcow_cache *c,
						   int i)
{
	if (!c->entries[i].dirty || !c->entries[i].offset) {
		return 0;
	} else {
		dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt), "flush dirty cache tables is not supported yet\n");
		return -EINVAL;
	}
}

static int __xloop_file_fmt_qcow_cache_do_get(struct xloop_file_fmt *xlo_fmt, struct xloop_file_fmt_qcow_cache *c,
					      u64 offset, void **table, bool read_from_disk)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	int i;
	int ret;
	int lookup_index;
	u64 min_lru_counter = U64_MAX;
	int min_lru_index = -1;
	u64 read_offset;
	u64 offset_div_table_size;
	size_t len;

	ASSERT(offset != 0);

	if (!IS_ALIGNED(offset, c->table_size)) {
		dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				    "cannot get entry from %s cache: offset %llx is unaligned\n",
				    __xloop_file_fmt_qcow_cache_get_name(xlo_fmt, c), offset);
		return -EIO;
	}

	/* Check if the table is already cached */
	offset_div_table_size = div_u64(offset, c->table_size) * 4;
	div_u64_rem(offset_div_table_size, c->size, &lookup_index);
	i = lookup_index;
	do {
		const struct xloop_file_fmt_qcow_cache_table *t = &c->entries[i];

		if (t->offset == offset)
			goto found;

		if (t->ref == 0 && t->lru_counter < min_lru_counter) {
			min_lru_counter = t->lru_counter;
			min_lru_index = i;
		}
		if (++i == c->size)
			i = 0;

	} while (i != lookup_index);

	if (min_lru_index == -1) {
		BUG();
		panic("Oops: This can't happen in current synchronous code while using AIO with the QCOW cache\n");
	}

	/* Cache miss: write a table back and replace it */
	i = min_lru_index;

	ret = __xloop_file_fmt_qcow_cache_entry_flush(xlo_fmt, c, i);
	if (ret < 0)
		return ret;

	c->entries[i].offset = 0;
	if (read_from_disk) {
		read_offset = offset;
		len = kernel_read(xlo->xlo_backing_file, __xloop_file_fmt_qcow_cache_get_table_addr(c, i),
				  c->table_size, &read_offset);
		if (len < 0) {
			len = ret;
			return ret;
		}
	}

	c->entries[i].offset = offset;

	/* And return the right table */
found:
	c->entries[i].ref++;
	*table = __xloop_file_fmt_qcow_cache_get_table_addr(c, i);

	return 0;
}

int xloop_file_fmt_qcow_cache_get(struct xloop_file_fmt *xlo_fmt, u64 offset, void **table)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_file_fmt_qcow_cache *c = qcow_data->l2_table_cache;

	return __xloop_file_fmt_qcow_cache_do_get(xlo_fmt, c, offset, table, true);
}

void xloop_file_fmt_qcow_cache_put(struct xloop_file_fmt *xlo_fmt, void **table)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_file_fmt_qcow_cache *c = qcow_data->l2_table_cache;
	int i = __xloop_file_fmt_qcow_cache_get_table_idx(c, *table);

	c->entries[i].ref--;
	*table = NULL;

	if (c->entries[i].ref == 0)
		c->entries[i].lru_counter = ++c->lru_counter;

	ASSERT(c->entries[i].ref >= 0);
}
