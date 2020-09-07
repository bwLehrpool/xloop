/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xloop_file_fmt_qcow_cache.h
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * L2/refcount table cache for the QCOW2 format.
 *
 * The copyright (C) 2010 of the original code is owned by
 * Kevin Wolf <kwolf@redhat.com>
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#ifndef _LINUX_XLOOP_FILE_FMT_QCOW_CACHE_H
#define _LINUX_XLOOP_FILE_FMT_QCOW_CACHE_H

#include "loop_file_fmt.h"

struct xloop_file_fmt_qcow_cache_table {
	s64 offset;
	u64 lru_counter;
	int ref;
	bool dirty;
};

struct xloop_file_fmt_qcow_cache {
	struct xloop_file_fmt_qcow_cache_table *entries;
	struct xloop_file_fmt_qcow_cache *depends;
	int size;
	int table_size;
	bool depends_on_flush;
	void *table_array;
	u64 lru_counter;
	u64 cache_clean_lru_counter;
};

extern struct xloop_file_fmt_qcow_cache *xloop_file_fmt_qcow_cache_create(
	struct xloop_file_fmt *xlo_fmt,
	int num_tables,
	unsigned table_size);

extern void xloop_file_fmt_qcow_cache_destroy(struct xloop_file_fmt *xlo_fmt);

extern int xloop_file_fmt_qcow_cache_get(struct xloop_file_fmt *xlo_fmt,
					u64 offset,
					void **table);

extern void xloop_file_fmt_qcow_cache_put(struct xloop_file_fmt *xlo_fmt,
					 void **table);

#endif
