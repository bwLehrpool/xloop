/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt_qcow_cluster.c
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * Cluster calculation and lookup for the QCOW2 format.
 *
 * The copyright (C) 2004-2006 of the original code is owned by Fabrice Bellard.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#include <linux/kernel.h>
#include <linux/string.h>

#include "loop_file_fmt.h"
#include "loop_file_fmt_qcow_main.h"
#include "loop_file_fmt_qcow_cache.h"
#include "loop_file_fmt_qcow_cluster.h"

/*
 * Loads a L2 slice into memory (L2 slices are the parts of L2 tables
 * that are loaded by the qcow2 cache). If the slice is in the cache,
 * the cache is used; otherwise the L2 slice is loaded from the image
 * file.
 */
static int __loop_file_fmt_qcow_cluster_l2_load(struct loop_file_fmt *lo_fmt,
	u64 offset, u64 l2_offset, u64 **l2_slice)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;

	int start_of_slice = sizeof(u64) * (
		loop_file_fmt_qcow_offset_to_l2_index(qcow_data, offset) -
		loop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data, offset)
	);

	ASSERT(qcow_data->l2_table_cache != NULL);
	return loop_file_fmt_qcow_cache_get(lo_fmt, l2_offset + start_of_slice,
		(void **) l2_slice);
}

/*
 * Checks how many clusters in a given L2 slice are contiguous in the image
 * file. As soon as one of the flags in the bitmask stop_flags changes compared
 * to the first cluster, the search is stopped and the cluster is not counted
 * as contiguous. (This allows it, for example, to stop at the first compressed
 * cluster which may require a different handling)
 */
static int __loop_file_fmt_qcow_cluster_count_contiguous(
	struct loop_file_fmt *lo_fmt, int nb_clusters, int cluster_size,
	u64 *l2_slice, u64 stop_flags)
{
	int i;
	enum loop_file_fmt_qcow_cluster_type first_cluster_type;
	u64 mask = stop_flags | L2E_OFFSET_MASK | QCOW_OFLAG_COMPRESSED;
	u64 first_entry = be64_to_cpu(l2_slice[0]);
	u64 offset = first_entry & mask;

	first_cluster_type = loop_file_fmt_qcow_get_cluster_type(lo_fmt,
		first_entry);
	if (first_cluster_type == QCOW_CLUSTER_UNALLOCATED) {
		return 0;
	}

	/* must be allocated */
	ASSERT(first_cluster_type == QCOW_CLUSTER_NORMAL ||
		first_cluster_type == QCOW_CLUSTER_ZERO_ALLOC);

	for (i = 0; i < nb_clusters; i++) {
		u64 l2_entry = be64_to_cpu(l2_slice[i]) & mask;
		if (offset + (u64) i * cluster_size != l2_entry) {
			break;
		}
	}

	return i;
}

/*
 * Checks how many consecutive unallocated clusters in a given L2
 * slice have the same cluster type.
 */
static int __loop_file_fmt_qcow_cluster_count_contiguous_unallocated(
	struct loop_file_fmt *lo_fmt, int nb_clusters, u64 *l2_slice,
	enum loop_file_fmt_qcow_cluster_type wanted_type)
{
	int i;

	ASSERT(wanted_type == QCOW_CLUSTER_ZERO_PLAIN ||
		wanted_type == QCOW_CLUSTER_UNALLOCATED);

	for (i = 0; i < nb_clusters; i++) {
		u64 entry = be64_to_cpu(l2_slice[i]);
		enum loop_file_fmt_qcow_cluster_type type =
			loop_file_fmt_qcow_get_cluster_type(lo_fmt, entry);

		if (type != wanted_type) {
			break;
		}
	}

	return i;
}

/*
 * For a given offset of the virtual disk, find the cluster type and offset in
 * the qcow2 file. The offset is stored in *cluster_offset.
 *
 * On entry, *bytes is the maximum number of contiguous bytes starting at
 * offset that we are interested in.
 *
 * On exit, *bytes is the number of bytes starting at offset that have the same
 * cluster type and (if applicable) are stored contiguously in the image file.
 * Compressed clusters are always returned one by one.
 *
 * Returns the cluster type (QCOW2_CLUSTER_*) on success, -errno in error
 * cases.
 */
int loop_file_fmt_qcow_cluster_get_offset(struct loop_file_fmt *lo_fmt,
	u64 offset, unsigned int *bytes, u64 *cluster_offset)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	unsigned int l2_index;
	u64 l1_index, l2_offset, *l2_slice;
	int c;
	unsigned int offset_in_cluster;
	u64 bytes_available, bytes_needed, nb_clusters;
	enum loop_file_fmt_qcow_cluster_type type;
	int ret;

	offset_in_cluster = loop_file_fmt_qcow_offset_into_cluster(qcow_data,
		offset);
	bytes_needed = (u64) *bytes + offset_in_cluster;

	/* compute how many bytes there are between the start of the cluster
	 * containing offset and the end of the l2 slice that contains
	 * the entry pointing to it */
	bytes_available = ((u64)(
		qcow_data->l2_slice_size -
		loop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data, offset))
	) << qcow_data->cluster_bits;

	if (bytes_needed > bytes_available) {
		bytes_needed = bytes_available;
	}

	*cluster_offset = 0;

	/* seek to the l2 offset in the l1 table */
	l1_index = loop_file_fmt_qcow_offset_to_l1_index(qcow_data, offset);
	if (l1_index >= qcow_data->l1_size) {
		type = QCOW_CLUSTER_UNALLOCATED;
		goto out;
	}

	l2_offset = qcow_data->l1_table[l1_index] & L1E_OFFSET_MASK;
	if (!l2_offset) {
		type = QCOW_CLUSTER_UNALLOCATED;
		goto out;
	}

	if (loop_file_fmt_qcow_offset_into_cluster(qcow_data, l2_offset)) {
		printk_ratelimited(KERN_ERR "loop_file_fmt_qcow: L2 table "
			"offset %llx unaligned (L1 index: %llx)", l2_offset,
			l1_index);
		return -EIO;
	}

	/* load the l2 slice in memory */
	ret = __loop_file_fmt_qcow_cluster_l2_load(lo_fmt, offset, l2_offset,
		&l2_slice);
	if (ret < 0) {
		return ret;
	}

	/* find the cluster offset for the given disk offset */
	l2_index = loop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data,
		offset);
	*cluster_offset = be64_to_cpu(l2_slice[l2_index]);

	nb_clusters = loop_file_fmt_qcow_size_to_clusters(qcow_data,
		bytes_needed);
	/* bytes_needed <= *bytes + offset_in_cluster, both of which are
	 * unsigned integers; the minimum cluster size is 512, so this
	 * assertion is always true */
	ASSERT(nb_clusters <= INT_MAX);

	type = loop_file_fmt_qcow_get_cluster_type(lo_fmt, *cluster_offset);
	if (qcow_data->qcow_version < 3 && (
			type == QCOW_CLUSTER_ZERO_PLAIN ||
			type == QCOW_CLUSTER_ZERO_ALLOC)) {
		printk_ratelimited(KERN_ERR "loop_file_fmt_qcow: zero cluster "
			"entry found in pre-v3 image (L2 offset: %llx, "
			"L2 index: %x)\n", l2_offset, l2_index);
		ret = -EIO;
		goto fail;
	}
	switch (type) {
	case QCOW_CLUSTER_COMPRESSED:
		if (loop_file_fmt_qcow_has_data_file(lo_fmt)) {
			printk_ratelimited(KERN_ERR "loop_file_fmt_qcow: "
				"compressed cluster entry found in image with "
				"external data file (L2 offset: %llx, "
				"L2 index: %x)", l2_offset, l2_index);
			ret = -EIO;
			goto fail;
		}
		/* Compressed clusters can only be processed one by one */
		c = 1;
		*cluster_offset &= L2E_COMPRESSED_OFFSET_SIZE_MASK;
		break;
	case QCOW_CLUSTER_ZERO_PLAIN:
	case QCOW_CLUSTER_UNALLOCATED:
		/* how many empty clusters ? */
		c = __loop_file_fmt_qcow_cluster_count_contiguous_unallocated(
			lo_fmt, nb_clusters, &l2_slice[l2_index], type);
		*cluster_offset = 0;
		break;
	case QCOW_CLUSTER_ZERO_ALLOC:
	case QCOW_CLUSTER_NORMAL:
		/* how many allocated clusters ? */
		c = __loop_file_fmt_qcow_cluster_count_contiguous(lo_fmt,
			nb_clusters, qcow_data->cluster_size,
			&l2_slice[l2_index], QCOW_OFLAG_ZERO);
		*cluster_offset &= L2E_OFFSET_MASK;
		if (loop_file_fmt_qcow_offset_into_cluster(qcow_data,
				*cluster_offset)) {
			printk_ratelimited(KERN_ERR "loop_file_fmt_qcow: "
				"cluster allocation offset %llx unaligned "
				"(L2 offset: %llx, L2 index: %x)\n",
				*cluster_offset, l2_offset, l2_index);
			ret = -EIO;
			goto fail;
		}
		if (loop_file_fmt_qcow_has_data_file(lo_fmt) &&
			*cluster_offset != offset - offset_in_cluster) {
			printk_ratelimited(KERN_ERR "loop_file_fmt_qcow: "
				"external data file host cluster offset %llx "
				"does not match guest cluster offset: %llx, "
				"L2 index: %x)", *cluster_offset,
				offset - offset_in_cluster, l2_index);
			ret = -EIO;
			goto fail;
		}
		break;
	default:
		BUG();
	}

	loop_file_fmt_qcow_cache_put(lo_fmt, (void **) &l2_slice);

	bytes_available = (s64) c * qcow_data->cluster_size;

out:
	if (bytes_available > bytes_needed) {
		bytes_available = bytes_needed;
	}

	/* bytes_available <= bytes_needed <= *bytes + offset_in_cluster;
	 * subtracting offset_in_cluster will therefore definitely yield
	 * something not exceeding UINT_MAX */
	ASSERT(bytes_available - offset_in_cluster <= UINT_MAX);
	*bytes = bytes_available - offset_in_cluster;

	return type;

fail:
	loop_file_fmt_qcow_cache_put(lo_fmt, (void **) &l2_slice);
	return ret;
}
