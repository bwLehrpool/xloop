// SPDX-License-Identifier: GPL-2.0
/*
 * xloop_file_fmt_qcow_cluster.c
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * Cluster calculation and lookup for the QCOW2 format.
 *
 * The copyright (C) 2004-2006 of the original code is owned by Fabrice Bellard.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/string.h>

#include "xloop_file_fmt.h"
#include "xloop_file_fmt_qcow_main.h"
#include "xloop_file_fmt_qcow_cache.h"
#include "xloop_file_fmt_qcow_cluster.h"

/*
 * __xloop_file_fmt_qcow_cluster_l2_load
 *
 * @xlo_fmt: QCOW file format
 * @offset: A guest offset, used to calculate what slice of the L2
 *          table to load.
 * @l2_offset: Offset to the L2 table in the image file.
 * @l2_slice: Location to store the pointer to the L2 slice.
 *
 * Loads a L2 slice into memory (L2 slices are the parts of L2 tables
 * that are loaded by the qcow2 cache). If the slice is in the cache,
 * the cache is used; otherwise the L2 slice is loaded from the image
 * file.
 */
static int __xloop_file_fmt_qcow_cluster_l2_load(struct xloop_file_fmt *xlo_fmt, u64 offset, u64 l2_offset,
						 u64 **l2_slice)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	int start_of_slice = xloop_file_fmt_qcow_l2_entry_size(qcow_data) *
			     (xloop_file_fmt_qcow_offset_to_l2_index(qcow_data, offset) -
			      xloop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data, offset));

	ASSERT(qcow_data->l2_table_cache != NULL);
	return xloop_file_fmt_qcow_cache_get(xlo_fmt, l2_offset + start_of_slice, (void **)l2_slice);
}

/*
 * For a given L2 entry, count the number of contiguous subclusters of
 * the same type starting from @sc_from. Compressed clusters are
 * treated as if they were divided into subclusters of size
 * qcow_data->subcluster_size.
 *
 * Return the number of contiguous subclusters and set @type to the
 * subcluster type.
 *
 * If the L2 entry is invalid return -errno and set @type to
 * QCOW_SUBCLUSTER_INVALID.
 */
static int __xloop_file_fmt_qcow_get_subcluster_range_type(struct xloop_file_fmt *xlo_fmt, u64 l2_entry, u64 l2_bitmap,
							   unsigned int sc_from,
							   enum xloop_file_fmt_qcow_subcluster_type *type)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	u32 val;

	*type = xloop_file_fmt_qcow_get_subcluster_type(xlo_fmt, l2_entry, l2_bitmap, sc_from);

	if (*type == QCOW_SUBCLUSTER_INVALID)
		return -EINVAL;
	else if (!xloop_file_fmt_qcow_has_subclusters(qcow_data) || *type == QCOW_SUBCLUSTER_COMPRESSED)
		return qcow_data->subclusters_per_cluster - sc_from;

	switch (*type) {
	case QCOW_SUBCLUSTER_NORMAL:
		val = l2_bitmap | QCOW_OFLAG_SUB_ALLOC_RANGE(0, sc_from);
		return __builtin_ctz(~val) - sc_from;

	case QCOW_SUBCLUSTER_ZERO_PLAIN:
	case QCOW_SUBCLUSTER_ZERO_ALLOC:
		val = (l2_bitmap | QCOW_OFLAG_SUB_ZERO_RANGE(0, sc_from)) >> 32;
		return __builtin_ctz(~val) - sc_from;

	case QCOW_SUBCLUSTER_UNALLOCATED_PLAIN:
	case QCOW_SUBCLUSTER_UNALLOCATED_ALLOC:
		val = ((l2_bitmap >> 32) | l2_bitmap) & ~QCOW_OFLAG_SUB_ALLOC_RANGE(0, sc_from);
		return __builtin_ctz(val) - sc_from;

	default:
		/* not reachable */
		ASSERT(false);
		*type = QCOW_SUBCLUSTER_INVALID;
		return 0;
	}
}

/*
 * Return the number of contiguous subclusters of the exact same type
 * in a given L2 slice, starting from cluster @l2_index, subcluster
 * @sc_index. Allocated subclusters are required to be contiguous in
 * the image file.
 * At most @nb_clusters are checked (note that this means clusters,
 * not subclusters).
 * Compressed clusters are always processed one by one but for the
 * purpose of this count they are treated as if they were divided into
 * subclusters of size qcow_data->subcluster_size.
 * On failure return -errno and update @l2_index to point to the
 * invalid entry.
 */
static int __xloop_file_fmt_qcow_count_contiguous_subclusters(struct xloop_file_fmt *xlo_fmt, int nb_clusters,
							      unsigned int sc_index, u64 *l2_slice,
							      unsigned int *l2_index)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	int i, count = 0;
	bool check_offset = false;
	u64 expected_offset = 0;
	enum xloop_file_fmt_qcow_subcluster_type expected_type = QCOW_SUBCLUSTER_NORMAL;
	enum xloop_file_fmt_qcow_subcluster_type type;

	ASSERT(*l2_index + nb_clusters <= qcow_data->l2_slice_size);

	for (i = 0; i < nb_clusters; i++) {
		unsigned int first_sc = (i == 0) ? sc_index : 0;
		u64 l2_entry = xloop_file_fmt_qcow_get_l2_entry(qcow_data, l2_slice, *l2_index + i);
		u64 l2_bitmap = xloop_file_fmt_qcow_get_l2_bitmap(qcow_data, l2_slice, *l2_index + i);
		int ret =
			__xloop_file_fmt_qcow_get_subcluster_range_type(xlo_fmt, l2_entry, l2_bitmap, first_sc, &type);
		if (ret < 0) {
			*l2_index += i; /* Point to the invalid entry */
			return -EIO;
		}
		if (i == 0) {
			if (type == QCOW_SUBCLUSTER_COMPRESSED) {
				/* Compressed clusters are always processed one by one */
				return ret;
			}
			expected_type = type;
			expected_offset = l2_entry & QCOW_L2E_OFFSET_MASK;
			check_offset = (type == QCOW_SUBCLUSTER_NORMAL || type == QCOW_SUBCLUSTER_ZERO_ALLOC ||
					type == QCOW_SUBCLUSTER_UNALLOCATED_ALLOC);
		} else if (type != expected_type) {
			break;
		} else if (check_offset) {
			expected_offset += qcow_data->cluster_size;
			if (expected_offset != (l2_entry & QCOW_L2E_OFFSET_MASK))
				break;
		}
		count += ret;
		/* Stop if there are type changes before the end of the cluster */
		if (first_sc + ret < qcow_data->subclusters_per_cluster)
			break;
	}

	return count;
}

/*
 * xloop_file_fmt_qcow_get_host_offset
 *
 * For a given offset of the virtual disk find the equivalent host
 * offset in the qcow2 file and store it in *host_offset. Neither
 * offset needs to be aligned to a cluster boundary.
 *
 * If the cluster is unallocated then *host_offset will be 0.
 * If the cluster is compressed then *host_offset will contain the
 * complete compressed cluster descriptor.
 *
 * On entry, *bytes is the maximum number of contiguous bytes starting at
 * offset that we are interested in.
 *
 * On exit, *bytes is the number of bytes starting at offset that have the same
 * subcluster type and (if applicable) are stored contiguously in the image
 * file. The subcluster type is stored in *subcluster_type.
 * Compressed clusters are always processed one by one.
 *
 * Returns 0 on success, -errno in error cases.
 */
int xloop_file_fmt_qcow_get_host_offset(struct xloop_file_fmt *xlo_fmt, u64 offset, unsigned int *bytes,
					u64 *host_offset, enum xloop_file_fmt_qcow_subcluster_type *subcluster_type)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	unsigned int l2_index, sc_index;
	u64 l1_index, l2_offset, *l2_slice, l2_entry, l2_bitmap;
	int sc;
	unsigned int offset_in_cluster;
	u64 bytes_available, bytes_needed, nb_clusters;
	enum xloop_file_fmt_qcow_subcluster_type type;
	int ret;
	u64 host_cluster_offset;

	offset_in_cluster = xloop_file_fmt_qcow_offset_into_cluster(qcow_data, offset);
	bytes_needed = (u64)*bytes + offset_in_cluster;

	/*
	 * compute how many bytes there are between the start of the cluster
	 * containing offset and the end of the l2 slice that contains
	 * the entry pointing to it
	 */
	bytes_available =
		((u64)(qcow_data->l2_slice_size - xloop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data, offset)))
		<< qcow_data->cluster_bits;

	if (bytes_needed > bytes_available)
		bytes_needed = bytes_available;

	*host_offset = 0;

	/* seek to the l2 offset in the l1 table */
	l1_index = xloop_file_fmt_qcow_offset_to_l1_index(qcow_data, offset);
	if (l1_index >= qcow_data->l1_size) {
		type = QCOW_SUBCLUSTER_UNALLOCATED_PLAIN;
		goto out;
	}

	l2_offset = qcow_data->l1_table[l1_index] & QCOW_L1E_OFFSET_MASK;
	if (!l2_offset) {
		type = QCOW_SUBCLUSTER_UNALLOCATED_PLAIN;
		goto out;
	}

	if (xloop_file_fmt_qcow_offset_into_cluster(qcow_data, l2_offset)) {
		dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt), "L2 table offset %llx unaligned (L1 index: %llx)",
				    l2_offset, l1_index);
		return -EIO;
	}

	/* load the l2 slice in memory */
	ret = __xloop_file_fmt_qcow_cluster_l2_load(xlo_fmt, offset, l2_offset, &l2_slice);
	if (ret < 0)
		return ret;

	/* find the cluster offset for the given disk offset */
	l2_index = xloop_file_fmt_qcow_offset_to_l2_slice_index(qcow_data, offset);
	sc_index = xloop_file_fmt_qcow_offset_to_sc_index(qcow_data, offset);
	l2_entry = xloop_file_fmt_qcow_get_l2_entry(qcow_data, l2_slice, l2_index);
	l2_bitmap = xloop_file_fmt_qcow_get_l2_bitmap(qcow_data, l2_slice, l2_index);

	nb_clusters = xloop_file_fmt_qcow_size_to_clusters(qcow_data, bytes_needed);
	/*
	 * bytes_needed <= *bytes + offset_in_cluster, both of which are
	 * unsigned integers; the minimum cluster size is 512, so this
	 * assertion is always true
	 */
	ASSERT(nb_clusters <= INT_MAX);

	type = xloop_file_fmt_qcow_get_subcluster_type(xlo_fmt, l2_entry, l2_bitmap, sc_index);
	if (qcow_data->qcow_version < 3 && (type == QCOW_SUBCLUSTER_ZERO_PLAIN || type == QCOW_SUBCLUSTER_ZERO_ALLOC)) {
		dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				    "zero cluster entry found in pre-v3 image (L2 offset: %llx, L2 index: %x)\n",
				    l2_offset, l2_index);
		ret = -EIO;
		goto fail;
	}
	switch (type) {
	case QCOW_SUBCLUSTER_INVALID:
		break; /* This is handled by count_contiguous_subclusters() below */
	case QCOW_SUBCLUSTER_COMPRESSED:
		if (xloop_file_fmt_qcow_has_data_file(qcow_data)) {
			dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				"compressed cluster entry found in image with external data file "
				"(L2 offset: %llx, L2 index: %x)\n", l2_offset, l2_index);
			ret = -EIO;
			goto fail;
		}
		*host_offset = l2_entry & QCOW_L2E_COMPRESSED_OFFSET_SIZE_MASK;
		break;
	case QCOW_SUBCLUSTER_ZERO_PLAIN:
	case QCOW_SUBCLUSTER_UNALLOCATED_PLAIN:
		break;
	case QCOW_SUBCLUSTER_ZERO_ALLOC:
	case QCOW_SUBCLUSTER_NORMAL:
	case QCOW_SUBCLUSTER_UNALLOCATED_ALLOC:
		host_cluster_offset = l2_entry & QCOW_L2E_OFFSET_MASK;
		*host_offset = host_cluster_offset + offset_in_cluster;
		if (xloop_file_fmt_qcow_offset_into_cluster(qcow_data, host_cluster_offset)) {
			dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				"cluster allocation offset %llx unaligned (L2 offset: %llx, L2 index: %x)\n",
				host_cluster_offset, l2_offset, l2_index);
			ret = -EIO;
			goto fail;
		}
		if (xloop_file_fmt_qcow_has_data_file(qcow_data) && *host_offset != offset) {
			dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				"external data file host cluster offset %llx does not match guest cluster offset: "
				"%llx, L2 index: %x)\n", host_cluster_offset, offset - offset_in_cluster, l2_index);
			ret = -EIO;
			goto fail;
		}
		break;
	default:
		BUG();
	}

	sc = __xloop_file_fmt_qcow_count_contiguous_subclusters(xlo_fmt, nb_clusters, sc_index, l2_slice, &l2_index);

	if (sc < 0) {
		dev_err_ratelimited(xloop_file_fmt_to_dev(xlo_fmt),
				    "invalid cluster entry found (L2 offset: %#llx, L2 index: %#x)", l2_offset,
				    l2_index);
		ret = -EIO;
		goto fail;
	}
	xloop_file_fmt_qcow_cache_put(xlo_fmt, (void **)&l2_slice);

	bytes_available = ((s64)sc + sc_index) << qcow_data->subcluster_bits;

out:
	if (bytes_available > bytes_needed)
		bytes_available = bytes_needed;

	/*
	 * bytes_available <= bytes_needed <= *bytes + offset_in_cluster;
	 * subtracting offset_in_cluster will therefore definitely yield
	 * something not exceeding UINT_MAX
	 */
	ASSERT(bytes_available - offset_in_cluster <= UINT_MAX);
	*bytes = bytes_available - offset_in_cluster;

	*subcluster_type = type;

	return 0;

fail:
	xloop_file_fmt_qcow_cache_put(xlo_fmt, (void **)&l2_slice);
	return ret;
}
