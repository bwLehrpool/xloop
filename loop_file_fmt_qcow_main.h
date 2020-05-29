/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt_qcow.h
 *
 * QCOW file format driver for the loop device module.
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * Declarations for the QCOW2 file format.
 *
 * The copyright (C) 2004-2006 of the original code is owned by Fabrice Bellard.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#ifndef _LINUX_LOOP_FILE_FMT_QCOW_H
#define _LINUX_LOOP_FILE_FMT_QCOW_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/zlib.h>

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include "loop_file_fmt.h"

#ifdef CONFIG_DEBUG_DRIVER
#define ASSERT(x)  							\
do {									\
	if (!(x)) {							\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

#define KiB (1024)
#define MiB (1024 * 1024)

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1
#define QCOW_CRYPT_LUKS 2

#define QCOW_MAX_CRYPT_CLUSTERS 32
#define QCOW_MAX_SNAPSHOTS 65536

/* Field widths in QCOW mean normal cluster offsets cannot reach
 * 64PB; depending on cluster size, compressed clusters can have a
 * smaller limit (64PB for up to 16k clusters, then ramps down to
 * 512TB for 2M clusters).  */
#define QCOW_MAX_CLUSTER_OFFSET ((1ULL << 56) - 1)

/* 8 MB refcount table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW_MAX_REFTABLE_SIZE (8 * MiB)

/* 32 MB L1 table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW_MAX_L1_SIZE (32 * MiB)

/* Allow for an average of 1k per snapshot table entry, should be plenty of
 * space for snapshot names and IDs */
#define QCOW_MAX_SNAPSHOTS_SIZE (1024 * QCOW_MAX_SNAPSHOTS)

/* Bitmap header extension constraints */
#define QCOW_MAX_BITMAPS 65535
#define QCOW_MAX_BITMAP_DIRECTORY_SIZE (1024 * QCOW_MAX_BITMAPS)

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED     (1ULL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED (1ULL << 62)
/* The cluster reads as all zeros */
#define QCOW_OFLAG_ZERO (1ULL << 0)

#define QCOW_MIN_CLUSTER_BITS 9
#define QCOW_MAX_CLUSTER_BITS 21

/* Defined in the qcow2 spec (compressed cluster descriptor) */
#define QCOW_COMPRESSED_SECTOR_SIZE 512U
#define QCOW_COMPRESSED_SECTOR_MASK (~(QCOW_COMPRESSED_SECTOR_SIZE - 1))

/* Must be at least 2 to cover COW */
#define QCOW_MIN_L2_CACHE_SIZE 2 /* cache entries */

/* Must be at least 4 to cover all cases of refcount table growth */
#define QCOW_MIN_REFCOUNT_CACHE_SIZE 4 /* clusters */

#define QCOW_DEFAULT_L2_CACHE_MAX_SIZE (32 * MiB)
#define QCOW_DEFAULT_CACHE_CLEAN_INTERVAL 600  /* seconds */

#define QCOW_DEFAULT_CLUSTER_SIZE 65536

/* Buffer size for debugfs file buffer to display QCOW header information */
#define QCOW_HEADER_BUF_LEN 1024

/* Buffer size for debugfs file buffer to receive and display offset and
 * cluster offset information */
#define QCOW_OFFSET_BUF_LEN 32
#define QCOW_CLUSTER_BUF_LEN 128

struct loop_file_fmt_qcow_header {
	u32 magic;
	u32 version;
	u64 backing_file_offset;
	u32 backing_file_size;
	u32 cluster_bits;
	u64 size; /* in bytes */
	u32 crypt_method;
	u32 l1_size;
	u64 l1_table_offset;
	u64 refcount_table_offset;
	u32 refcount_table_clusters;
	u32 nb_snapshots;
	u64 snapshots_offset;

	/* The following fields are only valid for version >= 3 */
	u64 incompatible_features;
	u64 compatible_features;
	u64 autoclear_features;

	u32 refcount_order;
	u32 header_length;
} __attribute__((packed));

struct loop_file_fmt_qcow_snapshot_header {
	/* header is 8 byte aligned */
	u64 l1_table_offset;

	u32 l1_size;
	u16 id_str_size;
	u16 name_size;

	u32 date_sec;
	u32 date_nsec;

	u64 vm_clock_nsec;

	u32 vm_state_size;
	/* for extension */
	u32 extra_data_size;
	/* extra data follows */
	/* id_str follows */
	/* name follows  */
} __attribute__((packed));

enum {
	QCOW_FEAT_TYPE_INCOMPATIBLE    = 0,
	QCOW_FEAT_TYPE_COMPATIBLE      = 1,
	QCOW_FEAT_TYPE_AUTOCLEAR       = 2,
};

/* incompatible feature bits */
enum {
	QCOW_INCOMPAT_DIRTY_BITNR      = 0,
	QCOW_INCOMPAT_CORRUPT_BITNR    = 1,
	QCOW_INCOMPAT_DATA_FILE_BITNR  = 2,
	QCOW_INCOMPAT_DIRTY            = 1 << QCOW_INCOMPAT_DIRTY_BITNR,
	QCOW_INCOMPAT_CORRUPT          = 1 << QCOW_INCOMPAT_CORRUPT_BITNR,
	QCOW_INCOMPAT_DATA_FILE        = 1 << QCOW_INCOMPAT_DATA_FILE_BITNR,

	QCOW_INCOMPAT_MASK             = QCOW_INCOMPAT_DIRTY
					| QCOW_INCOMPAT_CORRUPT
					| QCOW_INCOMPAT_DATA_FILE,
};

/* compatible feature bits */
enum {
	QCOW_COMPAT_LAZY_REFCOUNTS_BITNR = 0,
	QCOW_COMPAT_LAZY_REFCOUNTS       = 1 << QCOW_COMPAT_LAZY_REFCOUNTS_BITNR,

	QCOW_COMPAT_FEAT_MASK            = QCOW_COMPAT_LAZY_REFCOUNTS,
};

/* autoclear feature bits */
enum {
	QCOW_AUTOCLEAR_BITMAPS_BITNR       = 0,
	QCOW_AUTOCLEAR_DATA_FILE_RAW_BITNR = 1,
	QCOW_AUTOCLEAR_BITMAPS             = 1 << QCOW_AUTOCLEAR_BITMAPS_BITNR,
	QCOW_AUTOCLEAR_DATA_FILE_RAW       = 1 << QCOW_AUTOCLEAR_DATA_FILE_RAW_BITNR,

	QCOW_AUTOCLEAR_MASK                = QCOW_AUTOCLEAR_BITMAPS |
						QCOW_AUTOCLEAR_DATA_FILE_RAW,
};

struct loop_file_fmt_qcow_data {
	u64 size;
	int cluster_bits;
	int cluster_size;
	int cluster_sectors;
	int l2_slice_size;
	int l2_bits;
	int l2_size;
	int l1_size;
	int l1_vm_state_index;
	int refcount_block_bits;
	int refcount_block_size;
	int csize_shift;
	int csize_mask;
	u64 cluster_offset_mask;
	u64 l1_table_offset;
	u64 *l1_table;

	struct loop_file_fmt_qcow_cache *l2_table_cache;
	struct loop_file_fmt_qcow_cache *refcount_block_cache;

	u64 *refcount_table;
	u64 refcount_table_offset;
	u32 refcount_table_size;
	u32 max_refcount_table_index; /* Last used entry in refcount_table */
	u64 free_cluster_index;
	u64 free_byte_offset;

	u32 crypt_method_header;
	u64 snapshots_offset;
	int snapshots_size;
	unsigned int nb_snapshots;

	u32 nb_bitmaps;
	u64 bitmap_directory_size;
	u64 bitmap_directory_offset;

	int qcow_version;
	bool use_lazy_refcounts;
	int refcount_order;
	int refcount_bits;
	u64 refcount_max;

	u64 incompatible_features;
	u64 compatible_features;
	u64 autoclear_features;

	struct z_stream_s *strm;

	/* debugfs entries */
#ifdef CONFIG_DEBUG_FS
	struct dentry *dbgfs_dir;
	struct dentry *dbgfs_file_qcow_header;
	char dbgfs_file_qcow_header_buf[QCOW_HEADER_BUF_LEN];
	struct dentry *dbgfs_file_qcow_offset;
	char dbgfs_file_qcow_offset_buf[QCOW_OFFSET_BUF_LEN];
	char dbgfs_file_qcow_cluster_buf[QCOW_CLUSTER_BUF_LEN];
	u64 dbgfs_qcow_offset;
	struct mutex dbgfs_qcow_offset_mutex;
#endif
};

struct loop_file_fmt_qcow_cow_region {
	/**
	 * Offset of the COW region in bytes from the start of the first
	 * cluster touched by the request.
	 */
	unsigned offset;

	/** Number of bytes to copy */
	unsigned nb_bytes;
};

enum loop_file_fmt_qcow_cluster_type {
	QCOW_CLUSTER_UNALLOCATED,
	QCOW_CLUSTER_ZERO_PLAIN,
	QCOW_CLUSTER_ZERO_ALLOC,
	QCOW_CLUSTER_NORMAL,
	QCOW_CLUSTER_COMPRESSED,
};

enum loop_file_fmt_qcow_metadata_overlap {
	QCOW_OL_MAIN_HEADER_BITNR      = 0,
	QCOW_OL_ACTIVE_L1_BITNR        = 1,
	QCOW_OL_ACTIVE_L2_BITNR        = 2,
	QCOW_OL_REFCOUNT_TABLE_BITNR   = 3,
	QCOW_OL_REFCOUNT_BLOCK_BITNR   = 4,
	QCOW_OL_SNAPSHOT_TABLE_BITNR   = 5,
	QCOW_OL_INACTIVE_L1_BITNR      = 6,
	QCOW_OL_INACTIVE_L2_BITNR      = 7,
	QCOW_OL_BITMAP_DIRECTORY_BITNR = 8,

	QCOW_OL_MAX_BITNR              = 9,

	QCOW_OL_NONE             = 0,
	QCOW_OL_MAIN_HEADER      = (1 << QCOW_OL_MAIN_HEADER_BITNR),
	QCOW_OL_ACTIVE_L1        = (1 << QCOW_OL_ACTIVE_L1_BITNR),
	QCOW_OL_ACTIVE_L2        = (1 << QCOW_OL_ACTIVE_L2_BITNR),
	QCOW_OL_REFCOUNT_TABLE   = (1 << QCOW_OL_REFCOUNT_TABLE_BITNR),
	QCOW_OL_REFCOUNT_BLOCK   = (1 << QCOW_OL_REFCOUNT_BLOCK_BITNR),
	QCOW_OL_SNAPSHOT_TABLE   = (1 << QCOW_OL_SNAPSHOT_TABLE_BITNR),
	QCOW_OL_INACTIVE_L1      = (1 << QCOW_OL_INACTIVE_L1_BITNR),
	/* NOTE: Checking overlaps with inactive L2 tables will result in bdrv
	 * reads. */
	QCOW_OL_INACTIVE_L2      = (1 << QCOW_OL_INACTIVE_L2_BITNR),
	QCOW_OL_BITMAP_DIRECTORY = (1 << QCOW_OL_BITMAP_DIRECTORY_BITNR),
};

/* Perform all overlap checks which can be done in constant time */
#define QCOW_OL_CONSTANT \
	(QCOW_OL_MAIN_HEADER | QCOW_OL_ACTIVE_L1 | QCOW_OL_REFCOUNT_TABLE | \
		QCOW_OL_SNAPSHOT_TABLE | QCOW_OL_BITMAP_DIRECTORY)

/* Perform all overlap checks which don't require disk access */
#define QCOW_OL_CACHED \
	(QCOW_OL_CONSTANT | QCOW_OL_ACTIVE_L2 | QCOW_OL_REFCOUNT_BLOCK | \
		QCOW_OL_INACTIVE_L1)

/* Perform all overlap checks */
#define QCOW_OL_ALL \
	(QCOW_OL_CACHED | QCOW_OL_INACTIVE_L2)

#define L1E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_COMPRESSED_OFFSET_SIZE_MASK 0x3fffffffffffffffULL

#define REFT_OFFSET_MASK 0xfffffffffffffe00ULL

#define INV_OFFSET (-1ULL)

static inline bool loop_file_fmt_qcow_has_data_file(
	struct loop_file_fmt *lo_fmt)
{
	/* At the moment, there is no support for copy on write! */
	return false;
}

static inline bool loop_file_fmt_qcow_data_file_is_raw(
	struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	return !!(qcow_data->autoclear_features &
		QCOW_AUTOCLEAR_DATA_FILE_RAW);
}

static inline s64 loop_file_fmt_qcow_start_of_cluster(
	struct loop_file_fmt_qcow_data *qcow_data, s64 offset)
{
	return offset & ~(qcow_data->cluster_size - 1);
}

static inline s64 loop_file_fmt_qcow_offset_into_cluster(
	struct loop_file_fmt_qcow_data *qcow_data, s64 offset)
{
	return offset & (qcow_data->cluster_size - 1);
}

static inline s64 loop_file_fmt_qcow_size_to_clusters(
	struct loop_file_fmt_qcow_data *qcow_data, u64 size)
{
	return (size + (qcow_data->cluster_size - 1)) >>
		qcow_data->cluster_bits;
}

static inline s64 loop_file_fmt_qcow_size_to_l1(
	struct loop_file_fmt_qcow_data *qcow_data, s64 size)
{
	int shift = qcow_data->cluster_bits + qcow_data->l2_bits;
	return (size + (1ULL << shift) - 1) >> shift;
}

static inline int loop_file_fmt_qcow_offset_to_l1_index(
	struct loop_file_fmt_qcow_data *qcow_data, u64 offset)
{
	return offset >> (qcow_data->l2_bits + qcow_data->cluster_bits);
}

static inline int loop_file_fmt_qcow_offset_to_l2_index(
	struct loop_file_fmt_qcow_data *qcow_data, s64 offset)
{
	return (offset >> qcow_data->cluster_bits) & (qcow_data->l2_size - 1);
}

static inline int loop_file_fmt_qcow_offset_to_l2_slice_index(
	struct loop_file_fmt_qcow_data *qcow_data, s64 offset)
{
	return (offset >> qcow_data->cluster_bits) &
		(qcow_data->l2_slice_size - 1);
}

static inline s64 loop_file_fmt_qcow_vm_state_offset(
	struct loop_file_fmt_qcow_data *qcow_data)
{
	return (s64)qcow_data->l1_vm_state_index <<
		(qcow_data->cluster_bits + qcow_data->l2_bits);
}

static inline enum loop_file_fmt_qcow_cluster_type
loop_file_fmt_qcow_get_cluster_type(struct loop_file_fmt *lo_fmt, u64 l2_entry)
{
	if (l2_entry & QCOW_OFLAG_COMPRESSED) {
		return QCOW_CLUSTER_COMPRESSED;
	} else if (l2_entry & QCOW_OFLAG_ZERO) {
		if (l2_entry & L2E_OFFSET_MASK) {
			return QCOW_CLUSTER_ZERO_ALLOC;
		}
		return QCOW_CLUSTER_ZERO_PLAIN;
	} else if (!(l2_entry & L2E_OFFSET_MASK)) {
		/* Offset 0 generally means unallocated, but it is ambiguous
		 * with external data files because 0 is a valid offset there.
		 * However, all clusters in external data files always have
		 * refcount 1, so we can rely on QCOW_OFLAG_COPIED to
		 * disambiguate. */
		if (loop_file_fmt_qcow_has_data_file(lo_fmt) &&
			(l2_entry & QCOW_OFLAG_COPIED)) {
			return QCOW_CLUSTER_NORMAL;
		} else {
			return QCOW_CLUSTER_UNALLOCATED;
		}
	} else {
		return QCOW_CLUSTER_NORMAL;
	}
}

#endif
