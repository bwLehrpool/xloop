/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt_qcow.c
 *
 * QCOW file format driver for the loop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/mutex.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>

#include "loop_file_fmt.h"
#include "loop_file_fmt_qcow_main.h"
#include "loop_file_fmt_qcow_cache.h"
#include "loop_file_fmt_qcow_cluster.h"

static int __qcow_file_fmt_header_read(struct loop_file_fmt *lo_fmt,
	struct loop_file_fmt_qcow_header *header)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	ssize_t len;
	loff_t offset;
	int ret = 0;

	/* read QCOW header */
	offset = 0;
	len = kernel_read(lo->lo_backing_file, header, sizeof(*header),
		&offset);
	if (len < 0) {
		printk(KERN_ERR "loop_file_fmt_qcow: could not read QCOW "
			"header");
		return len;
	}

	header->magic = be32_to_cpu(header->magic);
	header->version = be32_to_cpu(header->version);
	header->backing_file_offset = be64_to_cpu(header->backing_file_offset);
	header->backing_file_size = be32_to_cpu(header->backing_file_size);
	header->cluster_bits = be32_to_cpu(header->cluster_bits);
	header->size = be64_to_cpu(header->size);
	header->crypt_method = be32_to_cpu(header->crypt_method);
	header->l1_size = be32_to_cpu(header->l1_size);
	header->l1_table_offset = be64_to_cpu(header->l1_table_offset);
	header->refcount_table_offset =
		be64_to_cpu(header->refcount_table_offset);
	header->refcount_table_clusters =
		be32_to_cpu(header->refcount_table_clusters);
	header->nb_snapshots = be32_to_cpu(header->nb_snapshots);
	header->snapshots_offset = be64_to_cpu(header->snapshots_offset);

	/* check QCOW file format and header version */
	if (header->magic != QCOW_MAGIC) {
		printk(KERN_ERR "loop_file_fmt_qcow: image is not in QCOW "
			"format");
		return -EINVAL;
	}

	if (header->version < 2 || header->version > 3) {
		printk(KERN_ERR "loop_file_fmt_qcow: unsupported QCOW version "
			"%d", header->version);
		return -ENOTSUPP;
	}

	/* initialize version 3 header fields */
	if (header->version == 2) {
		header->incompatible_features =  0;
		header->compatible_features   =  0;
		header->autoclear_features    =  0;
		header->refcount_order        =  4;
		header->header_length         = 72;
	} else {
		header->incompatible_features =
			be64_to_cpu(header->incompatible_features);
		header->compatible_features =
			be64_to_cpu(header->compatible_features);
		header->autoclear_features =
			be64_to_cpu(header->autoclear_features);
		header->refcount_order = be32_to_cpu(header->refcount_order);
		header->header_length = be32_to_cpu(header->header_length);

		if (header->header_length < 104) {
			printk(KERN_ERR "loop_file_fmt_qcow: QCOW header too "
				"short");
			return -EINVAL;
		}
	}

	return ret;
}

static int __qcow_file_fmt_validate_table(struct loop_file_fmt *lo_fmt,
	u64 offset, u64 entries, size_t entry_len, s64 max_size_bytes,
	const char *table_name)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;

	if (entries > max_size_bytes / entry_len) {
		printk(KERN_INFO "loop_file_fmt_qcow: %s too large",
			table_name);
		return -EFBIG;
	}

	/* Use signed S64_MAX as the maximum even for u64 header fields,
	 * because values will be passed to qemu functions taking s64. */
	if ((S64_MAX - entries * entry_len < offset) || (
		loop_file_fmt_qcow_offset_into_cluster(qcow_data, offset) != 0)
	) {
		printk(KERN_INFO "loop_file_fmt_qcow: %s offset invalid",
			table_name);
		return -EINVAL;
	}

	return 0;
}

static inline loff_t __qcow_file_fmt_rq_get_pos(struct loop_file_fmt *lo_fmt,
						struct request *rq)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	return ((loff_t) blk_rq_pos(rq) << 9) + lo->lo_offset;
}

static int __qcow_file_fmt_compression_init(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	int ret = 0;

	qcow_data->strm = kzalloc(sizeof(*qcow_data->strm), GFP_KERNEL);
	if (!qcow_data->strm) {
		ret = -ENOMEM;
		goto out;
	}

	qcow_data->strm->workspace = vzalloc(zlib_inflate_workspacesize());
	if (!qcow_data->strm->workspace) {
		ret = -ENOMEM;
		goto out_free_strm;
	}

	return ret;

out_free_strm:
	kfree(qcow_data->strm);
out:
	return ret;
}

static void __qcow_file_fmt_compression_exit(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;

	if (qcow_data->strm->workspace)
		vfree(qcow_data->strm->workspace);

	if (qcow_data->strm)
		kfree(qcow_data->strm);
}

#ifdef CONFIG_DEBUG_FS
static void __qcow_file_fmt_header_to_buf(struct loop_file_fmt *lo_fmt,
	const struct loop_file_fmt_qcow_header *header)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	char *header_buf = qcow_data->dbgfs_file_qcow_header_buf;
	ssize_t len = 0;

	len += sprintf(header_buf + len, "magic: %d\n",
		header->magic);
	len += sprintf(header_buf + len, "version: %d\n",
		header->version);
	len += sprintf(header_buf + len, "backing_file_offset: %lld\n",
		header->backing_file_offset);
	len += sprintf(header_buf + len, "backing_file_size: %d\n",
		header->backing_file_size);
	len += sprintf(header_buf + len, "cluster_bits: %d\n",
		header->cluster_bits);
	len += sprintf(header_buf + len, "size: %lld\n",
		header->size);
	len += sprintf(header_buf + len, "crypt_method: %d\n",
		header->crypt_method);
	len += sprintf(header_buf + len, "l1_size: %d\n",
		header->l1_size);
	len += sprintf(header_buf + len, "l1_table_offset: %lld\n",
		header->l1_table_offset);
	len += sprintf(header_buf + len, "refcount_table_offset: %lld\n",
		header->refcount_table_offset);
	len += sprintf(header_buf + len, "refcount_table_clusters: %d\n",
		header->refcount_table_clusters);
	len += sprintf(header_buf + len, "nb_snapshots: %d\n",
		header->nb_snapshots);
	len += sprintf(header_buf + len, "snapshots_offset: %lld\n",
		header->snapshots_offset);

	if (header->version == 3) {
		len += sprintf(header_buf + len,
			"incompatible_features: %lld\n",
			header->incompatible_features);
		len += sprintf(header_buf + len,
			"compatible_features: %lld\n",
			header->compatible_features);
		len += sprintf(header_buf + len,
			"autoclear_features: %lld\n",
			header->autoclear_features);
		len += sprintf(header_buf + len,
			"refcount_order: %d\n",
			header->refcount_order);
		len += sprintf(header_buf + len,
			"header_length: %d\n",
			header->header_length);
	}

	ASSERT(len < QCOW_HEADER_BUF_LEN);
}

static ssize_t __qcow_file_fmt_dbgfs_hdr_read(struct file *file,
	char __user *buf, size_t size, loff_t *ppos)
{
	struct loop_file_fmt *lo_fmt = file->private_data;
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	char *header_buf = qcow_data->dbgfs_file_qcow_header_buf;

	return simple_read_from_buffer(buf, size, ppos, header_buf,
		strlen(header_buf));
}

static const struct file_operations qcow_file_fmt_dbgfs_hdr_fops = {
	.open = simple_open,
	.read = __qcow_file_fmt_dbgfs_hdr_read
};

static ssize_t __qcow_file_fmt_dbgfs_ofs_read(struct file *file,
	char __user *buf, size_t size, loff_t *ppos)
{
	struct loop_file_fmt *lo_fmt = file->private_data;
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	unsigned int cur_bytes = 1;
	u64 offset = 0;
	u64 cluster_offset = 0;
	s64 offset_in_cluster = 0;
	ssize_t len = 0;
	int ret = 0;

	/* read the share debugfs offset */
	ret = mutex_lock_interruptible(&qcow_data->dbgfs_qcow_offset_mutex);
	if (ret)
		return ret;

	offset = qcow_data->dbgfs_qcow_offset;
	mutex_unlock(&qcow_data->dbgfs_qcow_offset_mutex);

	/* calculate and print the cluster offset */
	ret = loop_file_fmt_qcow_cluster_get_offset(lo_fmt,
		offset, &cur_bytes, &cluster_offset);
	if (ret < 0)
		return -EINVAL;

	offset_in_cluster = loop_file_fmt_qcow_offset_into_cluster(qcow_data,
		offset);

	len = sprintf(qcow_data->dbgfs_file_qcow_cluster_buf,
		"offset: %lld\ncluster_offset: %lld\noffset_in_cluster: %lld\n",
		offset, cluster_offset, offset_in_cluster);

	ASSERT(len < QCOW_CLUSTER_BUF_LEN);

	return simple_read_from_buffer(buf, size, ppos,
		qcow_data->dbgfs_file_qcow_cluster_buf, len);
}

static ssize_t __qcow_file_fmt_dbgfs_ofs_write(struct file *file,
	const char __user *buf, size_t size, loff_t *ppos)
{
	struct loop_file_fmt *lo_fmt = file->private_data;
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	ssize_t len = 0;
	int ret = 0;

	if (*ppos > QCOW_OFFSET_BUF_LEN || size > QCOW_OFFSET_BUF_LEN)
		return -EINVAL;

	len = simple_write_to_buffer(qcow_data->dbgfs_file_qcow_offset_buf,
		QCOW_OFFSET_BUF_LEN, ppos, buf, size);
	if (len < 0)
		return len;

	qcow_data->dbgfs_file_qcow_offset_buf[len] = '\0';

	ret = mutex_lock_interruptible(&qcow_data->dbgfs_qcow_offset_mutex);
	if (ret)
		return ret;

	ret = kstrtou64(qcow_data->dbgfs_file_qcow_offset_buf, 10,
		&qcow_data->dbgfs_qcow_offset);
	if (ret < 0)
		goto out;

	ret = len;
out:
	mutex_unlock(&qcow_data->dbgfs_qcow_offset_mutex);
	return ret;
}

static const struct file_operations qcow_file_fmt_dbgfs_ofs_fops = {
	.open = simple_open,
	.read = __qcow_file_fmt_dbgfs_ofs_read,
	.write = __qcow_file_fmt_dbgfs_ofs_write
};

static int __qcow_file_fmt_dbgfs_init(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	int ret = 0;

	qcow_data->dbgfs_dir = debugfs_create_dir("QCOW", lo->lo_dbgfs_dir);
	if (IS_ERR_OR_NULL(qcow_data->dbgfs_dir)) {
		ret = -ENODEV;
		goto out;
	}

	qcow_data->dbgfs_file_qcow_header = debugfs_create_file("header",
		S_IRUGO, qcow_data->dbgfs_dir, lo_fmt,
		&qcow_file_fmt_dbgfs_hdr_fops);
	if (IS_ERR_OR_NULL(qcow_data->dbgfs_file_qcow_header)) {
		ret = -ENODEV;
		goto out_free_dbgfs_dir;
	}

	qcow_data->dbgfs_file_qcow_offset = debugfs_create_file("offset",
		S_IRUGO | S_IWUSR, qcow_data->dbgfs_dir, lo_fmt,
		&qcow_file_fmt_dbgfs_ofs_fops);
	if (IS_ERR_OR_NULL(qcow_data->dbgfs_file_qcow_offset)) {
		qcow_data->dbgfs_file_qcow_offset = NULL;
		ret = -ENODEV;
		goto out_free_dbgfs_hdr;
	}

	qcow_data->dbgfs_qcow_offset = 0;
	mutex_init(&qcow_data->dbgfs_qcow_offset_mutex);

	return ret;

out_free_dbgfs_hdr:
	debugfs_remove(qcow_data->dbgfs_file_qcow_header);
	qcow_data->dbgfs_file_qcow_header = NULL;
out_free_dbgfs_dir:
	debugfs_remove(qcow_data->dbgfs_dir);
	qcow_data->dbgfs_dir = NULL;
out:
	return ret;
}

static void __qcow_file_fmt_dbgfs_exit(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;

	if (qcow_data->dbgfs_file_qcow_offset)
		debugfs_remove(qcow_data->dbgfs_file_qcow_offset);

	mutex_destroy(&qcow_data->dbgfs_qcow_offset_mutex);

	if (qcow_data->dbgfs_file_qcow_header)
		debugfs_remove(qcow_data->dbgfs_file_qcow_header);

	if (qcow_data->dbgfs_dir)
		debugfs_remove(qcow_data->dbgfs_dir);
}
#endif

static int qcow_file_fmt_init(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data;
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	struct loop_file_fmt_qcow_header header;
	u64 l1_vm_state_index;
	u64 l2_cache_size;
	u64 l2_cache_entry_size;
	ssize_t len;
	unsigned int i;
	int ret = 0;

	/* allocate memory for saving QCOW file format data */
	qcow_data = kzalloc(sizeof(*qcow_data), GFP_KERNEL);
	if (!qcow_data)
		return -ENOMEM;

	lo_fmt->private_data = qcow_data;

	/* read the QCOW file header */
	ret = __qcow_file_fmt_header_read(lo_fmt, &header);
	if (ret)
		goto free_qcow_data;

	/* save information of the header fields in human readable format in
	 * a file buffer to access it with debugfs */
#ifdef CONFIG_DEBUG_FS
	__qcow_file_fmt_header_to_buf(lo_fmt, &header);
#endif

	qcow_data->qcow_version = header.version;

	/* Initialise cluster size */
	if (header.cluster_bits < QCOW_MIN_CLUSTER_BITS
		|| header.cluster_bits > QCOW_MAX_CLUSTER_BITS) {
		printk(KERN_ERR "loop_file_fmt_qcow: unsupported cluster "
			"size: 2^%d", header.cluster_bits);
		ret = -EINVAL;
		goto free_qcow_data;
	}

	qcow_data->cluster_bits = header.cluster_bits;
	qcow_data->cluster_size = 1 << qcow_data->cluster_bits;
	qcow_data->cluster_sectors = 1 <<
		(qcow_data->cluster_bits - SECTOR_SHIFT);

	if (header.header_length > qcow_data->cluster_size) {
		printk(KERN_ERR "loop_file_fmt_qcow: QCOW header exceeds "
			"cluster size");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (header.backing_file_offset > qcow_data->cluster_size) {
		printk(KERN_ERR "loop_file_fmt_qcow: invalid backing file "
			"offset");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (header.backing_file_offset) {
		printk(KERN_ERR "loop_file_fmt_qcow: backing file support not "
			"available");
		ret = -ENOTSUPP;
		goto free_qcow_data;
	}

	/* handle feature bits */
	qcow_data->incompatible_features = header.incompatible_features;
	qcow_data->compatible_features = header.compatible_features;
	qcow_data->autoclear_features = header.autoclear_features;

	if (qcow_data->incompatible_features & QCOW_INCOMPAT_DIRTY) {
		printk(KERN_ERR "loop_file_fmt_qcow: image contains "
			"inconsistent refcounts");
		ret = -EACCES;
		goto free_qcow_data;
	}

	if (qcow_data->incompatible_features & QCOW_INCOMPAT_CORRUPT) {
		printk(KERN_ERR "loop_file_fmt_qcow: image is corrupt; cannot "
			"be opened read/write");
		ret = -EACCES;
		goto free_qcow_data;
	}

	if (qcow_data->incompatible_features & QCOW_INCOMPAT_DATA_FILE) {
		printk(KERN_ERR "loop_file_fmt_qcow: clusters in the external "
			"data file are not refcounted");
		ret = -EACCES;
		goto free_qcow_data;
	}

	/* Check support for various header values */
	if (header.refcount_order > 6) {
		printk(KERN_ERR "loop_file_fmt_qcow: reference count entry "
			"width too large; may not exceed 64 bits");
		ret = -EINVAL;
		goto free_qcow_data;
	}
	qcow_data->refcount_order = header.refcount_order;
	qcow_data->refcount_bits = 1 << qcow_data->refcount_order;
	qcow_data->refcount_max = U64_C(1) << (qcow_data->refcount_bits - 1);
	qcow_data->refcount_max += qcow_data->refcount_max - 1;

	qcow_data->crypt_method_header = header.crypt_method;
	if (qcow_data->crypt_method_header) {
		printk(KERN_ERR "loop_file_fmt_qcow: encryption support not "
			"available");
		ret = -ENOTSUPP;
		goto free_qcow_data;
	}

	/* L2 is always one cluster */
	qcow_data->l2_bits = qcow_data->cluster_bits - 3;
	qcow_data->l2_size = 1 << qcow_data->l2_bits;
	/* 2^(qcow_data->refcount_order - 3) is the refcount width in bytes */
	qcow_data->refcount_block_bits = qcow_data->cluster_bits -
		(qcow_data->refcount_order - 3);
	qcow_data->refcount_block_size = 1 << qcow_data->refcount_block_bits;
	qcow_data->size = header.size;
	qcow_data->csize_shift = (62 - (qcow_data->cluster_bits - 8));
	qcow_data->csize_mask = (1 << (qcow_data->cluster_bits - 8)) - 1;
	qcow_data->cluster_offset_mask = (1LL << qcow_data->csize_shift) - 1;

	qcow_data->refcount_table_offset = header.refcount_table_offset;
	qcow_data->refcount_table_size = header.refcount_table_clusters <<
		(qcow_data->cluster_bits - 3);

	if (header.refcount_table_clusters == 0) {
		printk(KERN_ERR "loop_file_fmt_qcow: image does not contain a "
			"reference count table");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	ret = __qcow_file_fmt_validate_table(lo_fmt,
		qcow_data->refcount_table_offset,
		header.refcount_table_clusters, qcow_data->cluster_size,
		QCOW_MAX_REFTABLE_SIZE, "Reference count table");
	if (ret < 0) {
		goto free_qcow_data;
	}

	/* The total size in bytes of the snapshot table is checked in
	 * qcow2_read_snapshots() because the size of each snapshot is
	 * variable and we don't know it yet.
	 * Here we only check the offset and number of snapshots. */
	ret = __qcow_file_fmt_validate_table(lo_fmt, header.snapshots_offset,
		header.nb_snapshots,
		sizeof(struct loop_file_fmt_qcow_snapshot_header),
		sizeof(struct loop_file_fmt_qcow_snapshot_header) *
		QCOW_MAX_SNAPSHOTS, "Snapshot table");
	if (ret < 0) {
		goto free_qcow_data;
	}

	/* read the level 1 table */
	ret = __qcow_file_fmt_validate_table(lo_fmt, header.l1_table_offset,
		header.l1_size, sizeof(u64), QCOW_MAX_L1_SIZE,
		"Active L1 table");
	if (ret < 0) {
		goto free_qcow_data;
	}
	qcow_data->l1_size = header.l1_size;
	qcow_data->l1_table_offset = header.l1_table_offset;

	l1_vm_state_index = loop_file_fmt_qcow_size_to_l1(qcow_data,
		header.size);
	if (l1_vm_state_index > INT_MAX) {
		printk(KERN_ERR "loop_file_fmt_qcow: image is too big");
		ret = -EFBIG;
		goto free_qcow_data;
	}
	qcow_data->l1_vm_state_index = l1_vm_state_index;

	/* the L1 table must contain at least enough entries to put header.size
	 * bytes */
	if (qcow_data->l1_size < qcow_data->l1_vm_state_index) {
		printk(KERN_ERR "loop_file_fmt_qcow: L1 table is too small");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (qcow_data->l1_size > 0) {
		qcow_data->l1_table = vzalloc(round_up(qcow_data->l1_size *
			sizeof(u64), 512));
		if (qcow_data->l1_table == NULL) {
			printk(KERN_ERR "loop_file_fmt_qcow: could not "
				"allocate L1 table");
			ret = -ENOMEM;
			goto free_qcow_data;
		}
		len = kernel_read(lo->lo_backing_file, qcow_data->l1_table,
			qcow_data->l1_size * sizeof(u64),
			&qcow_data->l1_table_offset);
		if (len < 0) {
			printk(KERN_ERR "loop_file_fmt_qcow: could not read L1 "
				"table");
			ret = len;
			goto free_l1_table;
		}
		for (i = 0; i < qcow_data->l1_size; i++) {
			qcow_data->l1_table[i] =
				be64_to_cpu(qcow_data->l1_table[i]);
		}
	}

	/* Internal snapshots */
	qcow_data->snapshots_offset = header.snapshots_offset;
	qcow_data->nb_snapshots = header.nb_snapshots;

	if (qcow_data->nb_snapshots > 0) {
		printk(KERN_ERR "loop_file_fmt_qcow: snapshots support not "
			"available");
		ret = -ENOTSUPP;
		goto free_l1_table;
	}


	/* create cache for L2 */
	l2_cache_size =  qcow_data->size / (qcow_data->cluster_size / 8);
	l2_cache_entry_size = min(qcow_data->cluster_size, (int)4096);

	/* limit the L2 size to maximum QCOW_DEFAULT_L2_CACHE_MAX_SIZE */
	l2_cache_size = min(l2_cache_size, (u64)QCOW_DEFAULT_L2_CACHE_MAX_SIZE);

	/* calculate the number of cache tables */
	l2_cache_size /= l2_cache_entry_size;
	if (l2_cache_size < QCOW_MIN_L2_CACHE_SIZE) {
		l2_cache_size = QCOW_MIN_L2_CACHE_SIZE;
	}

	if (l2_cache_size > INT_MAX) {
		printk(KERN_ERR "loop_file_fmt_qcow: L2 cache size too big");
		ret = -EINVAL;
		goto free_l1_table;
	}

	qcow_data->l2_slice_size = l2_cache_entry_size / sizeof(u64);

	qcow_data->l2_table_cache = loop_file_fmt_qcow_cache_create(lo_fmt,
		l2_cache_size, l2_cache_entry_size);
	if (!qcow_data->l2_table_cache) {
		ret = -ENOMEM;
		goto free_l1_table;
	}

	/* initialize compression support */
	ret = __qcow_file_fmt_compression_init(lo_fmt);
	if (ret < 0)
		goto free_l2_cache;

	/* initialize debugfs entries */
#ifdef CONFIG_DEBUG_FS
	ret = __qcow_file_fmt_dbgfs_init(lo_fmt);
	if (ret < 0)
		goto free_l2_cache;
#endif

	return ret;

free_l2_cache:
	loop_file_fmt_qcow_cache_destroy(lo_fmt);
free_l1_table:
	vfree(qcow_data->l1_table);
free_qcow_data:
	kfree(qcow_data);
	lo_fmt->private_data = NULL;
	return ret;
}

static void qcow_file_fmt_exit(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;

#ifdef CONFIG_DEBUG_FS
	__qcow_file_fmt_dbgfs_exit(lo_fmt);
#endif

	__qcow_file_fmt_compression_exit(lo_fmt);

	if (qcow_data->l1_table) {
		vfree(qcow_data->l1_table);
	}

	if (qcow_data->l2_table_cache) {
		loop_file_fmt_qcow_cache_destroy(lo_fmt);
	}

	if (qcow_data) {
		kfree(qcow_data);
		lo_fmt->private_data = NULL;
	}
}

static ssize_t __qcow_file_fmt_buffer_decompress(struct loop_file_fmt *lo_fmt,
						 void *dest,
						 size_t dest_size,
						 const void *src,
						 size_t src_size)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	int ret = 0;

	qcow_data->strm->avail_in = src_size;
	qcow_data->strm->next_in = (void *) src;
	qcow_data->strm->avail_out = dest_size;
	qcow_data->strm->next_out = dest;

	ret = zlib_inflateInit2(qcow_data->strm, -12);
	if (ret != Z_OK) {
		return -1;
	}

	ret = zlib_inflate(qcow_data->strm, Z_FINISH);
	if ((ret != Z_STREAM_END && ret != Z_BUF_ERROR)
		|| qcow_data->strm->avail_out != 0) {
		/* We approve Z_BUF_ERROR because we need @dest buffer to be
		 * filled, but @src buffer may be processed partly (because in
		 * qcow2 we know size of compressed data with precision of one
		 * sector) */
		ret = -1;
	}

	zlib_inflateEnd(qcow_data->strm);

	return ret;
}

static int __qcow_file_fmt_read_compressed(struct loop_file_fmt *lo_fmt,
					   struct bio_vec *bvec,
					   u64 file_cluster_offset,
					   u64 offset,
					   u64 bytes,
					   u64 bytes_done)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	int ret = 0, csize, nb_csectors;
	u64 coffset;
	u8 *in_buf, *out_buf;
	ssize_t len;
	void *data;
	unsigned long irq_flags;
	int offset_in_cluster = loop_file_fmt_qcow_offset_into_cluster(
		qcow_data, offset);

	coffset = file_cluster_offset & qcow_data->cluster_offset_mask;
	nb_csectors = ((file_cluster_offset >> qcow_data->csize_shift) &
		qcow_data->csize_mask) + 1;
	csize = nb_csectors * QCOW_COMPRESSED_SECTOR_SIZE -
		(coffset & ~QCOW_COMPRESSED_SECTOR_MASK);

	in_buf = vmalloc(csize);
	if (!in_buf) {
		return -ENOMEM;
	}

	out_buf = vmalloc(qcow_data->cluster_size);
	if (!out_buf) {
		ret = -ENOMEM;
		goto out_free_in_buf;
	}

	len = kernel_read(lo->lo_backing_file, in_buf, csize, &coffset);
	if (len < 0) {
		ret = len;
		goto out_free_out_buf;
	}

	if (__qcow_file_fmt_buffer_decompress(lo_fmt, out_buf,
		qcow_data->cluster_size, in_buf, csize) < 0) {
		ret = -EIO;
		goto out_free_out_buf;
	}

	ASSERT(bytes <= bvec->bv_len);
	data = bvec_kmap_irq(bvec, &irq_flags) + bytes_done;
	memcpy(data, out_buf + offset_in_cluster, bytes);
	flush_dcache_page(bvec->bv_page);
	bvec_kunmap_irq(data, &irq_flags);

out_free_out_buf:
	vfree(out_buf);
out_free_in_buf:
	vfree(in_buf);

	return ret;
}

static int __qcow_file_fmt_read_bvec(struct loop_file_fmt *lo_fmt,
				     struct bio_vec *bvec,
				     loff_t *ppos)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	int offset_in_cluster;
	int ret;
	unsigned int cur_bytes; /* number of bytes in current iteration */
	u64 bytes;
	u64 cluster_offset = 0;
	u64 bytes_done = 0;
	void *data;
	unsigned long irq_flags;
	ssize_t len;
	loff_t pos_read;

	bytes = bvec->bv_len;

	while (bytes != 0) {

		/* prepare next request */
		cur_bytes = bytes;

		ret = loop_file_fmt_qcow_cluster_get_offset(lo_fmt, *ppos,
			&cur_bytes, &cluster_offset);
		if (ret < 0) {
			goto fail;
		}

		offset_in_cluster = loop_file_fmt_qcow_offset_into_cluster(
			qcow_data, *ppos);

		switch (ret) {
		case QCOW_CLUSTER_UNALLOCATED:
		case QCOW_CLUSTER_ZERO_PLAIN:
		case QCOW_CLUSTER_ZERO_ALLOC:
			data = bvec_kmap_irq(bvec, &irq_flags) + bytes_done;
			memset(data, 0, cur_bytes);
			flush_dcache_page(bvec->bv_page);
			bvec_kunmap_irq(data, &irq_flags);
			break;

		case QCOW_CLUSTER_COMPRESSED:
			ret = __qcow_file_fmt_read_compressed(lo_fmt, bvec,
				cluster_offset, *ppos, cur_bytes, bytes_done);
			if (ret < 0) {
				goto fail;
			}

			break;

		case QCOW_CLUSTER_NORMAL:
			if ((cluster_offset & 511) != 0) {
				ret = -EIO;
				goto fail;
			}

			pos_read = cluster_offset + offset_in_cluster;

			data = bvec_kmap_irq(bvec, &irq_flags) + bytes_done;
			len = kernel_read(lo->lo_backing_file, data, cur_bytes,
				&pos_read);
			flush_dcache_page(bvec->bv_page);
			bvec_kunmap_irq(data, &irq_flags);

			if (len < 0)
				return len;

			break;

		default:
			ret = -EIO;
			goto fail;
		}

		bytes -= cur_bytes;
		*ppos += cur_bytes;
		bytes_done += cur_bytes;
	}

	ret = 0;

fail:
	return ret;
}

static int qcow_file_fmt_read(struct loop_file_fmt *lo_fmt,
			      struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	loff_t pos;
	int ret = 0;

	pos = __qcow_file_fmt_rq_get_pos(lo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		ret = __qcow_file_fmt_read_bvec(lo_fmt, &bvec, &pos);
		if (ret)
			return ret;

		cond_resched();
	}

	return ret;
}

static loff_t qcow_file_fmt_sector_size(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_qcow_data *qcow_data = lo_fmt->private_data;
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	loff_t loopsize;

	if (qcow_data->size > 0)
		loopsize = qcow_data->size;
	else
		return 0;

	if (lo->lo_offset > 0)
		loopsize -= lo->lo_offset;

	if (lo->lo_sizelimit > 0 && lo->lo_sizelimit < loopsize)
		loopsize = lo->lo_sizelimit;

	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return loopsize >> 9;
}

static struct loop_file_fmt_ops qcow_file_fmt_ops = {
	.init = qcow_file_fmt_init,
	.exit = qcow_file_fmt_exit,
	.read = qcow_file_fmt_read,
	.write = NULL,
	.read_aio = NULL,
	.write_aio = NULL,
	.discard = NULL,
	.flush = NULL,
	.sector_size = qcow_file_fmt_sector_size
};

static struct loop_file_fmt_driver qcow_file_fmt_driver = {
	.name = "QCOW",
	.file_fmt_type = LO_FILE_FMT_QCOW,
	.ops = &qcow_file_fmt_ops,
	.owner = THIS_MODULE
};

static int __init loop_file_fmt_qcow_init(void)
{
	printk(KERN_INFO "loop_file_fmt_qcow: init loop device QCOW file "
		"format driver");
	return loop_file_fmt_register_driver(&qcow_file_fmt_driver);
}

static void __exit loop_file_fmt_qcow_exit(void)
{
	printk(KERN_INFO "loop_file_fmt_qcow: exit loop device QCOW file "
		"format driver");
	loop_file_fmt_unregister_driver(&qcow_file_fmt_driver);
}

module_init(loop_file_fmt_qcow_init);
module_exit(loop_file_fmt_qcow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_DESCRIPTION("Loop device QCOW file format driver");
MODULE_SOFTDEP("pre: loop");
