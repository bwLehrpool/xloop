// SPDX-License-Identifier: GPL-2.0
/*
 * xloop_file_fmt_qcow.c
 *
 * QCOW file format driver for the xloop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>
#ifdef CONFIG_ZSTD_DECOMPRESS
#include <linux/zstd.h>
#endif
#include <linux/math64.h>

#include <xloop/version.h>

#include "xloop_file_fmt.h"
#include "xloop_file_fmt_qcow_main.h"
#include "xloop_file_fmt_qcow_cache.h"
#include "xloop_file_fmt_qcow_cluster.h"

#ifdef CONFIG_ZSTD_DECOMPRESS
#define ZSTD_WINDOWLOG_LIMIT_DEFAULT 27
#define ZSTD_MAXWINDOWSIZE ((U32_C(1) << ZSTD_WINDOWLOG_LIMIT_DEFAULT) + 1)

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
#define zstd_dstream_workspace_bound ZSTD_DStreamWorkspaceBound
#define zstd_init_dstream ZSTD_initDStream
#define zstd_reset_dstream ZSTD_resetDStream
#define zstd_decompress_stream ZSTD_decompressStream
#define zstd_is_error ZSTD_isError
#endif

#endif

typedef ssize_t (*qcow_file_fmt_decompress_fn)(struct xloop_file_fmt *xlo_fmt, void *dest, size_t dest_size,
					       const void *src, size_t src_size);

static int __qcow_file_fmt_header_read(struct xloop_file_fmt *xlo_fmt, struct file *file,
				       struct xloop_file_fmt_qcow_header *header)
{
	ssize_t len;
	loff_t offset;
	int ret = 0;

	/* read QCOW header */
	offset = 0;
	len = kernel_read(file, header, sizeof(*header), &offset);
	if (len < 0) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "could not read QCOW header\n");
		return len;
	}
	if (len != sizeof(*header)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "short read of QCOW header (%d/%d)\n",
				(int)len, (int)sizeof(*header));
		return -EIO;
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
	header->refcount_table_offset = be64_to_cpu(header->refcount_table_offset);
	header->refcount_table_clusters = be32_to_cpu(header->refcount_table_clusters);
	header->nb_snapshots = be32_to_cpu(header->nb_snapshots);
	header->snapshots_offset = be64_to_cpu(header->snapshots_offset);

	/* check QCOW file format and header version */
	if (header->magic != QCOW_MAGIC) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "image is not in QCOW format\n");
		return -EINVAL;
	}

	if (header->version < 2 || header->version > 3) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "unsupported QCOW version %d\n", header->version);
		return -ENOTSUPP;
	}

	/* initialize version 3 header fields */
	if (header->version == 2) {
		header->incompatible_features = 0;
		header->compatible_features = 0;
		header->autoclear_features = 0;
		header->refcount_order = 4;
		header->header_length = 72;
	} else {
		header->incompatible_features = be64_to_cpu(header->incompatible_features);
		header->compatible_features = be64_to_cpu(header->compatible_features);
		header->autoclear_features = be64_to_cpu(header->autoclear_features);
		header->refcount_order = be32_to_cpu(header->refcount_order);
		header->header_length = be32_to_cpu(header->header_length);

		if (header->header_length < 104) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "QCOW header too short\n");
			return -EINVAL;
		}
	}

	return ret;
}

static int __qcow_file_fmt_validate_table(struct xloop_file_fmt *xlo_fmt, u64 offset, u64 entries, size_t entry_len,
					  s64 max_size_bytes, const char *table_name)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	if (entries > div_s64(max_size_bytes, entry_len)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "%s too large\n", table_name);
		return -EFBIG;
	}

	/*
	 * Use signed S64_MAX as the maximum even for u64 header fields,
	 * because values will be passed to qemu functions taking s64.
	 */
	if ((S64_MAX - entries * entry_len < offset) ||
	    (xloop_file_fmt_qcow_offset_into_cluster(qcow_data, offset) != 0)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "%s offset invalid", table_name);
		return -EINVAL;
	}

	return 0;
}

static inline loff_t __qcow_file_fmt_rq_get_pos(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);

	return ((loff_t)blk_rq_pos(rq) << 9) + xlo->xlo_offset;
}

static int __qcow_file_fmt_compression_init(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	int ret = 0;
#ifdef CONFIG_ZSTD_DECOMPRESS
	size_t workspace_size;
#endif

	/* create workspace for ZLIB decompression stream */
	qcow_data->zlib_dstrm = kzalloc(sizeof(*qcow_data->zlib_dstrm), GFP_KERNEL);
	if (!qcow_data->zlib_dstrm) {
		ret = -ENOMEM;
		goto out;
	}

	qcow_data->zlib_dstrm->workspace = vzalloc(zlib_inflate_workspacesize());
	if (!qcow_data->zlib_dstrm->workspace) {
		ret = -ENOMEM;
		goto out_free_zlib_dstrm;
	}

	/* set up ZLIB decompression stream */
	ret = zlib_inflateInit2(qcow_data->zlib_dstrm, -12);
	if (ret != Z_OK) {
		ret = -EIO;
		goto out_free_zlib_dworkspace;
	}

#ifdef CONFIG_ZSTD_DECOMPRESS
	/* create workspace for ZSTD decompression stream */
	workspace_size = zstd_dstream_workspace_bound(ZSTD_MAXWINDOWSIZE);
	qcow_data->zstd_dworkspace = vzalloc(workspace_size);
	if (!qcow_data->zstd_dworkspace) {
		ret = -ENOMEM;
		goto out_free_zlib_dworkspace;
	}

	/* set up ZSTD decompression stream */
	qcow_data->zstd_dstrm = zstd_init_dstream(ZSTD_MAXWINDOWSIZE, qcow_data->zstd_dworkspace, workspace_size);
	if (!qcow_data->zstd_dstrm) {
		ret = -EINVAL;
		goto out_free_zstd_dworkspace;
	}
#endif

	/* create cache for last compressed QCOW cluster */
	qcow_data->cmp_last_coffset = ULLONG_MAX;
	qcow_data->cmp_last_size = 0;
	qcow_data->cmp_out_buf = vmalloc(qcow_data->cluster_size);
	if (!qcow_data->cmp_out_buf) {
		ret = -ENOMEM;
#ifdef CONFIG_ZSTD_DECOMPRESS
		goto out_free_zstd_dworkspace;
#else
		goto out_free_zlib_dworkspace;
#endif
	}

	mutex_init(&qcow_data->global_mutex);

	return ret;

#ifdef CONFIG_ZSTD_DECOMPRESS
out_free_zstd_dworkspace:
	vfree(qcow_data->zstd_dworkspace);
#endif
out_free_zlib_dworkspace:
	vfree(qcow_data->zlib_dstrm->workspace);
out_free_zlib_dstrm:
	kfree(qcow_data->zlib_dstrm);
out:
	return ret;
}

static void __qcow_file_fmt_compression_exit(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	mutex_destroy(&qcow_data->global_mutex);

	/* ZLIB specific cleanup */
	zlib_inflateEnd(qcow_data->zlib_dstrm);
	vfree(qcow_data->zlib_dstrm->workspace);
	kfree(qcow_data->zlib_dstrm);

	/* ZSTD specific cleanup */
#ifdef CONFIG_ZSTD_DECOMPRESS
	vfree(qcow_data->zstd_dworkspace);
#endif

	/* last compressed QCOW cluster cleanup */
	vfree(qcow_data->cmp_out_buf);
}

#ifdef CONFIG_DEBUG_FS
static void __qcow_file_fmt_header_to_buf(struct xloop_file_fmt *xlo_fmt,
					  const struct xloop_file_fmt_qcow_header *header)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	char *header_buf = qcow_data->dbgfs_file_qcow_header_buf;
	ssize_t len = 0;

	len += sprintf(header_buf + len, "magic: %d\n", header->magic);
	len += sprintf(header_buf + len, "version: %d\n", header->version);
	len += sprintf(header_buf + len, "backing_file_offset: %lld\n", header->backing_file_offset);
	len += sprintf(header_buf + len, "backing_file_size: %d\n", header->backing_file_size);
	len += sprintf(header_buf + len, "cluster_bits: %d\n", header->cluster_bits);
	len += sprintf(header_buf + len, "size: %lld\n", header->size);
	len += sprintf(header_buf + len, "crypt_method: %d\n", header->crypt_method);
	len += sprintf(header_buf + len, "l1_size: %d\n", header->l1_size);
	len += sprintf(header_buf + len, "l1_table_offset: %lld\n", header->l1_table_offset);
	len += sprintf(header_buf + len, "refcount_table_offset: %lld\n", header->refcount_table_offset);
	len += sprintf(header_buf + len, "refcount_table_clusters: %d\n", header->refcount_table_clusters);
	len += sprintf(header_buf + len, "nb_snapshots: %d\n", header->nb_snapshots);
	len += sprintf(header_buf + len, "snapshots_offset: %lld\n", header->snapshots_offset);

	if (header->version == 3) {
		len += sprintf(header_buf + len, "incompatible_features: %lld\n", header->incompatible_features);
		len += sprintf(header_buf + len, "compatible_features: %lld\n", header->compatible_features);
		len += sprintf(header_buf + len, "autoclear_features: %lld\n", header->autoclear_features);
		len += sprintf(header_buf + len, "refcount_order: %d\n", header->refcount_order);
		len += sprintf(header_buf + len, "header_length: %d\n", header->header_length);
	}

	if (header->header_length > offsetof(struct xloop_file_fmt_qcow_header, compression_type))
		len += sprintf(header_buf + len, "compression_type: %d\n", header->compression_type);

	ASSERT(len < QCOW_HEADER_BUF_LEN);
}

static ssize_t __qcow_file_fmt_dbgfs_hdr_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct xloop_file_fmt *xlo_fmt = file->private_data;
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	char *header_buf = qcow_data->dbgfs_file_qcow_header_buf;

	return simple_read_from_buffer(buf, size, ppos, header_buf, strlen(header_buf));
}

static const struct file_operations qcow_file_fmt_dbgfs_hdr_fops = { .open = simple_open,
								     .read = __qcow_file_fmt_dbgfs_hdr_read };

static ssize_t __qcow_file_fmt_dbgfs_ofs_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct xloop_file_fmt *xlo_fmt = file->private_data;
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	unsigned int cur_bytes = 1;
	u64 offset = 0;
	u64 coffset = 0;
	u64 host_offset = 0;
	s64 offset_in_cluster = 0;
	enum xloop_file_fmt_qcow_subcluster_type type;
	ssize_t len = 0;
	int ret = 0, csize = 0, nb_csectors = 0;

	/* read the share debugfs offset */
	ret = mutex_lock_interruptible(&qcow_data->dbgfs_qcow_offset_mutex);
	if (ret)
		return ret;

	offset = qcow_data->dbgfs_qcow_offset;
	mutex_unlock(&qcow_data->dbgfs_qcow_offset_mutex);

	/* calculate and print the cluster offset */
	mutex_lock(&qcow_data->global_mutex);
	ret = xloop_file_fmt_qcow_get_host_offset(xlo_fmt, offset, &cur_bytes, &host_offset, &type);
	mutex_unlock(&qcow_data->global_mutex);
	if (ret)
		return -EINVAL;

	offset_in_cluster = xloop_file_fmt_qcow_offset_into_cluster(qcow_data, offset);

	len = sprintf(qcow_data->dbgfs_file_qcow_cluster_buf,
		      "cluster type: %s\n"
		      "cluster offset host: %lld\n"
		      "cluster offset guest: %lld\n"
		      "cluster offset in-cluster: %lld\n",
		      xloop_file_fmt_qcow_get_subcluster_name(type), host_offset, offset, offset_in_cluster);

	if (type == QCOW_SUBCLUSTER_COMPRESSED) {
		coffset = host_offset & qcow_data->cluster_offset_mask;
		nb_csectors = ((host_offset >> qcow_data->csize_shift) & qcow_data->csize_mask) + 1;
		csize = nb_csectors * QCOW_COMPRESSED_SECTOR_SIZE - (coffset & ~QCOW_COMPRESSED_SECTOR_MASK);

		len += sprintf(qcow_data->dbgfs_file_qcow_cluster_buf + len,
			       "cluster compressed offset: %lld\n"
			       "cluster compressed sectors: %d\n"
			       "cluster compressed size: %d\n",
			       coffset, nb_csectors, csize);
	}

	ASSERT(len < QCOW_CLUSTER_BUF_LEN);

	return simple_read_from_buffer(buf, size, ppos, qcow_data->dbgfs_file_qcow_cluster_buf, len);
}

static ssize_t __qcow_file_fmt_dbgfs_ofs_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	struct xloop_file_fmt *xlo_fmt = file->private_data;
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	ssize_t len = 0;
	int ret = 0;

	if (*ppos > QCOW_OFFSET_BUF_LEN || size > QCOW_OFFSET_BUF_LEN)
		return -EINVAL;

	len = simple_write_to_buffer(qcow_data->dbgfs_file_qcow_offset_buf, QCOW_OFFSET_BUF_LEN, ppos, buf, size);
	if (len < 0)
		return len;

	qcow_data->dbgfs_file_qcow_offset_buf[len] = '\0';

	ret = mutex_lock_interruptible(&qcow_data->dbgfs_qcow_offset_mutex);
	if (ret)
		return ret;

	ret = kstrtou64(qcow_data->dbgfs_file_qcow_offset_buf, 10, &qcow_data->dbgfs_qcow_offset);
	if (ret < 0)
		goto out;

	ret = len;
out:
	mutex_unlock(&qcow_data->dbgfs_qcow_offset_mutex);
	return ret;
}

static const struct file_operations qcow_file_fmt_dbgfs_ofs_fops = { .open = simple_open,
								     .read = __qcow_file_fmt_dbgfs_ofs_read,
								     .write = __qcow_file_fmt_dbgfs_ofs_write };

static int __qcow_file_fmt_dbgfs_init(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	int ret = 0;

	qcow_data->dbgfs_dir = debugfs_create_dir("QCOW", xlo->xlo_dbgfs_dir);
	if (IS_ERR_OR_NULL(qcow_data->dbgfs_dir)) {
		ret = -ENODEV;
		goto out;
	}

	qcow_data->dbgfs_file_qcow_header =
		debugfs_create_file("header", 0444, qcow_data->dbgfs_dir, xlo_fmt, &qcow_file_fmt_dbgfs_hdr_fops);
	if (IS_ERR_OR_NULL(qcow_data->dbgfs_file_qcow_header)) {
		ret = -ENODEV;
		goto out_free_dbgfs_dir;
	}

	qcow_data->dbgfs_file_qcow_offset = debugfs_create_file("offset", 0644, qcow_data->dbgfs_dir,
								xlo_fmt, &qcow_file_fmt_dbgfs_ofs_fops);
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

static void __qcow_file_fmt_dbgfs_exit(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	debugfs_remove(qcow_data->dbgfs_file_qcow_offset);

	mutex_destroy(&qcow_data->dbgfs_qcow_offset_mutex);

	debugfs_remove(qcow_data->dbgfs_file_qcow_header);

	debugfs_remove(qcow_data->dbgfs_dir);
}
#endif

static int __qcow_file_fmt_validate_compression_type(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

	switch (qcow_data->compression_type) {
	case QCOW_COMPRESSION_TYPE_ZLIB:
#ifdef CONFIG_ZSTD_DECOMPRESS
	case QCOW_COMPRESSION_TYPE_ZSTD:
#endif
		break;
	default:
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "unknown compression type: %u", qcow_data->compression_type);
		return -ENOTSUPP;
	}

	/*
	 * if the compression type differs from QCOW_COMPRESSION_TYPE_ZLIB
	 * the incompatible feature flag must be set
	 */
	if (qcow_data->compression_type == QCOW_COMPRESSION_TYPE_ZLIB) {
		if (qcow_data->incompatible_features & QCOW_INCOMPAT_COMPRESSION) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt),
				"compression type incompatible feature bit must not be set\n");
			return -EINVAL;
		}
	} else {
		if (!(qcow_data->incompatible_features & QCOW_INCOMPAT_COMPRESSION)) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt),
				"compression type incompatible feature bit must be set\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int qcow_file_fmt_init(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data;
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct xloop_file_fmt_qcow_header header;
	u64 l1_vm_state_index;
	u64 l2_cache_size;
	u64 l2_cache_entry_size;
	u64 virtual_disk_size;
	u64 max_l2_entries;
	u64 max_l2_cache;
	u64 l2_cache_max_setting;
	ssize_t len;
	unsigned int i;
	int ret = 0;

	/* allocate memory for saving QCOW file format data */
	qcow_data = kzalloc(sizeof(*qcow_data), GFP_KERNEL);
	if (!qcow_data)
		return -ENOMEM;

	xlo_fmt->private_data = qcow_data;

	/* read the QCOW file header */
	ret = __qcow_file_fmt_header_read(xlo_fmt, xlo->xlo_backing_file, &header);
	if (ret)
		goto free_qcow_data;

	/*
	 * save information of the header fields in human readable format in
	 * a file buffer to access it with debugfs
	 */
#ifdef CONFIG_DEBUG_FS
	__qcow_file_fmt_header_to_buf(xlo_fmt, &header);
#endif

	qcow_data->qcow_version = header.version;

	/* Initialise cluster size */
	if (header.cluster_bits < QCOW_MIN_CLUSTER_BITS || header.cluster_bits > QCOW_MAX_CLUSTER_BITS) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "unsupported cluster size: 2^%d\n", header.cluster_bits);
		ret = -EINVAL;
		goto free_qcow_data;
	}

	qcow_data->cluster_bits = header.cluster_bits;
	qcow_data->cluster_size = 1 << qcow_data->cluster_bits;

	if (header.header_length > qcow_data->cluster_size) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "QCOW header exceeds cluster size\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (header.backing_file_offset > qcow_data->cluster_size) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "invalid backing file offset\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (header.backing_file_offset) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "backing file support not available\n");
		ret = -ENOTSUPP;
		goto free_qcow_data;
	}

	/* handle feature bits */
	qcow_data->incompatible_features = header.incompatible_features;
	qcow_data->compatible_features = header.compatible_features;
	qcow_data->autoclear_features = header.autoclear_features;

	/*
	 * Handle compression type
	 * Older qcow2 images don't contain the compression type header.
	 * Distinguish them by the header length and use
	 * the only valid (default) compression type in that case
	 */
	if (header.header_length > offsetof(struct xloop_file_fmt_qcow_header, compression_type))
		qcow_data->compression_type = header.compression_type;
	else
		qcow_data->compression_type = QCOW_COMPRESSION_TYPE_ZLIB;

	ret = __qcow_file_fmt_validate_compression_type(xlo_fmt);
	if (ret)
		goto free_qcow_data;

	/* check for incompatible features */
	if (qcow_data->incompatible_features & QCOW_INCOMPAT_DIRTY) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "image contains inconsistent refcounts\n");
		ret = -EACCES;
		goto free_qcow_data;
	}

	if (qcow_data->incompatible_features & QCOW_INCOMPAT_CORRUPT) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "image is corrupt; cannot be opened read/write\n");
		ret = -EACCES;
		goto free_qcow_data;
	}

	if (qcow_data->incompatible_features & QCOW_INCOMPAT_DATA_FILE) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "data-file is required for this image\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	qcow_data->subclusters_per_cluster =
		xloop_file_fmt_qcow_has_subclusters(qcow_data) ? QCOW_EXTL2_SUBCLUSTERS_PER_CLUSTER : 1;
	qcow_data->subcluster_size = qcow_data->cluster_size / qcow_data->subclusters_per_cluster;
	/*
	 * check if subcluster_size is non-zero to avoid unknown results of
	 * __builtin_ctz
	 */
	ASSERT(qcow_data->subcluster_size != 0);
	qcow_data->subcluster_bits = __builtin_ctz(qcow_data->subcluster_size);

	if (qcow_data->subcluster_size < (1 << QCOW_MIN_CLUSTER_BITS)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "unsupported subcluster size: %d\n",
			qcow_data->subcluster_size);
		ret = -EINVAL;
		goto free_qcow_data;
	}

	/* Check support for various header values */
	if (header.refcount_order > 6) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt),
			"reference count entry width too large; may not exceed 64 bits\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}
	qcow_data->refcount_order = header.refcount_order;
	qcow_data->refcount_bits = 1 << qcow_data->refcount_order;
	qcow_data->refcount_max = U64_C(1) << (qcow_data->refcount_bits - 1);
	qcow_data->refcount_max += qcow_data->refcount_max - 1;

	qcow_data->crypt_method_header = header.crypt_method;
	if (qcow_data->crypt_method_header) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "encryption support not available\n");
		ret = -ENOTSUPP;
		goto free_qcow_data;
	}

	/*
	 * check if xloop_file_fmt_qcow_l2_entry_size(qcow_data) is non-zero to
	 * avoid unknown results of __builtin_ctz
	 */
	ASSERT(xloop_file_fmt_qcow_l2_entry_size(qcow_data) != 0);
	qcow_data->l2_bits = qcow_data->cluster_bits - __builtin_ctz(xloop_file_fmt_qcow_l2_entry_size(qcow_data));
	qcow_data->l2_size = 1 << qcow_data->l2_bits;
	/* 2^(qcow_data->refcount_order - 3) is the refcount width in bytes */
	qcow_data->refcount_block_bits = qcow_data->cluster_bits - (qcow_data->refcount_order - 3);
	qcow_data->refcount_block_size = 1 << qcow_data->refcount_block_bits;
	qcow_data->size = header.size;
	qcow_data->csize_shift = (62 - (qcow_data->cluster_bits - 8));
	qcow_data->csize_mask = (1 << (qcow_data->cluster_bits - 8)) - 1;
	qcow_data->cluster_offset_mask = (1LL << qcow_data->csize_shift) - 1;

	qcow_data->refcount_table_offset = header.refcount_table_offset;
	qcow_data->refcount_table_size = header.refcount_table_clusters << (qcow_data->cluster_bits - 3);

	if (header.refcount_table_clusters == 0) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "image does not contain a reference count table\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	ret = __qcow_file_fmt_validate_table(xlo_fmt, qcow_data->refcount_table_offset, header.refcount_table_clusters,
					     qcow_data->cluster_size, QCOW_MAX_REFTABLE_SIZE, "Reference count table");
	if (ret < 0)
		goto free_qcow_data;

	/*
	 * The total size in bytes of the snapshot table is checked in
	 * qcow2_read_snapshots() because the size of each snapshot is
	 * variable and we don't know it yet.
	 * Here we only check the offset and number of snapshots.
	 */
	ret = __qcow_file_fmt_validate_table(xlo_fmt, header.snapshots_offset, header.nb_snapshots,
					     sizeof(struct xloop_file_fmt_qcow_snapshot_header),
					     sizeof(struct xloop_file_fmt_qcow_snapshot_header) * QCOW_MAX_SNAPSHOTS,
					     "Snapshot table");
	if (ret < 0)
		goto free_qcow_data;

	/* read the level 1 table */
	ret = __qcow_file_fmt_validate_table(xlo_fmt, header.l1_table_offset, header.l1_size, QCOW_L1E_SIZE,
					     QCOW_MAX_L1_SIZE, "Active L1 table");
	if (ret < 0)
		goto free_qcow_data;

	qcow_data->l1_size = header.l1_size;
	qcow_data->l1_table_offset = header.l1_table_offset;

	l1_vm_state_index = xloop_file_fmt_qcow_size_to_l1(qcow_data, header.size);
	if (l1_vm_state_index > INT_MAX) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "image is too big\n");
		ret = -EFBIG;
		goto free_qcow_data;
	}
	qcow_data->l1_vm_state_index = l1_vm_state_index;

	/* the L1 table must contain at least enough entries to put header.size bytes */
	if (qcow_data->l1_size < qcow_data->l1_vm_state_index) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "L1 table is too small\n");
		ret = -EINVAL;
		goto free_qcow_data;
	}

	if (qcow_data->l1_size > 0) {
		const int read_size = qcow_data->l1_size * QCOW_L1E_SIZE;
		qcow_data->l1_table = vzalloc(round_up(qcow_data->l1_size * QCOW_L1E_SIZE, 512));
		if (qcow_data->l1_table == NULL) {
			ret = -ENOMEM;
			goto free_qcow_data;
		}
		len = kernel_read(xlo->xlo_backing_file, qcow_data->l1_table, read_size, &qcow_data->l1_table_offset);
		if (len < 0) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "could not read L1 table\n");
			ret = len;
			goto free_l1_table;
		}
		if (len != read_size) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "short read in L1 table (%d/%d)\n",
					(int)len, read_size);
			ret = -EIO;
			goto free_l1_table;
		}
		for (i = 0; i < qcow_data->l1_size; i++)
			qcow_data->l1_table[i] = be64_to_cpu(qcow_data->l1_table[i]);
	}

	/* Internal snapshots */
	qcow_data->snapshots_offset = header.snapshots_offset;
	qcow_data->nb_snapshots = header.nb_snapshots;

	if (qcow_data->nb_snapshots > 0) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "snapshots support not available\n");
		ret = -ENOTSUPP;
		goto free_l1_table;
	}

	/* create cache for L2 */
	virtual_disk_size = qcow_data->size;
	max_l2_entries = DIV64_U64_ROUND_UP(virtual_disk_size, qcow_data->cluster_size);
	max_l2_cache = round_up(max_l2_entries * xloop_file_fmt_qcow_l2_entry_size(qcow_data), qcow_data->cluster_size);

	/* define the maximum L2 cache size */
	l2_cache_max_setting = QCOW_DEFAULT_L2_CACHE_MAX_SIZE;

	/* limit the L2 cache size to maximum l2_cache_max_setting */
	l2_cache_size = min(max_l2_cache, l2_cache_max_setting);

	/* determine the size of a cache entry */
	l2_cache_entry_size = min_t(int, qcow_data->cluster_size, PAGE_SIZE);

	/* calculate the number of cache tables */
	l2_cache_size = div_u64(l2_cache_size, l2_cache_entry_size);
	if (l2_cache_size < QCOW_MIN_L2_CACHE_SIZE)
		l2_cache_size = QCOW_MIN_L2_CACHE_SIZE;

	if (l2_cache_size > INT_MAX) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "L2 cache size too big\n");
		ret = -EINVAL;
		goto free_l1_table;
	}

	qcow_data->l2_slice_size = div_u64(l2_cache_entry_size, xloop_file_fmt_qcow_l2_entry_size(qcow_data));

	qcow_data->l2_table_cache = xloop_file_fmt_qcow_cache_create(xlo_fmt, l2_cache_size, l2_cache_entry_size);
	if (!qcow_data->l2_table_cache) {
		ret = -ENOMEM;
		goto free_l1_table;
	}

	/* initialize compression support */
	ret = __qcow_file_fmt_compression_init(xlo_fmt);
	if (ret < 0)
		goto free_l2_cache;

	/* initialize debugfs entries */
#ifdef CONFIG_DEBUG_FS
	ret = __qcow_file_fmt_dbgfs_init(xlo_fmt);
	if (ret < 0)
		goto free_l2_cache;
#endif

	return ret;

free_l2_cache:
	xloop_file_fmt_qcow_cache_destroy(xlo_fmt);
free_l1_table:
	vfree(qcow_data->l1_table);
free_qcow_data:
	kfree(qcow_data);
	xlo_fmt->private_data = NULL;
	return ret;
}

static void qcow_file_fmt_exit(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;

#ifdef CONFIG_DEBUG_FS
	__qcow_file_fmt_dbgfs_exit(xlo_fmt);
#endif

	__qcow_file_fmt_compression_exit(xlo_fmt);

	if (qcow_data->l1_table)
		vfree(qcow_data->l1_table);

	if (qcow_data->l2_table_cache)
		xloop_file_fmt_qcow_cache_destroy(xlo_fmt);

	kfree(qcow_data);
	xlo_fmt->private_data = NULL;
}

/*
 * __qcow_file_fmt_zlib_decompress()
 *
 * Decompress some data (not more than @src_size bytes) to produce exactly
 * @dest_size bytes using zlib compression method
 *
 * @xlo_fmt - QCOW file format
 * @dest - destination buffer, @dest_size bytes
 * @src - source buffer, @src_size bytes
 *
 * Returns: actual decompressed bytes on success
 *          -EIO on fail
 */
static ssize_t __qcow_file_fmt_zlib_decompress(struct xloop_file_fmt *xlo_fmt, void *dest, size_t dest_size,
					       const void *src, size_t src_size)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	u8 zerostuff = 0;
	int ret;

	ret = zlib_inflateReset(qcow_data->zlib_dstrm);
	if (ret != Z_OK) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zlib reset error: %d\n", (int)ret);
		ret = -EINVAL;
		goto out;
	}

	qcow_data->zlib_dstrm->avail_in = src_size;
	qcow_data->zlib_dstrm->next_in = (void *)src;
	qcow_data->zlib_dstrm->avail_out = dest_size;
	qcow_data->zlib_dstrm->next_out = dest;

	ret = zlib_inflate(qcow_data->zlib_dstrm, Z_SYNC_FLUSH);
	/*
	 * Work around a bug in zlib, which sometimes wants to taste an extra
	 * byte when being used in the (undocumented) raw deflate mode.
	 * (From USAGI).
	 */
	if (ret == Z_OK && !qcow_data->zlib_dstrm->avail_in && qcow_data->zlib_dstrm->avail_out) {
		qcow_data->zlib_dstrm->next_in = &zerostuff;
		qcow_data->zlib_dstrm->avail_in = 1;
		ret = zlib_inflate(qcow_data->zlib_dstrm, Z_FINISH);
	}
	if (ret != Z_STREAM_END) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zlib inflate error: %d\n", (int)ret);
		ret = -EIO;
		goto out;
	}
	ret = dest_size - qcow_data->zlib_dstrm->avail_out;

out:
	return ret;
}

#ifdef CONFIG_ZSTD_DECOMPRESS
/*
 * __qcow_file_fmt_zstd_decompress()
 *
 * Decompress some data (not more than @src_size bytes) to produce exactly
 * @dest_size bytes using zstd compression method
 *
 * @xlo_fmt - QCOW file format
 * @dest - destination buffer, @dest_size bytes
 * @src - source buffer, @src_size bytes
 *
 * Returns: actual decompressed bytes on success
 *          -EIO on any error
 */
static ssize_t __qcow_file_fmt_zstd_decompress(struct xloop_file_fmt *xlo_fmt, void *dest, size_t dest_size,
					       const void *src, size_t src_size)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	size_t zstd_ret = 0;
	ssize_t ret = 0;

	ZSTD_outBuffer output = { .dst = dest, .size = dest_size, .pos = 0 };

	ZSTD_inBuffer input = { .src = src, .size = src_size, .pos = 0 };

	zstd_ret = zstd_reset_dstream(qcow_data->zstd_dstrm);

	if (zstd_is_error(zstd_ret)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zstd reset error: %d\n", (int)zstd_ret);
		ret = -EINVAL;
		goto out;
	}

	/*
	 * The compressed stream from the input buffer may consist of more
	 * than one zstd frame. So we iterate until we get a fully
	 * uncompressed cluster.
	 * From zstd docs related to ZSTD_decompressStream:
	 * "return : 0 when a frame is completely decoded and fully flushed"
	 * We suppose that this means: each time ZSTD_decompressStream reads
	 * only ONE full frame and returns 0 if and only if that frame
	 * is completely decoded and flushed. Only after returning 0,
	 * ZSTD_decompressStream reads another ONE full frame.
	 */
	while (output.pos < output.size) {
		size_t last_in_pos = input.pos;
		size_t last_out_pos = output.pos;

		zstd_ret = zstd_decompress_stream(qcow_data->zstd_dstrm, &output, &input);

		if (zstd_is_error(zstd_ret))
			break;

	/*
	 * The ZSTD manual is vague about what to do if it reads
	 * the buffer partially, and we don't want to get stuck
	 * in an infinite loop where ZSTD_decompressStream
	 * returns > 0 waiting for another input chunk. So, we add
	 * a check which ensures that the loop makes some progress
	 * on each step.
	 */
		if (last_in_pos >= input.pos && last_out_pos >= output.pos) {
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zstd not making any progress\n");
			ret = -EIO;
			goto out;
		}
	}
	/*
	 * Make sure that we have the frame fully flushed here
	 * if not, we somehow managed to get uncompressed cluster
	 * greater then the cluster size, possibly because of its
	 * damage.
	 */
	if (zstd_is_error(zstd_ret)) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zstd decompress error: %d\n", (int)zstd_ret);
		ret = -EIO;
	} if (zstd_ret) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "zstd incomplete frame at end of cluster\n");
		ret = -EIO;
	} else {
		ret = output.pos;
	}

out:
	return ret;
}
#endif

/*
 * __qcow_file_fmt_buffer_decompress()
 *
 * Decompress @src_size bytes of data using the compression
 * method defined by the image compression type
 *
 * @xlo_fmt - QCOW file format
 * @dest - destination buffer, @dest_size bytes
 * @src - source buffer, @src_size bytes
 *
 * Returns: actual decompressed size on success
 *          a negative error code on failure
 */
static ssize_t __qcow_file_fmt_buffer_decompress(struct xloop_file_fmt *xlo_fmt, void *dest, size_t dest_size,
						 const void *src, size_t src_size)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	qcow_file_fmt_decompress_fn decompress_fn;

	switch (qcow_data->compression_type) {
	case QCOW_COMPRESSION_TYPE_ZLIB:
		decompress_fn = __qcow_file_fmt_zlib_decompress;
		break;

#ifdef CONFIG_ZSTD_DECOMPRESS
	case QCOW_COMPRESSION_TYPE_ZSTD:
		decompress_fn = __qcow_file_fmt_zstd_decompress;
		break;
#endif
	default:
		return -EINVAL;
	}

	return decompress_fn(xlo_fmt, dest, dest_size, src, src_size);
}

/*
 * __qcow_file_fmt_read_compressed()
 *
 * Decompress @bytes of data starting at virtual @offset
 * using the compression method defined by the image
 * compression type and write them to @bvec
 *
 * @xlo_fmt - QCOW file format
 * @bvec - io vector to write uncompressed data to
 * @file_cluster_offset - offset to compressed cluster in qcow2
 * @offset - virtual offset, as seen on loop device
 * @bytes - number of bytes to read
 * @bytes_done - how many bytes are actually already finished (when called after partial read)
 *
 * Returns: actual decompressed size on success
 *          a negative error code on failure
 */
static int __qcow_file_fmt_read_compressed(struct xloop_file_fmt *xlo_fmt, struct bio_vec *bvec,
					   u64 file_cluster_offset, u64 offset, u64 bytes, u64 bytes_done)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	int ret;
	u64 coffset;
	u8 *in_buf = NULL;
	ssize_t len;
	void *data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	unsigned long irq_flags;
#endif
	int offset_in_cluster = xloop_file_fmt_qcow_offset_into_cluster(qcow_data, offset);

	coffset = file_cluster_offset & qcow_data->cluster_offset_mask;

	if (qcow_data->cmp_last_coffset != coffset) {
		int csize, nb_csectors;

		nb_csectors = ((file_cluster_offset >> qcow_data->csize_shift) & qcow_data->csize_mask) + 1;
		csize = nb_csectors * QCOW_COMPRESSED_SECTOR_SIZE - (coffset & ~QCOW_COMPRESSED_SECTOR_MASK);
		in_buf = vmalloc(csize);
		if (!in_buf) {
			qcow_data->cmp_last_coffset = ULLONG_MAX;
			return -ENOMEM;
		}
		qcow_data->cmp_last_coffset = coffset;
		len = kernel_read(xlo->xlo_backing_file, in_buf, csize, &coffset);
		if (len < 0) {
			qcow_data->cmp_last_coffset = ULLONG_MAX;
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "error %d reading compressed cluster at %llu\n",
					(int)len, coffset);
			ret = len;
			goto out_free_in_buf;
		}
		if (len != csize) {
			qcow_data->cmp_last_coffset = ULLONG_MAX;
			dev_err(xloop_file_fmt_to_dev(xlo_fmt), "short read in compressed cluster at %llu (%d/%d)\n",
					coffset, (int)len, csize);
			ret = -EIO;
			goto out_free_in_buf;
		}

		ret = __qcow_file_fmt_buffer_decompress(xlo_fmt, qcow_data->cmp_out_buf,
				qcow_data->cluster_size, in_buf, csize);
		if (ret <= 0) {
			qcow_data->cmp_last_coffset = ULLONG_MAX;
			if (ret == 0) {
				dev_err(xloop_file_fmt_to_dev(xlo_fmt), "decompressed cluster at %llu is empty\n",
					coffset);
				ret = -EIO;
			}
			goto out_free_in_buf;
		}
		qcow_data->cmp_last_size = ret;
	}

	if (offset_in_cluster + bytes > qcow_data->cmp_last_size) {
		dev_err(xloop_file_fmt_to_dev(xlo_fmt), "read %d bytes from compressed cluster of size %d\n",
			(int)(offset_in_cluster + bytes), qcow_data->cmp_last_size);
		ret = -EIO;
		goto out_free_in_buf;
	}

	ASSERT(bytes <= bvec->bv_len);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	data = bvec_kmap_local(bvec);
#else
	data = bvec_kmap_irq(bvec, &irq_flags);
#endif
	memcpy(data + bytes_done, qcow_data->cmp_out_buf + offset_in_cluster, bytes);
	flush_dcache_page(bvec->bv_page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
	kunmap_local(data);
#else
	bvec_kunmap_irq(data, &irq_flags);
#endif
	ret = bytes;

out_free_in_buf:
	vfree(in_buf);

	return ret;
}

static int __qcow_file_fmt_read_bvec(struct xloop_file_fmt *xlo_fmt, struct bio_vec *bvec, loff_t *ppos)
{
	struct xloop_file_fmt_qcow_data *qcow_data = xlo_fmt->private_data;
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	int ret;
	unsigned int cur_bytes; /* number of bytes in current iteration */
	u64 bytes;
	u64 host_offset = 0;
	u64 bytes_done = 0;
	enum xloop_file_fmt_qcow_subcluster_type type;
	void *data;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
	unsigned long irq_flags;
#endif
	ssize_t len;
	loff_t pos_read;

	/* bvec_kmap expects the passed bvec to only contain a single page */
	ASSERT(bvec->bv_len <= PAGE_SIZE);
	bytes = bvec->bv_len;

	while (bytes != 0) {
		/* prepare next request. if this spans a cluster boundary, this will be clamped */
		cur_bytes = bytes;

		mutex_lock(&qcow_data->global_mutex);
		ret = xloop_file_fmt_qcow_get_host_offset(xlo_fmt, *ppos, &cur_bytes, &host_offset, &type);
		mutex_unlock(&qcow_data->global_mutex);
		if (ret)
			goto fail;

		switch (type) {
		case QCOW_SUBCLUSTER_ZERO_PLAIN:
		case QCOW_SUBCLUSTER_ZERO_ALLOC:
		case QCOW_SUBCLUSTER_UNALLOCATED_PLAIN:
		case QCOW_SUBCLUSTER_UNALLOCATED_ALLOC:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
			data = bvec_kmap_local(bvec);
#else
			data = bvec_kmap_irq(bvec, &irq_flags);
#endif
			memset(data + bytes_done, 0, cur_bytes);
			flush_dcache_page(bvec->bv_page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
			kunmap_local(data);
#else
			bvec_kunmap_irq(data, &irq_flags);
#endif
			break;

		case QCOW_SUBCLUSTER_COMPRESSED:
			mutex_lock(&qcow_data->global_mutex);
			ret = __qcow_file_fmt_read_compressed(xlo_fmt, bvec, host_offset, *ppos, cur_bytes, bytes_done);
			mutex_unlock(&qcow_data->global_mutex);
			if (ret < 0)
				goto fail;
			if (len == 0) {
				dev_err(xloop_file_fmt_to_dev(xlo_fmt), "Unexpected empty read in compressed cluster\n");
				ret = -EIO;
				goto fail;
			}
			cur_bytes = ret;

			break;

		case QCOW_SUBCLUSTER_NORMAL:
			pos_read = host_offset;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
			data = bvec_kmap_local(bvec);
#else
			data = bvec_kmap_irq(bvec, &irq_flags);
#endif
			len = kernel_read(xlo->xlo_backing_file, data + bytes_done, cur_bytes, &pos_read);
			flush_dcache_page(bvec->bv_page);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
			kunmap_local(data);
#else
			bvec_kunmap_irq(data, &irq_flags);
#endif

			if (len < 0) {
				dev_err(xloop_file_fmt_to_dev(xlo_fmt), "Read error in uncompressed cluster\n");
				ret = len;
				goto fail;
			}

			if (len == 0) {
				dev_err(xloop_file_fmt_to_dev(xlo_fmt), "Premature EOF when reading uncompressed cluster\n");
				ret = -EIO;
				goto fail;
			}
			cur_bytes = len;
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

static int qcow_file_fmt_read(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	loff_t pos;
	int ret = 0;

	pos = __qcow_file_fmt_rq_get_pos(xlo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		ret = __qcow_file_fmt_read_bvec(xlo_fmt, &bvec, &pos);
		if (ret)
			return ret;

		cond_resched();
	}

	return ret;
}

static loff_t qcow_file_fmt_sector_size(struct xloop_file_fmt *xlo_fmt, struct file *file, loff_t offset,
					loff_t sizelimit)
{
	struct xloop_file_fmt_qcow_header header;
	loff_t xloopsize;
	int ret;

	/* temporary read the QCOW file header of other QCOW image file */
	ret = __qcow_file_fmt_header_read(xlo_fmt, file, &header);
	if (ret)
		return 0;

	/* compute xloopsize in bytes */
	xloopsize = header.size;
	if (offset > 0)
		xloopsize -= offset;
	/* offset is beyond i_size, weird but possible */
	if (xloopsize < 0)
		return 0;

	if (sizelimit > 0 && sizelimit < xloopsize)
		xloopsize = sizelimit;
	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return xloopsize >> 9;
}

static struct xloop_file_fmt_ops qcow_file_fmt_ops = {
	.init        = qcow_file_fmt_init,
	.exit        = qcow_file_fmt_exit,
	.read        = qcow_file_fmt_read,
	.write       = NULL,
	.read_aio    = NULL,
	.write_aio   = NULL,
	.write_zeros = NULL,
	.discard     = NULL,
	.flush       = NULL,
	.sector_size = qcow_file_fmt_sector_size,
};

static struct xloop_file_fmt_driver qcow_file_fmt_driver = {
	.name          = "QCOW",
	.file_fmt_type = XLO_FILE_FMT_QCOW,
	.ops           = &qcow_file_fmt_ops,
	.owner         = THIS_MODULE,
};

static int __init xloop_file_fmt_qcow_init(void)
{
	pr_info("init xloop device QCOW file format driver\n");
	return xloop_file_fmt_register_driver(&qcow_file_fmt_driver);
}

static void __exit xloop_file_fmt_qcow_exit(void)
{
	pr_info("exit xloop device QCOW file format driver\n");
	xloop_file_fmt_unregister_driver(&qcow_file_fmt_driver);
}

module_init(xloop_file_fmt_qcow_init);
module_exit(xloop_file_fmt_qcow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_DESCRIPTION("xloop device QCOW file format driver");
MODULE_SOFTDEP("pre: xloop");
MODULE_VERSION(XLOOP_VERSION);
