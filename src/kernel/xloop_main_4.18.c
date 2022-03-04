// SPDX-License-Identifier: GPL-2.0
/*
 * xloop_main.c
 *
 * Written by Theodore Ts'o, 3/29/93
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 *
 * DES encryption plus some minor changes by Werner Almesberger, 30-MAY-1993
 * more DES encryption plus IDEA encryption by Nicholas J. Leon, June 20, 1996
 *
 * Modularized and updated for 1.1.16 kernel - Mitch Dsouza 28th May 1994
 * Adapted for 1.3.59 kernel - Andries Brouwer, 1 Feb 1996
 *
 * Fixed do_xloop_request() re-entrancy - Vincent.Renardias@waw.com Mar 20, 1997
 *
 * Added devfs support - Richard Gooch <rgooch@atnf.csiro.au> 16-Jan-1998
 *
 * Handle sparse backing files correctly - Kenn Humborg, Jun 28, 1998
 *
 * Loadable modules and other fixes by AK, 1998
 *
 * Make real block number available to downstream transfer functions, enables
 * CBC (and relatives) mode encryption requiring unique IVs per data block.
 * Reed H. Petty, rhp@draper.net
 *
 * Maximum number of xloop devices now dynamic via max_xloop module parameter.
 * Russell Kroll <rkroll@exploits.org> 19990701
 *
 * Maximum number of xloop devices when compiled-in now selectable by passing
 * max_xloop=<1-255> to the kernel on boot.
 * Erik I. Bolsø, <eriki@himolde.no>, Oct 31, 1999
 *
 * Completely rewrite request handling to be make_request_fn style and
 * non blocking, pushing work to a helper thread. Lots of fixes from
 * Al Viro too.
 * Jens Axboe <axboe@suse.de>, Nov 2000
 *
 * Support up to 256 xloop devices
 * Heinz Mauelshagen <mge@sistina.com>, Feb 2002
 *
 * Support for falling back on the write file operation when the address space
 * operations write_begin is not available on the backing filesystem.
 * Anton Altaparmakov, 16 Feb 2005
 *
 * Support for using file formats.
 * Manuel Bentele <development@manuel-bentele.de>, 2019
 *
 * Still To Fix:
 * - Advisory locking is ignored here.
 * - Should use an own CAP_* category instead of CAP_SYS_ADMIN
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/blk-cgroup.h>
#include <linux/version.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include <xloop/version.h>

#include "xloop_file_fmt.h"
#include "xloop_main.h"

#include <linux/uaccess.h>

static DEFINE_IDR(xloop_index_idr);
static DEFINE_MUTEX(xloop_ctl_mutex);

static int max_part;
static int part_shift;

struct device *xloop_device_to_dev(struct xloop_device *xlo)
{
	return disk_to_dev(xlo->xlo_disk);
}
EXPORT_SYMBOL(xloop_device_to_dev);

static int transfer_xor(struct xloop_device *xlo, int cmd, struct page *raw_page, unsigned int raw_off,
			struct page *xloop_page, unsigned int xloop_off, int size, sector_t real_block)
{
	char *raw_buf = kmap_atomic(raw_page) + raw_off;
	char *xloop_buf = kmap_atomic(xloop_page) + xloop_off;
	char *in, *out, *key;
	int i, keysize;

	if (cmd == READ) {
		in = raw_buf;
		out = xloop_buf;
	} else {
		in = xloop_buf;
		out = raw_buf;
	}

	key = xlo->xlo_encrypt_key;
	keysize = xlo->xlo_encrypt_key_size;
	for (i = 0; i < size; i++)
		*out++ = *in++ ^ key[(i & 511) % keysize];

	kunmap_atomic(xloop_buf);
	kunmap_atomic(raw_buf);
	cond_resched();
	return 0;
}

static int xor_init(struct xloop_device *xlo, const struct xloop_info64 *info)
{
	if (unlikely(info->xlo_encrypt_key_size <= 0))
		return -EINVAL;
	return 0;
}

static struct xloop_func_table none_funcs = {
	.number = XLO_CRYPT_NONE,
};

static struct xloop_func_table xor_funcs = { .number = XLO_CRYPT_XOR, .transfer = transfer_xor, .init = xor_init };

/* xfer_funcs[0] is special - its release function is never called */
static struct xloop_func_table *xfer_funcs[MAX_XLO_CRYPT] = { &none_funcs, &xor_funcs };

static loff_t get_xloop_size(struct xloop_device *xlo, struct file *file)
{
	return xloop_file_fmt_sector_size(xlo->xlo_fmt, file, xlo->xlo_offset, xlo->xlo_sizelimit);
}

static void __xloop_update_dio(struct xloop_device *xlo, bool dio)
{
	struct file *file = xlo->xlo_backing_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	unsigned short sb_bsize = 0;
	unsigned int dio_align = 0;
	bool use_dio;

	if (inode->i_sb->s_bdev) {
		sb_bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
		dio_align = sb_bsize - 1;
	}

	/*
	 * We support direct I/O only if xlo_offset is aligned with the
	 * logical I/O size of backing device, and the logical block
	 * size of xloop is bigger than the backing device's and the xloop
	 * needn't transform transfer.
	 *
	 * TODO: the above condition may be loosed in the future, and
	 * direct I/O may be switched runtime at that time because most
	 * of requests in sane applications should be PAGE_SIZE aligned
	 */
	if (dio) {
		if (queue_logical_block_size(xlo->xlo_queue) >= sb_bsize && !(xlo->xlo_offset & dio_align) &&
		    mapping->a_ops->direct_IO && !xlo->transfer)
			use_dio = true;
		else
			use_dio = false;
	} else {
		use_dio = false;
	}

	if (xlo->use_dio == use_dio)
		return;

	/* flush dirty pages before changing direct IO */
	xloop_file_fmt_flush(xlo->xlo_fmt);

	/*
	 * The flag of XLO_FLAGS_DIRECT_IO is handled similarly with
	 * XLO_FLAGS_READ_ONLY, both are set from kernel, and losetup
	 * will get updated by ioctl(XLOOP_GET_STATUS)
	 */
	if (xlo->xlo_state == Xlo_bound)
		blk_mq_freeze_queue(xlo->xlo_queue);
	xlo->use_dio = use_dio;
	if (use_dio) {
		blk_queue_flag_clear(QUEUE_FLAG_NOMERGES, xlo->xlo_queue);
		xlo->xlo_flags |= XLO_FLAGS_DIRECT_IO;
	} else {
		blk_queue_flag_set(QUEUE_FLAG_NOMERGES, xlo->xlo_queue);
		xlo->xlo_flags &= ~XLO_FLAGS_DIRECT_IO;
	}
	if (xlo->xlo_state == Xlo_bound)
		blk_mq_unfreeze_queue(xlo->xlo_queue);
}

/**
 * xloop_validate_block_size() - validates the passed in block size
 * @bsize: size to validate
 */
static int xloop_validate_block_size(unsigned short bsize)
{
	if (bsize < 512 || bsize > PAGE_SIZE || !is_power_of_2(bsize))
		return -EINVAL;

	return 0;
}

/**
 * xloop_set_size() - sets device size and notifies userspace
 * @xlo: struct xloop_device to set the size for
 * @size: new size of the xloop device
 *
 * Callers must validate that the size passed into this function fits into
 * a sector_t, eg using xloop_validate_size()
 */
static void xloop_set_size(struct xloop_device *xlo, loff_t size)
{
	struct block_device *bdev = xlo->xlo_device;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	sector_t capacity;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	bd_set_nr_sectors(bdev, size);
#else
	bd_set_size(bdev, size << SECTOR_SHIFT);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	if (!set_capacity_revalidate_and_notify(xlo->xlo_disk, size, false))
		kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	set_capacity_revalidate_and_notify(xlo->xlo_disk, size, false);
#else
	capacity = get_capacity(xlo->xlo_disk);
	set_capacity(xlo->xlo_disk, size);
	if (capacity != size && capacity != 0 && size != 0) {
		char *envp[] = { "RESIZE=1", NULL };

		kobject_uevent_env(&disk_to_dev(xlo->xlo_disk)->kobj, KOBJ_CHANGE, envp);
	}
#endif
}

static void xlo_complete_rq(struct request *rq)
{
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	blk_status_t ret = BLK_STS_OK;

	if (!cmd->use_aio || cmd->ret < 0 || cmd->ret == blk_rq_bytes(rq) || req_op(rq) != REQ_OP_READ) {
		if (cmd->ret < 0)
			ret = errno_to_blk_status(cmd->ret);
		goto end_io;
	}

	/*
	 * Short READ - if we got some data, advance our request and
	 * retry it. If we got no data, end the rest with EIO.
	 */
	if (cmd->ret) {
		blk_update_request(rq, BLK_STS_OK, cmd->ret);
		cmd->ret = 0;
		blk_mq_requeue_request(rq, true);
	} else {
		if (cmd->use_aio) {
			struct bio *bio = rq->bio;

			while (bio) {
				zero_fill_bio(bio);
				bio = bio->bi_next;
			}
		}
		ret = BLK_STS_IOERR;
end_io:
		blk_mq_end_request(rq, ret);
	}
}

static int do_req_filebacked(struct xloop_device *xlo, struct request *rq)
{
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);

	/*
	 * xlo_write_simple and xlo_read_simple should have been covered
	 * by io submit style function like xlo_rw_aio(), one blocker
	 * is that xlo_read_simple() need to call flush_dcache_page after
	 * the page is written from kernel, and it isn't easy to handle
	 * this in io submit style function which submits all segments
	 * of the req at one time. And direct read IO doesn't need to
	 * run flush_dcache_page().
	 */
	switch (req_op(rq)) {
	case REQ_OP_FLUSH:
		return xloop_file_fmt_flush(xlo->xlo_fmt);
	case REQ_OP_WRITE_ZEROES:
		return xloop_file_fmt_write_zeros(xlo->xlo_fmt, rq);
	case REQ_OP_DISCARD:
		return xloop_file_fmt_discard(xlo->xlo_fmt, rq);
	case REQ_OP_WRITE:
		if (cmd->use_aio)
			return xloop_file_fmt_write_aio(xlo->xlo_fmt, rq);
		else
			return xloop_file_fmt_write(xlo->xlo_fmt, rq);
	case REQ_OP_READ:
		if (cmd->use_aio)
			return xloop_file_fmt_read_aio(xlo->xlo_fmt, rq);
		else
			return xloop_file_fmt_read(xlo->xlo_fmt, rq);
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}

static inline void xloop_update_dio(struct xloop_device *xlo)
{
	__xloop_update_dio(xlo, (xlo->xlo_backing_file->f_flags & O_DIRECT) | xlo->use_dio);
}

static void xloop_reread_partitions(struct xloop_device *xlo, struct block_device *bdev)
{
	int rc;

#if (KERNEL_VERSION(5, 5, 0) <= LINUX_VERSION_CODE) ||                                                                 \
	RHEL_CHECK_VERSION(RHEL_RELEASE_VERSION(8, 3) <= RHEL_RELEASE_CODE)
	mutex_lock(&bdev->bd_mutex);
	rc = bdev_disk_changed(bdev, false);
	mutex_unlock(&bdev->bd_mutex);
#else
	rc = blkdev_reread_part(bdev);
#endif
	if (rc)
		dev_warn(xloop_device_to_dev(xlo), "partition scan failed (rc=%d)\n", rc);
}

static inline int is_xloop_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;

	return i && S_ISBLK(i->i_mode) && MAJOR(i->i_rdev) == XLOOP_MAJOR;
}

static int xloop_validate_file(struct file *file, struct block_device *bdev)
{
	struct inode *inode = file->f_mapping->host;
	struct file *f = file;

	/* Avoid recursion */
	while (is_xloop_device(f)) {
		struct xloop_device *l;

		if (f->f_mapping->host->i_bdev == bdev)
			return -EBADF;

		l = f->f_mapping->host->i_bdev->bd_disk->private_data;
		if (l->xlo_state != Xlo_bound)
			return -EINVAL;

		f = l->xlo_backing_file;
	}
	if (!S_ISREG(inode->i_mode) && !S_ISBLK(inode->i_mode))
		return -EINVAL;
	return 0;
}

/*
 * xloop_change_fd switched the backing store of a xloopback device to
 * a new file. This is useful for operating system installers to free up
 * the original file and in High Availability environments to switch to
 * an alternative location for the content in case of server meltdown.
 * This can only work if the xloop device is used read-only, and if the
 * new backing store is the same size and type as the old backing store.
 */
static int xloop_change_fd(struct xloop_device *xlo, struct block_device *bdev, unsigned int arg)
{
	struct file *file = NULL, *old_file;
	int error;
	bool partscan;

	error = mutex_lock_killable(&xloop_ctl_mutex);
	if (error)
		return error;
	error = -ENXIO;
	if (xlo->xlo_state != Xlo_bound)
		goto out_err;

	/* the xloop device has to be read-only */
	error = -EINVAL;
	if (!(xlo->xlo_flags & XLO_FLAGS_READ_ONLY))
		goto out_err;

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out_err;

	error = xloop_validate_file(file, bdev);
	if (error)
		goto out_err;

	old_file = xlo->xlo_backing_file;

	error = -EINVAL;

	/* size of the new backing store needs to be the same */
	if (get_xloop_size(xlo, file) != get_xloop_size(xlo, old_file))
		goto out_err;

	/* and ... switch */
	blk_mq_freeze_queue(xlo->xlo_queue);
	mapping_set_gfp_mask(old_file->f_mapping, xlo->old_gfp_mask);
	xlo->xlo_backing_file = file;
	xlo->old_gfp_mask = mapping_gfp_mask(file->f_mapping);
	mapping_set_gfp_mask(file->f_mapping, xlo->old_gfp_mask & ~(__GFP_IO | __GFP_FS));
	xloop_update_dio(xlo);
	blk_mq_unfreeze_queue(xlo->xlo_queue);
	partscan = xlo->xlo_flags & XLO_FLAGS_PARTSCAN;
	mutex_unlock(&xloop_ctl_mutex);
	/*
	 * We must drop file reference outside of xloop_ctl_mutex as dropping
	 * the file ref can take bd_mutex which creates circular locking
	 * dependency.
	 */
	fput(old_file);
	if (partscan)
		xloop_reread_partitions(xlo, bdev);
	return 0;

out_err:
	mutex_unlock(&xloop_ctl_mutex);
	if (file)
		fput(file);
	return error;
}

/* xloop sysfs attributes */

static ssize_t xloop_attr_show(struct device *dev, char *page, ssize_t (*callback)(struct xloop_device *, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct xloop_device *xlo = disk->private_data;

	return callback(xlo, page);
}

#define XLOOP_ATTR_RO(_name)                                                                                           \
	static ssize_t xloop_attr_##_name##_show(struct xloop_device *, char *);                                       \
	static ssize_t xloop_attr_do_show_##_name(struct device *d, struct device_attribute *attr, char *b)            \
	{                                                                                                              \
		return xloop_attr_show(d, b, xloop_attr_##_name##_show);                                               \
	}                                                                                                              \
	static struct device_attribute xloop_attr_##_name = __ATTR(_name, 0444, xloop_attr_do_show_##_name, NULL);

static ssize_t xloop_attr_backing_file_show(struct xloop_device *xlo, char *buf)
{
	ssize_t ret;
	char *p = NULL;

	spin_lock_irq(&xlo->xlo_lock);
	if (xlo->xlo_backing_file)
		p = file_path(xlo->xlo_backing_file, buf, PAGE_SIZE - 1);
	spin_unlock_irq(&xlo->xlo_lock);

	if (IS_ERR_OR_NULL(p))
		ret = PTR_ERR(p);
	else {
		ret = strlen(p);
		memmove(buf, p, ret);
		buf[ret++] = '\n';
		buf[ret] = 0;
	}

	return ret;
}

static ssize_t xloop_attr_file_fmt_type_show(struct xloop_device *xlo, char *buf)
{
	ssize_t len = 0;

	len = xloop_file_fmt_print_type(xlo->xlo_fmt->file_fmt_type, buf);
	len += sprintf(buf + len, "\n");

	return len;
}

static ssize_t xloop_attr_offset_show(struct xloop_device *xlo, char *buf)
{
	return sprintf(buf, "%llu\n", (unsigned long long)xlo->xlo_offset);
}

static ssize_t xloop_attr_sizelimit_show(struct xloop_device *xlo, char *buf)
{
	return sprintf(buf, "%llu\n", (unsigned long long)xlo->xlo_sizelimit);
}

static ssize_t xloop_attr_autoclear_show(struct xloop_device *xlo, char *buf)
{
	int autoclear = (xlo->xlo_flags & XLO_FLAGS_AUTOCLEAR);

	return sprintf(buf, "%s\n", autoclear ? "1" : "0");
}

static ssize_t xloop_attr_partscan_show(struct xloop_device *xlo, char *buf)
{
	int partscan = (xlo->xlo_flags & XLO_FLAGS_PARTSCAN);

	return sprintf(buf, "%s\n", partscan ? "1" : "0");
}

static ssize_t xloop_attr_dio_show(struct xloop_device *xlo, char *buf)
{
	int dio = (xlo->xlo_flags & XLO_FLAGS_DIRECT_IO);

	return sprintf(buf, "%s\n", dio ? "1" : "0");
}

XLOOP_ATTR_RO(backing_file);
XLOOP_ATTR_RO(file_fmt_type);
XLOOP_ATTR_RO(offset);
XLOOP_ATTR_RO(sizelimit);
XLOOP_ATTR_RO(autoclear);
XLOOP_ATTR_RO(partscan);
XLOOP_ATTR_RO(dio);

static struct attribute *xloop_attrs[] = {
	&xloop_attr_backing_file.attr, &xloop_attr_file_fmt_type.attr,
	&xloop_attr_offset.attr,       &xloop_attr_sizelimit.attr,
	&xloop_attr_autoclear.attr,    &xloop_attr_partscan.attr,
	&xloop_attr_dio.attr,	       NULL,
};

static struct attribute_group xloop_attribute_group = {
	.name  = "xloop",
	.attrs = xloop_attrs,
};

static void xloop_sysfs_init(struct xloop_device *xlo)
{
	xlo->sysfs_inited = !sysfs_create_group(&disk_to_dev(xlo->xlo_disk)->kobj, &xloop_attribute_group);
}

static void xloop_sysfs_exit(struct xloop_device *xlo)
{
	if (xlo->sysfs_inited)
		sysfs_remove_group(&disk_to_dev(xlo->xlo_disk)->kobj, &xloop_attribute_group);
}

static void xloop_config_discard(struct xloop_device *xlo)
{
	struct file *file = xlo->xlo_backing_file;
	struct inode *inode = file->f_mapping->host;
	struct request_queue *q = xlo->xlo_queue;
	u32 granularity, max_discard_sectors;

	/*
	 * If the backing device is a block device, mirror its zeroing
	 * capability. Set the discard sectors to the block device's zeroing
	 * capabilities because xloop discards result in blkdev_issue_zeroout(),
	 * not blkdev_issue_discard(). This maintains consistent behavior with
	 * file-backed xloop devices: discarded regions read back as zero.
	 */
	if (S_ISBLK(inode->i_mode) && !xlo->xlo_encrypt_key_size) {
		struct request_queue *backingq;

		backingq = bdev_get_queue(inode->i_bdev);

		max_discard_sectors = backingq->limits.max_write_zeroes_sectors;
		granularity = backingq->limits.discard_granularity ?: queue_physical_block_size(backingq);

	/*
	 * We use punch hole to reclaim the free space used by the
	 * image a.k.a. discard. However we do not support discard if
	 * encryption is enabled, because it may give an attacker
	 * useful information.
	 */
	} else if (!file->f_op->fallocate || xlo->xlo_encrypt_key_size) {
		max_discard_sectors = 0;
		granularity = 0;

	} else {
		max_discard_sectors = UINT_MAX >> 9;
		granularity = inode->i_sb->s_blocksize;
	}

	if (max_discard_sectors) {
		q->limits.discard_granularity = granularity;
		blk_queue_max_discard_sectors(q, max_discard_sectors);
		blk_queue_max_write_zeroes_sectors(q, max_discard_sectors);
		blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
	} else {
		q->limits.discard_granularity = 0;
		blk_queue_max_discard_sectors(q, 0);
		blk_queue_max_write_zeroes_sectors(q, 0);
		blk_queue_flag_clear(QUEUE_FLAG_DISCARD, q);
	}
	q->limits.discard_alignment = 0;
}

static void xloop_unprepare_queue(struct xloop_device *xlo)
{
	kthread_flush_worker(&xlo->worker);
	kthread_stop(xlo->worker_task);
}

static int xloop_kthread_worker_fn(void *worker_ptr)
{
#if (KERNEL_VERSION(5, 8, 0) <= LINUX_VERSION_CODE) ||                                                                 \
	RHEL_CHECK_VERSION(RHEL_RELEASE_VERSION(8, 4) <= RHEL_RELEASE_CODE)
	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
#else
	current->flags |= PF_LESS_THROTTLE | PF_MEMALLOC_NOIO;
#endif
	return kthread_worker_fn(worker_ptr);
}

static int xloop_prepare_queue(struct xloop_device *xlo)
{
	kthread_init_worker(&xlo->worker);
	xlo->worker_task = kthread_run(xloop_kthread_worker_fn, &xlo->worker, "xloop%d", xlo->xlo_number);
	if (IS_ERR(xlo->worker_task))
		return -ENOMEM;
	set_user_nice(xlo->worker_task, MIN_NICE);
	return 0;
}

static void xloop_update_rotational(struct xloop_device *xlo)
{
	struct file *file = xlo->xlo_backing_file;
	struct inode *file_inode = file->f_mapping->host;
	struct block_device *file_bdev = file_inode->i_sb->s_bdev;
	struct request_queue *q = xlo->xlo_queue;
	bool nonrot = true;

	/* not all filesystems (e.g. tmpfs) have a sb->s_bdev */
	if (file_bdev)
		nonrot = blk_queue_nonrot(bdev_get_queue(file_bdev));

	if (nonrot)
		blk_queue_flag_set(QUEUE_FLAG_NONROT, q);
	else
		blk_queue_flag_clear(QUEUE_FLAG_NONROT, q);
}

static int xloop_release_xfer(struct xloop_device *xlo)
{
	int err = 0;
	struct xloop_func_table *xfer = xlo->xlo_encryption;

	if (xfer) {
		if (xfer->release)
			err = xfer->release(xlo);
		xlo->transfer = NULL;
		xlo->xlo_encryption = NULL;
		module_put(xfer->owner);
	}
	return err;
}

static int xloop_init_xfer(struct xloop_device *xlo, struct xloop_func_table *xfer, const struct xloop_info64 *i)
{
	int err = 0;

	if (xfer) {
		struct module *owner = xfer->owner;

		if (!try_module_get(owner))
			return -EINVAL;
		if (xfer->init)
			err = xfer->init(xlo, i);
		if (err)
			module_put(owner);
		else
			xlo->xlo_encryption = xfer;
	}
	return err;
}

/**
 * xloop_set_status_from_info - configure device from xloop_info
 * @xlo: struct xloop_device to configure
 * @info: struct xloop_info64 to configure the device with
 *
 * Configures the xloop device parameters according to the passed
 * in xloop_info64 configuration.
 */
static int xloop_set_status_from_info(struct xloop_device *xlo, const struct xloop_info64 *info)
{
	int err;
	struct xloop_func_table *xfer;
	kuid_t uid = current_uid();

	if ((unsigned int)info->xlo_encrypt_key_size > XLO_KEY_SIZE)
		return -EINVAL;

	err = xloop_release_xfer(xlo);
	if (err)
		return err;

	if (info->xlo_encrypt_type) {
		unsigned int type = info->xlo_encrypt_type;

		if (type >= MAX_XLO_CRYPT)
			return -EINVAL;
		xfer = xfer_funcs[type];
		if (xfer == NULL)
			return -EINVAL;
	} else
		xfer = NULL;

	err = xloop_init_xfer(xlo, xfer, info);
	if (err)
		return err;

	xlo->xlo_offset = info->xlo_offset;
	xlo->xlo_sizelimit = info->xlo_sizelimit;
	memcpy(xlo->xlo_file_name, info->xlo_file_name, XLO_NAME_SIZE);
	memcpy(xlo->xlo_crypt_name, info->xlo_crypt_name, XLO_NAME_SIZE);
	xlo->xlo_file_name[XLO_NAME_SIZE - 1] = 0;
	xlo->xlo_crypt_name[XLO_NAME_SIZE - 1] = 0;

	if (!xfer)
		xfer = &none_funcs;
	xlo->transfer = xfer->transfer;
	xlo->ioctl = xfer->ioctl;

	xlo->xlo_flags = info->xlo_flags;

	xlo->xlo_encrypt_key_size = info->xlo_encrypt_key_size;
	xlo->xlo_init[0] = info->xlo_init[0];
	xlo->xlo_init[1] = info->xlo_init[1];
	if (info->xlo_encrypt_key_size) {
		memcpy(xlo->xlo_encrypt_key, info->xlo_encrypt_key, info->xlo_encrypt_key_size);
		xlo->xlo_key_owner = uid;
	}

	return 0;
}

static int xloop_configure(struct xloop_device *xlo, fmode_t mode, struct block_device *bdev,
			   const struct xloop_config *config)
{
	struct file *file;
	struct inode *inode;
	struct address_space *mapping;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	struct block_device *claimed_bdev = NULL;
#endif
	int error;
	loff_t size;
	bool partscan;
	unsigned short bsize;

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);

	error = -EBADF;
	file = fget(config->fd);
	if (!file)
		goto out;

	/*
	 * If we don't hold exclusive handle for the device, upgrade to it
	 * here to avoid changing device under exclusive owner.
	 */
	if (!(mode & FMODE_EXCL)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
		claimed_bdev = bdev->bd_contains;
		error = bd_prepare_to_claim(bdev, claimed_bdev, xloop_configure);
		if (error)
			goto out_putf;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
		claimed_bdev = bd_start_claiming(bdev, xloop_configure);
		if (IS_ERR(claimed_bdev)) {
			error = PTR_ERR(claimed_bdev);
			goto out_putf;
		}
#else
		bdgrab(bdev);
		error = blkdev_get(bdev, mode | FMODE_EXCL, xloop_configure);
		if (error)
			goto out_putf;
#endif
	}

	error = mutex_lock_killable(&xloop_ctl_mutex);
	if (error)
		goto out_bdev;

	error = -EBUSY;
	if (xlo->xlo_state != Xlo_unbound)
		goto out_unlock;

	error = xloop_validate_file(file, bdev);
	if (error)
		goto out_unlock;

	mapping = file->f_mapping;
	inode = mapping->host;

	if ((config->info.xlo_flags & ~XLOOP_CONFIGURE_SETTABLE_FLAGS) != 0) {
		error = -EINVAL;
		goto out_unlock;
	}

	if (config->block_size) {
		error = xloop_validate_block_size(config->block_size);
		if (error)
			goto out_unlock;
	}

	error = xloop_set_status_from_info(xlo, &config->info);
	if (error)
		goto out_unlock;

	if (!(file->f_mode & FMODE_WRITE) || !(mode & FMODE_WRITE) || !file->f_op->write_iter)
		xlo->xlo_flags |= XLO_FLAGS_READ_ONLY;

	error = xloop_prepare_queue(xlo);
	if (error)
		goto out_unlock;

	set_device_ro(bdev, (xlo->xlo_flags & XLO_FLAGS_READ_ONLY) != 0);

	xlo->use_dio = xlo->xlo_flags & XLO_FLAGS_DIRECT_IO;
	xlo->xlo_device = bdev;
	xlo->xlo_backing_file = file;
	xlo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, xlo->old_gfp_mask & ~(__GFP_IO | __GFP_FS));

	error = xloop_file_fmt_init(xlo->xlo_fmt, config->info.xlo_file_fmt_type);
	if (error)
		goto out_unlock;

	if (!(xlo->xlo_flags & XLO_FLAGS_READ_ONLY) && file->f_op->fsync)
		blk_queue_write_cache(xlo->xlo_queue, true, false);

	if (config->block_size)
		bsize = config->block_size;
	else if ((xlo->xlo_backing_file->f_flags & O_DIRECT) && inode->i_sb->s_bdev)
		/* In case of direct I/O, match underlying block size */
		bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
	else
		bsize = 512;

	blk_queue_logical_block_size(xlo->xlo_queue, bsize);
	blk_queue_physical_block_size(xlo->xlo_queue, bsize);
	blk_queue_io_min(xlo->xlo_queue, bsize);

	xloop_update_rotational(xlo);
	xloop_update_dio(xlo);
	xloop_sysfs_init(xlo);

	size = get_xloop_size(xlo, file);
	xloop_set_size(xlo, size);

	set_blocksize(bdev, S_ISBLK(inode->i_mode) ? block_size(inode->i_bdev) : PAGE_SIZE);

	xlo->xlo_state = Xlo_bound;
	if (part_shift)
		xlo->xlo_flags |= XLO_FLAGS_PARTSCAN;
	partscan = xlo->xlo_flags & XLO_FLAGS_PARTSCAN;
	if (partscan)
		xlo->xlo_disk->flags &= ~GENHD_FL_NO_PART_SCAN;

	/* Grab the block_device to prevent its destruction after we
	 * put /dev/xloopXX inode. Later in __xloop_clr_fd() we bdput(bdev).
	 */
	bdgrab(bdev);
	mutex_unlock(&xloop_ctl_mutex);
	if (partscan)
		xloop_reread_partitions(xlo, bdev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	if (claimed_bdev)
		bd_abort_claiming(bdev, claimed_bdev, xloop_configure);
#else
	if (!(mode & FMODE_EXCL))
		blkdev_put(bdev, mode | FMODE_EXCL);
#endif
	return 0;

out_unlock:
	mutex_unlock(&xloop_ctl_mutex);
out_bdev:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	if (claimed_bdev)
		bd_abort_claiming(bdev, claimed_bdev, xloop_configure);
#else
	if (!(mode & FMODE_EXCL))
		blkdev_put(bdev, mode | FMODE_EXCL);
#endif
out_putf:
	fput(file);
out:
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	return error;
}

static int __xloop_clr_fd(struct xloop_device *xlo, bool release)
{
	struct file *filp = NULL;
	gfp_t gfp = xlo->old_gfp_mask;
	struct block_device *bdev = xlo->xlo_device;
	int err = 0;
	bool partscan = false;
	int xlo_number;

	mutex_lock(&xloop_ctl_mutex);
	if (WARN_ON_ONCE(xlo->xlo_state != Xlo_rundown)) {
		err = -ENXIO;
		goto out_unlock;
	}

	filp = xlo->xlo_backing_file;
	if (filp == NULL) {
		err = -EINVAL;
		goto out_unlock;
	}

	/* freeze request queue during the transition */
	blk_mq_freeze_queue(xlo->xlo_queue);

	xloop_file_fmt_exit(xlo->xlo_fmt);

	spin_lock_irq(&xlo->xlo_lock);
	xlo->xlo_backing_file = NULL;
	spin_unlock_irq(&xlo->xlo_lock);

	xloop_release_xfer(xlo);
	xlo->transfer = NULL;
	xlo->ioctl = NULL;
	xlo->xlo_device = NULL;
	xlo->xlo_encryption = NULL;
	xlo->xlo_offset = 0;
	xlo->xlo_sizelimit = 0;
	xlo->xlo_encrypt_key_size = 0;
	memset(xlo->xlo_encrypt_key, 0, XLO_KEY_SIZE);
	memset(xlo->xlo_crypt_name, 0, XLO_NAME_SIZE);
	memset(xlo->xlo_file_name, 0, XLO_NAME_SIZE);
	blk_queue_logical_block_size(xlo->xlo_queue, 512);
	blk_queue_physical_block_size(xlo->xlo_queue, 512);
	blk_queue_io_min(xlo->xlo_queue, 512);
	if (bdev) {
		bdput(bdev);
		invalidate_bdev(bdev);
		bdev->bd_inode->i_mapping->wb_err = 0;
	}
	set_capacity(xlo->xlo_disk, 0);
	xloop_sysfs_exit(xlo);
	if (bdev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		bd_set_nr_sectors(bdev, 0);
#else
		bd_set_size(bdev, 0);
#endif
		/* let user-space know about this change */
		kobject_uevent(&disk_to_dev(bdev->bd_disk)->kobj, KOBJ_CHANGE);
	}
	mapping_set_gfp_mask(filp->f_mapping, gfp);
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	blk_mq_unfreeze_queue(xlo->xlo_queue);

	partscan = xlo->xlo_flags & XLO_FLAGS_PARTSCAN && bdev;
	xlo_number = xlo->xlo_number;
	xloop_unprepare_queue(xlo);
out_unlock:
	mutex_unlock(&xloop_ctl_mutex);
	if (partscan) {
		/*
		 * bd_mutex has been held already in release path, so don't
		 * acquire it if this function is called in such case.
		 *
		 * If the reread partition isn't from release path, xlo_refcnt
		 * must be at least one and it can only become zero when the
		 * current holder is released.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0) || RHEL_CHECK_VERSION(RHEL_RELEASE_VERSION(8, 3) <= RHEL_RELEASE_CODE)
		if (!release)
			mutex_lock(&bdev->bd_mutex);
		err = bdev_disk_changed(bdev, false);
#else
		err = blkdev_reread_part(bdev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
		if (!release)
			mutex_unlock(&bdev->bd_mutex);
#endif
		if (err)
			dev_warn(xloop_device_to_dev(xlo), "partition scan failed (rc=%d)\n", err);

		/* Device is gone, no point in returning error */
		err = 0;
	}

	/*
	 * xlo->xlo_state is set to Xlo_unbound here after above partscan has
	 * finished.
	 *
	 * There cannot be anybody else entering __xloop_clr_fd() as
	 * xlo->xlo_backing_file is already cleared and Xlo_rundown state
	 * protects us from all the other places trying to change the 'xlo'
	 * device.
	 */
	mutex_lock(&xloop_ctl_mutex);
	xlo->xlo_flags = 0;
	if (!part_shift)
		xlo->xlo_disk->flags |= GENHD_FL_NO_PART_SCAN;
	xlo->xlo_state = Xlo_unbound;
	mutex_unlock(&xloop_ctl_mutex);

	/*
	 * Need not hold xloop_ctl_mutex to fput backing file.
	 * Calling fput holding xloop_ctl_mutex triggers a circular
	 * lock dependency possibility warning as fput can take
	 * bd_mutex which is usually taken before xloop_ctl_mutex.
	 */
	if (filp)
		fput(filp);
	return err;
}

static int xloop_clr_fd(struct xloop_device *xlo)
{
	int err;

	err = mutex_lock_killable(&xloop_ctl_mutex);
	if (err)
		return err;
	if (xlo->xlo_state != Xlo_bound) {
		mutex_unlock(&xloop_ctl_mutex);
		return -ENXIO;
	}
	/*
	 * If we've explicitly asked to tear down the xloop device,
	 * and it has an elevated reference count, set it for auto-teardown when
	 * the last reference goes away. This stops $!~#$@ udev from
	 * preventing teardown because it decided that it needs to run blkid on
	 * the xloopback device whenever they appear. xfstests is notorious for
	 * failing tests because blkid via udev races with a losetup
	 * <dev>/do something like mkfs/losetup -d <dev> causing the losetup -d
	 * command to fail with EBUSY.
	 */
	if (atomic_read(&xlo->xlo_refcnt) > 1) {
		xlo->xlo_flags |= XLO_FLAGS_AUTOCLEAR;
		mutex_unlock(&xloop_ctl_mutex);
		return 0;
	}
	xlo->xlo_state = Xlo_rundown;
	mutex_unlock(&xloop_ctl_mutex);

	return __xloop_clr_fd(xlo, false);
}

static int xloop_set_status(struct xloop_device *xlo, const struct xloop_info64 *info)
{
	int err;
	struct block_device *bdev;
	kuid_t uid = current_uid();
	int prev_xlo_flags;
	bool partscan = false;
	bool size_changed = false;

	err = mutex_lock_killable(&xloop_ctl_mutex);
	if (err)
		return err;
	if (xlo->xlo_encrypt_key_size && !uid_eq(xlo->xlo_key_owner, uid) && !capable(CAP_SYS_ADMIN)) {
		err = -EPERM;
		goto out_unlock;
	}
	if (xlo->xlo_state != Xlo_bound) {
		err = -ENXIO;
		goto out_unlock;
	}

	if (xlo->xlo_offset != info->xlo_offset || xlo->xlo_sizelimit != info->xlo_sizelimit) {
		size_changed = true;
		sync_blockdev(xlo->xlo_device);
		invalidate_bdev(xlo->xlo_device);
	}

	/* I/O need to be drained during transfer transition */
	blk_mq_freeze_queue(xlo->xlo_queue);

	if (size_changed && xlo->xlo_device->bd_inode->i_mapping->nrpages) {
		/* If any pages were dirtied after invalidate_bdev(), try again */
		err = -EAGAIN;
		dev_warn(xloop_device_to_dev(xlo),
			 "xloop device has still dirty pages (nrpages=%lu)\n",
			 xlo->xlo_device->bd_inode->i_mapping->nrpages);
		goto out_unfreeze;
	}

	prev_xlo_flags = xlo->xlo_flags;

	err = xloop_set_status_from_info(xlo, info);
	if (err)
		goto out_unfreeze;

	/* Mask out flags that can't be set using XLOOP_SET_STATUS. */
	xlo->xlo_flags &= XLOOP_SET_STATUS_SETTABLE_FLAGS;
	/* For those flags, use the previous values instead */
	xlo->xlo_flags |= prev_xlo_flags & ~XLOOP_SET_STATUS_SETTABLE_FLAGS;
	/* For flags that can't be cleared, use previous values too */
	xlo->xlo_flags |= prev_xlo_flags & ~XLOOP_SET_STATUS_CLEARABLE_FLAGS;

	if (xlo->xlo_fmt->file_fmt_type != info->xlo_file_fmt_type) {
		/* xloop file format has changed, so change file format driver */
		err = xloop_file_fmt_change(xlo->xlo_fmt, info->xlo_file_fmt_type);
		if (err)
			goto out_unfreeze;

		/* After change of the file format, recalculate the capacity of the xloop device. */
		size_changed = true;
	}

	if (size_changed) {
		loff_t new_size = get_xloop_size(xlo, xlo->xlo_backing_file);

		xloop_set_size(xlo, new_size);
	}

	xloop_config_discard(xlo);

	/* update dio if xlo_offset or transfer is changed */
	__xloop_update_dio(xlo, xlo->use_dio);

out_unfreeze:
	blk_mq_unfreeze_queue(xlo->xlo_queue);

	if (!err && (xlo->xlo_flags & XLO_FLAGS_PARTSCAN) && !(prev_xlo_flags & XLO_FLAGS_PARTSCAN)) {
		xlo->xlo_disk->flags &= ~GENHD_FL_NO_PART_SCAN;
		bdev = xlo->xlo_device;
		partscan = true;
	}
out_unlock:
	mutex_unlock(&xloop_ctl_mutex);
	if (partscan)
		xloop_reread_partitions(xlo, bdev);

	return err;
}

static int xloop_get_status(struct xloop_device *xlo, struct xloop_info64 *info)
{
	struct path path;
	struct kstat stat;
	int ret;

	ret = mutex_lock_killable(&xloop_ctl_mutex);
	if (ret)
		return ret;
	if (xlo->xlo_state != Xlo_bound) {
		mutex_unlock(&xloop_ctl_mutex);
		return -ENXIO;
	}

	memset(info, 0, sizeof(*info));
	info->xlo_number = xlo->xlo_number;
	info->xlo_offset = xlo->xlo_offset;
	info->xlo_sizelimit = xlo->xlo_sizelimit;
	info->xlo_flags = xlo->xlo_flags;
	memcpy(info->xlo_file_name, xlo->xlo_file_name, XLO_NAME_SIZE);
	memcpy(info->xlo_crypt_name, xlo->xlo_crypt_name, XLO_NAME_SIZE);
	info->xlo_encrypt_type = xlo->xlo_encryption ? xlo->xlo_encryption->number : 0;
	if (xlo->xlo_encrypt_key_size && capable(CAP_SYS_ADMIN)) {
		info->xlo_encrypt_key_size = xlo->xlo_encrypt_key_size;
		memcpy(info->xlo_encrypt_key, xlo->xlo_encrypt_key, xlo->xlo_encrypt_key_size);
	}

	/* Drop xloop_ctl_mutex while we call into the filesystem. */
	path = xlo->xlo_backing_file->f_path;
	path_get(&path);
	mutex_unlock(&xloop_ctl_mutex);
	ret = vfs_getattr(&path, &stat, STATX_INO, AT_STATX_SYNC_AS_STAT);
	if (!ret) {
		info->xlo_device = huge_encode_dev(stat.dev);
		info->xlo_inode = stat.ino;
		info->xlo_rdevice = huge_encode_dev(stat.rdev);
	}
	path_put(&path);
	return ret;
}

static void xloop_info64_from_old(const struct xloop_info *info, struct xloop_info64 *info64)
{
	memset(info64, 0, sizeof(*info64));
	info64->xlo_number = info->xlo_number;
	info64->xlo_device = info->xlo_device;
	info64->xlo_inode = info->xlo_inode;
	info64->xlo_rdevice = info->xlo_rdevice;
	info64->xlo_offset = info->xlo_offset;
	info64->xlo_sizelimit = 0;
	info64->xlo_encrypt_type = info->xlo_encrypt_type;
	info64->xlo_encrypt_key_size = info->xlo_encrypt_key_size;
	info64->xlo_flags = info->xlo_flags;
	info64->xlo_init[0] = info->xlo_init[0];
	info64->xlo_init[1] = info->xlo_init[1];
	info64->xlo_file_fmt_type = info->xlo_file_fmt_type;
	if (info->xlo_encrypt_type == XLO_CRYPT_CRYPTOAPI)
		memcpy(info64->xlo_crypt_name, info->xlo_name, XLO_NAME_SIZE);
	else
		memcpy(info64->xlo_file_name, info->xlo_name, XLO_NAME_SIZE);
	memcpy(info64->xlo_encrypt_key, info->xlo_encrypt_key, XLO_KEY_SIZE);
}

static int xloop_info64_to_old(const struct xloop_info64 *info64, struct xloop_info *info)
{
	memset(info, 0, sizeof(*info));
	info->xlo_number = info64->xlo_number;
	info->xlo_device = info64->xlo_device;
	info->xlo_inode = info64->xlo_inode;
	info->xlo_rdevice = info64->xlo_rdevice;
	info->xlo_offset = info64->xlo_offset;
	info->xlo_encrypt_type = info64->xlo_encrypt_type;
	info->xlo_encrypt_key_size = info64->xlo_encrypt_key_size;
	info->xlo_flags = info64->xlo_flags;
	info->xlo_init[0] = info64->xlo_init[0];
	info->xlo_init[1] = info64->xlo_init[1];
	info->xlo_file_fmt_type = info64->xlo_file_fmt_type;
	if (info->xlo_encrypt_type == XLO_CRYPT_CRYPTOAPI)
		memcpy(info->xlo_name, info64->xlo_crypt_name, XLO_NAME_SIZE);
	else
		memcpy(info->xlo_name, info64->xlo_file_name, XLO_NAME_SIZE);
	memcpy(info->xlo_encrypt_key, info64->xlo_encrypt_key, XLO_KEY_SIZE);

	/* error in case values were truncated */
	if (info->xlo_device != info64->xlo_device || info->xlo_rdevice != info64->xlo_rdevice ||
	    info->xlo_inode != info64->xlo_inode || info->xlo_offset != info64->xlo_offset)
		return -EOVERFLOW;

	return 0;
}

static int xloop_set_status_old(struct xloop_device *xlo, const struct xloop_info __user *arg)
{
	struct xloop_info info;
	struct xloop_info64 info64;

	if (copy_from_user(&info, arg, sizeof(struct xloop_info)))
		return -EFAULT;
	xloop_info64_from_old(&info, &info64);
	return xloop_set_status(xlo, &info64);
}

static int xloop_set_status64(struct xloop_device *xlo, const struct xloop_info64 __user *arg)
{
	struct xloop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof(struct xloop_info64)))
		return -EFAULT;
	return xloop_set_status(xlo, &info64);
}

static int xloop_get_status_old(struct xloop_device *xlo, struct xloop_info __user *arg)
{
	struct xloop_info info;
	struct xloop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = xloop_get_status(xlo, &info64);
	if (!err)
		err = xloop_info64_to_old(&info64, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int xloop_get_status64(struct xloop_device *xlo, struct xloop_info64 __user *arg)
{
	struct xloop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = xloop_get_status(xlo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64)))
		err = -EFAULT;

	return err;
}

static int xloop_set_capacity(struct xloop_device *xlo)
{
	loff_t size;

	if (unlikely(xlo->xlo_state != Xlo_bound))
		return -ENXIO;

	size = get_xloop_size(xlo, xlo->xlo_backing_file);
	xloop_set_size(xlo, size);

	return 0;
}

static int xloop_set_dio(struct xloop_device *xlo, unsigned long arg)
{
	int error = -ENXIO;

	if (xlo->xlo_state != Xlo_bound)
		goto out;

	__xloop_update_dio(xlo, !!arg);
	if (xlo->use_dio == !!arg)
		return 0;
	error = -EINVAL;
out:
	return error;
}

static int xloop_set_block_size(struct xloop_device *xlo, unsigned long arg)
{
	int err = 0;

	if (xlo->xlo_state != Xlo_bound)
		return -ENXIO;

	err = xloop_validate_block_size(arg);
	if (err)
		return err;

	if (xlo->xlo_queue->limits.logical_block_size == arg)
		return 0;

	sync_blockdev(xlo->xlo_device);
	invalidate_bdev(xlo->xlo_device);

	blk_mq_freeze_queue(xlo->xlo_queue);

	/* invalidate_bdev should have truncated all the pages */
	if (xlo->xlo_device->bd_inode->i_mapping->nrpages) {
		err = -EAGAIN;
		dev_warn(xloop_device_to_dev(xlo),
			 "xloop device has still dirty pages (nrpages=%lu)\n",
			 xlo->xlo_device->bd_inode->i_mapping->nrpages);
		goto out_unfreeze;
	}

	blk_queue_logical_block_size(xlo->xlo_queue, arg);
	blk_queue_physical_block_size(xlo->xlo_queue, arg);
	blk_queue_io_min(xlo->xlo_queue, arg);
	xloop_update_dio(xlo);
out_unfreeze:
	blk_mq_unfreeze_queue(xlo->xlo_queue);

	return err;
}

static int xlo_simple_ioctl(struct xloop_device *xlo, unsigned int cmd, unsigned long arg)
{
	int err;

	err = mutex_lock_killable(&xloop_ctl_mutex);
	if (err)
		return err;
	switch (cmd) {
	case XLOOP_SET_CAPACITY:
		err = xloop_set_capacity(xlo);
		break;
	case XLOOP_SET_DIRECT_IO:
		err = xloop_set_dio(xlo, arg);
		break;
	case XLOOP_SET_BLOCK_SIZE:
		err = xloop_set_block_size(xlo, arg);
		break;
	default:
		err = xlo->ioctl ? xlo->ioctl(xlo, cmd, arg) : -EINVAL;
	}
	mutex_unlock(&xloop_ctl_mutex);
	return err;
}

static int xlo_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	struct xloop_device *xlo = bdev->bd_disk->private_data;
	void __user *argp = (void __user *)arg;
	int err;

	switch (cmd) {
	case XLOOP_SET_FD: {
		/*
		 * Legacy case - pass in a zeroed out struct xloop_config with
		 * only the file descriptor set , which corresponds with the
		 * default parameters we'd have used otherwise.
		 */
		struct xloop_config config;

		memset(&config, 0, sizeof(config));
		config.fd = arg;

		return xloop_configure(xlo, mode, bdev, &config);
	}
	case XLOOP_CONFIGURE: {
		struct xloop_config config;

		if (copy_from_user(&config, argp, sizeof(config)))
			return -EFAULT;

		return xloop_configure(xlo, mode, bdev, &config);
	}
	case XLOOP_CHANGE_FD:
		return xloop_change_fd(xlo, bdev, arg);
	case XLOOP_CLR_FD:
		return xloop_clr_fd(xlo);
	case XLOOP_SET_STATUS:
		err = -EPERM;
		if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN))
			err = xloop_set_status_old(xlo, argp);
		break;
	case XLOOP_GET_STATUS:
		return xloop_get_status_old(xlo, argp);
	case XLOOP_SET_STATUS64:
		err = -EPERM;
		if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN))
			err = xloop_set_status64(xlo, argp);
		break;
	case XLOOP_GET_STATUS64:
		return xloop_get_status64(xlo, argp);
	case XLOOP_SET_CAPACITY:
	case XLOOP_SET_DIRECT_IO:
	case XLOOP_SET_BLOCK_SIZE:
		if (!(mode & FMODE_WRITE) && !capable(CAP_SYS_ADMIN))
			return -EPERM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
		fallthrough;
#else
			/* fall through */
#endif
	default:
		err = xlo_simple_ioctl(xlo, cmd, arg);
		break;
	}

	return err;
}

#ifdef CONFIG_COMPAT
struct compat_xloop_info {
	compat_int_t   xlo_number;                    /* ioctl r/o */
	compat_dev_t   xlo_device;                    /* ioctl r/o */
	compat_ulong_t xlo_inode;                     /* ioctl r/o */
	compat_dev_t   xlo_rdevice;                   /* ioctl r/o */
	compat_int_t   xlo_offset;
	compat_int_t   xlo_encrypt_type;
	compat_int_t   xlo_encrypt_key_size;          /* ioctl w/o */
	compat_int_t   xlo_flags;                     /* ioctl r/o */
	char           xlo_name[XLO_NAME_SIZE];
	unsigned char  xlo_encrypt_key[XLO_KEY_SIZE]; /* ioctl w/o */
	compat_ulong_t xlo_init[2];
	char           reserved[4];
	compat_int_t   xlo_file_fmt_type;
};

/*
 * Transfer 32-bit compatibility structure in userspace to 64-bit xloop info
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int xloop_info64_from_compat(const struct compat_xloop_info __user *arg, struct xloop_info64 *info64)
{
	struct compat_xloop_info info;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	memset(info64, 0, sizeof(*info64));
	info64->xlo_number = info.xlo_number;
	info64->xlo_device = info.xlo_device;
	info64->xlo_inode = info.xlo_inode;
	info64->xlo_rdevice = info.xlo_rdevice;
	info64->xlo_offset = info.xlo_offset;
	info64->xlo_sizelimit = 0;
	info64->xlo_encrypt_type = info.xlo_encrypt_type;
	info64->xlo_encrypt_key_size = info.xlo_encrypt_key_size;
	info64->xlo_flags = info.xlo_flags;
	info64->xlo_init[0] = info.xlo_init[0];
	info64->xlo_init[1] = info.xlo_init[1];
	info64->xlo_file_fmt_type = info.xlo_file_fmt_type;
	if (info.xlo_encrypt_type == XLO_CRYPT_CRYPTOAPI)
		memcpy(info64->xlo_crypt_name, info.xlo_name, XLO_NAME_SIZE);
	else
		memcpy(info64->xlo_file_name, info.xlo_name, XLO_NAME_SIZE);
	memcpy(info64->xlo_encrypt_key, info.xlo_encrypt_key, XLO_KEY_SIZE);
	return 0;
}

/*
 * Transfer 64-bit xloop info to 32-bit compatibility structure in userspace
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int xloop_info64_to_compat(const struct xloop_info64 *info64, struct compat_xloop_info __user *arg)
{
	struct compat_xloop_info info;

	memset(&info, 0, sizeof(info));
	info.xlo_number = info64->xlo_number;
	info.xlo_device = info64->xlo_device;
	info.xlo_inode = info64->xlo_inode;
	info.xlo_rdevice = info64->xlo_rdevice;
	info.xlo_offset = info64->xlo_offset;
	info.xlo_encrypt_type = info64->xlo_encrypt_type;
	info.xlo_encrypt_key_size = info64->xlo_encrypt_key_size;
	info.xlo_flags = info64->xlo_flags;
	info.xlo_init[0] = info64->xlo_init[0];
	info.xlo_init[1] = info64->xlo_init[1];
	info.xlo_file_fmt_type = info64->xlo_file_fmt_type;
	if (info.xlo_encrypt_type == XLO_CRYPT_CRYPTOAPI)
		memcpy(info.xlo_name, info64->xlo_crypt_name, XLO_NAME_SIZE);
	else
		memcpy(info.xlo_name, info64->xlo_file_name, XLO_NAME_SIZE);
	memcpy(info.xlo_encrypt_key, info64->xlo_encrypt_key, XLO_KEY_SIZE);

	/* error in case values were truncated */
	if (info.xlo_device != info64->xlo_device || info.xlo_rdevice != info64->xlo_rdevice ||
	    info.xlo_inode != info64->xlo_inode || info.xlo_offset != info64->xlo_offset ||
	    info.xlo_init[0] != info64->xlo_init[0] || info.xlo_init[1] != info64->xlo_init[1] ||
	    info.xlo_file_fmt_type != info64->xlo_file_fmt_type)
		return -EOVERFLOW;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

static int xloop_set_status_compat(struct xloop_device *xlo, const struct compat_xloop_info __user *arg)
{
	struct xloop_info64 info64;
	int ret;

	ret = xloop_info64_from_compat(arg, &info64);
	if (ret < 0)
		return ret;
	return xloop_set_status(xlo, &info64);
}

static int xloop_get_status_compat(struct xloop_device *xlo, struct compat_xloop_info __user *arg)
{
	struct xloop_info64 info64;
	int err;

	if (!arg)
		return -EINVAL;
	err = xloop_get_status(xlo, &info64);
	if (!err)
		err = xloop_info64_to_compat(&info64, arg);
	return err;
}

static int xlo_compat_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	struct xloop_device *xlo = bdev->bd_disk->private_data;
	int err;

	switch (cmd) {
	case XLOOP_SET_STATUS:
		err = xloop_set_status_compat(xlo, (const struct compat_xloop_info __user *)arg);
		break;
	case XLOOP_GET_STATUS:
		err = xloop_get_status_compat(xlo, (struct compat_xloop_info __user *)arg);
		break;
	case XLOOP_SET_CAPACITY:
	case XLOOP_CLR_FD:
	case XLOOP_GET_STATUS64:
	case XLOOP_SET_STATUS64:
	case XLOOP_CONFIGURE:
		arg = (unsigned long)compat_ptr(arg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
		fallthrough;
#else
		/* fall through */
#endif
	case XLOOP_SET_FD:
	case XLOOP_CHANGE_FD:
	case XLOOP_SET_BLOCK_SIZE:
	case XLOOP_SET_DIRECT_IO:
		err = xlo_ioctl(bdev, mode, cmd, arg);
		break;
	default:
		err = -ENOIOCTLCMD;
		break;
	}
	return err;
}
#endif

static int xlo_open(struct block_device *bdev, fmode_t mode)
{
	struct xloop_device *xlo;
	int err;

	err = mutex_lock_killable(&xloop_ctl_mutex);
	if (err)
		return err;
	xlo = bdev->bd_disk->private_data;
	if (!xlo) {
		err = -ENXIO;
		goto out;
	}

	atomic_inc(&xlo->xlo_refcnt);
out:
	mutex_unlock(&xloop_ctl_mutex);
	return err;
}

static void xlo_release(struct gendisk *disk, fmode_t mode)
{
	struct xloop_device *xlo;

	mutex_lock(&xloop_ctl_mutex);
	xlo = disk->private_data;
	if (atomic_dec_return(&xlo->xlo_refcnt))
		goto out_unlock;

	if (xlo->xlo_flags & XLO_FLAGS_AUTOCLEAR) {
		if (xlo->xlo_state != Xlo_bound)
			goto out_unlock;
		xlo->xlo_state = Xlo_rundown;
		mutex_unlock(&xloop_ctl_mutex);
		/*
		 * In autoclear mode, stop the xloop thread
		 * and remove configuration after last close.
		 */
		__xloop_clr_fd(xlo, true);
		return;
	} else if (xlo->xlo_state == Xlo_bound) {
		/*
		 * Otherwise keep thread (if running) and config,
		 * but flush possible ongoing bios in thread.
		 */
		blk_mq_freeze_queue(xlo->xlo_queue);
		blk_mq_unfreeze_queue(xlo->xlo_queue);
	}

out_unlock:
	mutex_unlock(&xloop_ctl_mutex);
}

static const struct block_device_operations xlo_fops = {
	.owner        = THIS_MODULE,
	.open         = xlo_open,
	.release      = xlo_release,
	.ioctl        = xlo_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = xlo_compat_ioctl,
#endif
};

/*
 * And now the modules code and kernel interface.
 */
static int max_xloop;
module_param(max_xloop, int, 0444);
MODULE_PARM_DESC(max_xloop, "Maximum number of xloop devices");
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per xloop device");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_VERSION(XLOOP_VERSION);
MODULE_ALIAS_BLOCKDEV_MAJOR(XLOOP_MAJOR);

int xloop_register_transfer(struct xloop_func_table *funcs)
{
	unsigned int n = funcs->number;

	if (n >= MAX_XLO_CRYPT || xfer_funcs[n])
		return -EINVAL;
	xfer_funcs[n] = funcs;
	return 0;
}
EXPORT_SYMBOL(xloop_register_transfer);

static int unregister_transfer_cb(int id, void *ptr, void *data)
{
	struct xloop_device *xlo = ptr;
	struct xloop_func_table *xfer = data;

	mutex_lock(&xloop_ctl_mutex);
	if (xlo->xlo_encryption == xfer)
		xloop_release_xfer(xlo);
	mutex_unlock(&xloop_ctl_mutex);
	return 0;
}

int xloop_unregister_transfer(int number)
{
	unsigned int n = number;
	struct xloop_func_table *xfer;

	xfer = xfer_funcs[n];

	if (n == 0 || n >= MAX_XLO_CRYPT || xfer == NULL)
		return -EINVAL;

	xfer_funcs[n] = NULL;
	idr_for_each(&xloop_index_idr, &unregister_transfer_cb, xfer);
	return 0;
}
EXPORT_SYMBOL(xloop_unregister_transfer);

static blk_status_t xloop_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	struct xloop_device *xlo = rq->q->queuedata;

	blk_mq_start_request(rq);

	if (xlo->xlo_state != Xlo_bound)
		return BLK_STS_IOERR;

	switch (req_op(rq)) {
	case REQ_OP_FLUSH:
	case REQ_OP_DISCARD:
	case REQ_OP_WRITE_ZEROES:
		cmd->use_aio = false;
		break;
	default:
		cmd->use_aio = xlo->use_dio;
		break;
	}

	/* always use the first bio's css */
#ifdef CONFIG_BLK_CGROUP
	if (cmd->use_aio && rq->bio && rq->bio->bi_blkg) {
		cmd->css = &bio_blkcg(rq->bio)->css;
		css_get(cmd->css);
	} else
#endif
		cmd->css = NULL;
	kthread_queue_work(&xlo->worker, &cmd->work);

	return BLK_STS_OK;
}

static void xloop_handle_cmd(struct xloop_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	const bool write = op_is_write(req_op(rq));
	struct xloop_device *xlo = rq->q->queuedata;
	int ret = 0;

	if (write && (xlo->xlo_flags & XLO_FLAGS_READ_ONLY)) {
		ret = -EIO;
		goto failed;
	}

	ret = do_req_filebacked(xlo, rq);
failed:
	/* complete non-aio request */
	if (!cmd->use_aio || ret) {
		if (ret == -EOPNOTSUPP)
			cmd->ret = ret;
		else
			cmd->ret = ret ? -EIO : 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
		if (likely(!blk_should_fake_timeout(rq->q)))
			blk_mq_complete_request(rq);
#else
		blk_mq_complete_request(rq);
#endif
	}
}

static void xloop_queue_work(struct kthread_work *work)
{
	struct xloop_cmd *cmd = container_of(work, struct xloop_cmd, work);

	xloop_handle_cmd(cmd);
}

static int xloop_init_request(struct blk_mq_tag_set *set, struct request *rq, unsigned int hctx_idx,
			      unsigned int numa_node)
{
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);

	kthread_init_work(&cmd->work, xloop_queue_work);
	return 0;
}

static const struct blk_mq_ops xloop_mq_ops = {
	.queue_rq = xloop_queue_rq,
	.init_request = xloop_init_request,
	.complete = xlo_complete_rq,
};

static struct dentry *xloop_dbgfs_dir;

static int xloop_add(struct xloop_device **l, int i)
{
	struct xloop_device *xlo;
	struct gendisk *disk;
	int err;

	err = -ENOMEM;
	xlo = kzalloc(sizeof(*xlo), GFP_KERNEL);
	if (!xlo)
		goto out;

	xlo->xlo_state = Xlo_unbound;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&xloop_index_idr, xlo, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&xloop_index_idr, xlo, 0, 0, GFP_KERNEL);
	}
	if (err < 0)
		goto out_free_dev;
	i = err;

	err = -ENOMEM;
	xlo->tag_set.ops = &xloop_mq_ops;
	xlo->tag_set.nr_hw_queues = 1;
	xlo->tag_set.queue_depth = 128;
	xlo->tag_set.numa_node = NUMA_NO_NODE;
	xlo->tag_set.cmd_size = sizeof(struct xloop_cmd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	xlo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING;
#else
	xlo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
#endif
	xlo->tag_set.driver_data = xlo;

	err = blk_mq_alloc_tag_set(&xlo->tag_set);
	if (err)
		goto out_free_idr;

	xlo->xlo_queue = blk_mq_init_queue(&xlo->tag_set);
	if (IS_ERR(xlo->xlo_queue)) {
		err = PTR_ERR(xlo->xlo_queue);
		goto out_cleanup_tags;
	}
	xlo->xlo_queue->queuedata = xlo;

	blk_queue_max_hw_sectors(xlo->xlo_queue, BLK_DEF_MAX_SECTORS);

	/*
	 * By default, we do buffer IO, so it doesn't make sense to enable
	 * merge because the I/O submitted to backing file is handled page by
	 * page. For directio mode, merge does help to dispatch bigger request
	 * to underlayer disk. We will enable merge once directio is enabled.
	 */
	blk_queue_flag_set(QUEUE_FLAG_NOMERGES, xlo->xlo_queue);

	err = -ENOMEM;
	xlo->xlo_fmt = xloop_file_fmt_alloc();
	if (!xlo->xlo_fmt)
		goto out_free_queue;

	xloop_file_fmt_set_xlo(xlo->xlo_fmt, xlo);

	err = -ENOMEM;
	disk = xlo->xlo_disk = alloc_disk(1 << part_shift);
	if (!disk)
		goto out_free_file_fmt;

	/*
	 * Disable partition scanning by default. The in-kernel partition
	 * scanning can be requested individually per-device during its
	 * setup. Userspace can always add and remove partitions from all
	 * devices. The needed partition minors are allocated from the
	 * extended minor space, the main xloop device numbers will continue
	 * to match the xloop minors, regardless of the number of partitions
	 * used.
	 *
	 * If max_part is given, partition scanning is globally enabled for
	 * all xloop devices. The minors for the main xloop devices will be
	 * multiples of max_part.
	 *
	 * Note: Global-for-all-devices, set-only-at-init, read-only module
	 * parameteters like 'max_xloop' and 'max_part' make things needlessly
	 * complicated, are too static, inflexible and may surprise
	 * userspace tools. Parameters like this in general should be avoided.
	 */
	if (!part_shift)
		disk->flags |= GENHD_FL_NO_PART_SCAN;
	disk->flags |= GENHD_FL_EXT_DEVT;
	atomic_set(&xlo->xlo_refcnt, 0);
	xlo->xlo_number = i;
	spin_lock_init(&xlo->xlo_lock);
	disk->major = XLOOP_MAJOR;
	disk->first_minor = i << part_shift;
	disk->fops = &xlo_fops;
	disk->private_data = xlo;
	disk->queue = xlo->xlo_queue;
	sprintf(disk->disk_name, "xloop%d", i);
	add_disk(disk);
	*l = xlo;

	/*
	 * initialize debugfs entries
	 *
	 * create for each loop device a debugfs directory under 'loop' if
	 * the 'block' directory exists, otherwise create the loop directory in
	 * the root directory
	 */
#ifdef CONFIG_DEBUG_FS
	xlo->xlo_dbgfs_dir = debugfs_create_dir(disk->disk_name, xloop_dbgfs_dir);

	if (IS_ERR_OR_NULL(xlo->xlo_dbgfs_dir)) {
		err = -ENODEV;
		xlo->xlo_dbgfs_dir = NULL;
		goto out_free_file_fmt;
	}
#endif

	return xlo->xlo_number;

out_free_file_fmt:
	xloop_file_fmt_free(xlo->xlo_fmt);
out_free_queue:
	blk_cleanup_queue(xlo->xlo_queue);
out_cleanup_tags:
	blk_mq_free_tag_set(&xlo->tag_set);
out_free_idr:
	idr_remove(&xloop_index_idr, i);
out_free_dev:
	kfree(xlo);
out:
	return err;
}

static void xloop_remove(struct xloop_device *xlo)
{
	xloop_file_fmt_free(xlo->xlo_fmt);
	debugfs_remove(xlo->xlo_dbgfs_dir);
	del_gendisk(xlo->xlo_disk);
	blk_cleanup_queue(xlo->xlo_queue);
	blk_mq_free_tag_set(&xlo->tag_set);
	put_disk(xlo->xlo_disk);
	kfree(xlo);
}

static int find_free_cb(int id, void *ptr, void *data)
{
	struct xloop_device *xlo = ptr;
	struct xloop_device **l = data;

	if (xlo->xlo_state == Xlo_unbound) {
		*l = xlo;
		return 1;
	}
	return 0;
}

static int xloop_lookup(struct xloop_device **l, int i)
{
	struct xloop_device *xlo;
	int ret = -ENODEV;

	if (i < 0) {
		int err;

		err = idr_for_each(&xloop_index_idr, &find_free_cb, &xlo);
		if (err == 1) {
			*l = xlo;
			ret = xlo->xlo_number;
		}
		goto out;
	}

	/* lookup and return a specific i */
	xlo = idr_find(&xloop_index_idr, i);
	if (xlo) {
		*l = xlo;
		ret = xlo->xlo_number;
	}
out:
	return ret;
}

static struct kobject *xloop_probe(dev_t dev, int *part, void *data)
{
	struct xloop_device *xlo;
	struct kobject *kobj;
	int err;

	mutex_lock(&xloop_ctl_mutex);
	err = xloop_lookup(&xlo, MINOR(dev) >> part_shift);
	if (err < 0)
		err = xloop_add(&xlo, MINOR(dev) >> part_shift);
	if (err < 0)
		kobj = NULL;
	else
		kobj = get_disk_and_module(xlo->xlo_disk);
	mutex_unlock(&xloop_ctl_mutex);

	*part = 0;
	return kobj;
}

static long xloop_control_ioctl(struct file *file, unsigned int cmd, unsigned long parm)
{
	struct xloop_device *xlo;
	int ret;

	ret = mutex_lock_killable(&xloop_ctl_mutex);
	if (ret)
		return ret;

	ret = -EINVAL;
	switch (cmd) {
	case XLOOP_CTL_ADD:
		ret = xloop_lookup(&xlo, parm);
		if (ret >= 0) {
			ret = -EEXIST;
			break;
		}
		ret = xloop_add(&xlo, parm);
		break;
	case XLOOP_CTL_REMOVE:
		ret = xloop_lookup(&xlo, parm);
		if (ret < 0)
			break;
		if (xlo->xlo_state != Xlo_unbound) {
			ret = -EBUSY;
			break;
		}
		if (atomic_read(&xlo->xlo_refcnt) > 0) {
			ret = -EBUSY;
			break;
		}
		xlo->xlo_disk->private_data = NULL;
		idr_remove(&xloop_index_idr, xlo->xlo_number);
		xloop_remove(xlo);
		break;
	case XLOOP_CTL_GET_FREE:
		ret = xloop_lookup(&xlo, -1);
		if (ret >= 0)
			break;
		ret = xloop_add(&xlo, -1);
	}
	mutex_unlock(&xloop_ctl_mutex);

	return ret;
}

static const struct file_operations xloop_ctl_fops = {
	.open           = nonseekable_open,
	.unlocked_ioctl = xloop_control_ioctl,
	.compat_ioctl   = xloop_control_ioctl,
	.owner          = THIS_MODULE,
	.llseek         = noop_llseek,
};

static struct miscdevice xloop_misc = {
	.minor = XLOOP_CTRL_MINOR,
	.name  = "xloop-control",
	.fops  = &xloop_ctl_fops,
};

MODULE_ALIAS_MISCDEV(XLOOP_CTRL_MINOR);
MODULE_ALIAS("devname:xloop-control");

static int __init xloop_init(void)
{
	int i, nr;
	unsigned long range;
	struct xloop_device *xlo;
	int err;

	part_shift = 0;
	if (max_part > 0) {
		part_shift = fls(max_part);

		/*
		 * Adjust max_part according to part_shift as it is exported
		 * to user space so that user can decide correct minor number
		 * if [s]he want to create more devices.
		 *
		 * Note that -1 is required because partition 0 is reserved
		 * for the whole disk.
		 */
		max_part = (1UL << part_shift) - 1;
	}

	if ((1UL << part_shift) > DISK_MAX_PARTS) {
		err = -EINVAL;
		goto err_out;
	}

	if (max_xloop > 1UL << (MINORBITS - part_shift)) {
		err = -EINVAL;
		goto err_out;
	}

	/*
	 * If max_xloop is specified, create that many devices upfront.
	 * This also becomes a hard limit. If max_xloop is not specified,
	 * create CONFIG_BLK_DEV_XLOOP_MIN_COUNT xloop devices at module
	 * init time. xloop devices can be requested on-demand with the
	 * /dev/xloop-control interface, or be instantiated by accessing
	 * a 'dead' device node.
	 */
	if (max_xloop) {
		nr = CONFIG_BLK_DEV_XLOOP_MIN_COUNT;
		range = 1UL << MINORBITS;
	}

	err = misc_register(&xloop_misc);
	if (err < 0)
		goto err_out;

	if (register_blkdev(XLOOP_MAJOR, "xloop")) {
		err = -EIO;
		goto misc_out;
	}

#ifdef CONFIG_DEBUG_FS
	xloop_dbgfs_dir = debugfs_create_dir("xloop", NULL);
	if (IS_ERR_OR_NULL(xloop_dbgfs_dir)) {
		err = -ENODEV;
		goto misc_out;
	}
#endif

	blk_register_region(MKDEV(XLOOP_MAJOR, 0), range, THIS_MODULE, xloop_probe, NULL, NULL);

	/* pre-create number of devices given by config or max_xloop */
	mutex_lock(&xloop_ctl_mutex);
	for (i = 0; i < nr; i++)
		xloop_add(&xlo, i);
	mutex_unlock(&xloop_ctl_mutex);

	pr_info("module in version %s loaded\n", XLOOP_VERSION);
	return 0;

misc_out:
	misc_deregister(&xloop_misc);
err_out:
	return err;
}

static int xloop_exit_cb(int id, void *ptr, void *data)
{
	struct xloop_device *xlo = ptr;

	xloop_remove(xlo);
	return 0;
}

static void __exit xloop_exit(void)
{
	unsigned long range;

	range = max_xloop ? max_xloop << part_shift : 1UL << MINORBITS;

	mutex_lock(&xloop_ctl_mutex);

	idr_for_each(&xloop_index_idr, &xloop_exit_cb, NULL);
	idr_destroy(&xloop_index_idr);

	blk_unregister_region(MKDEV(XLOOP_MAJOR, 0), range);
	unregister_blkdev(XLOOP_MAJOR, "xloop");

#ifdef CONFIG_DEBUG_FS
	debugfs_remove(xloop_dbgfs_dir);
#endif

	misc_deregister(&xloop_misc);

	mutex_unlock(&xloop_ctl_mutex);

	pr_info("exit module\n");
}

module_init(xloop_init);
module_exit(xloop_exit);

#ifndef MODULE
static int __init max_xloop_setup(char *str)
{
	max_xloop = simple_strtol(str, NULL, 0);
	return 1;
}

__setup("max_xloop=", max_xloop_setup);
#endif
