// SPDX-License-Identifier: GPL-2.0-only
/*
 * xloop_main.c
 *
 * Written by Theodore Ts'o, 3/29/93
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
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
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/blk-cgroup.h>
#include <linux/sched/mm.h>
#include <linux/statfs.h>
#include <linux/uaccess.h>
//#include <linux/blk-mq.h>
//#include <linux/spinlock.h>

#include <linux/version.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include <xloop/version.h>

#include "xloop_file_fmt.h"
#include "xloop_main.h"

#define XLOOP_IDLE_WORKER_TIMEOUT (60 * HZ)
#define XLOOP_DEFAULT_HW_Q_DEPTH 128

static DEFINE_IDR(xloop_index_idr);
static DEFINE_MUTEX(xloop_ctl_mutex);
static DEFINE_MUTEX(xloop_validate_mutex);

/**
 * xloop_global_lock_killable() - take locks for safe xloop_validate_file() test
 *
 * @xlo: struct xloop_device
 * @global: true if @xlo is about to bind another "struct xloop_device", false otherwise
 *
 * Returns 0 on success, -EINTR otherwise.
 *
 * Since xloop_validate_file() traverses on other "struct xloop_device" if
 * is_xloop_device() is true, we need a global lock for serializing concurrent
 * xloop_configure()/xloop_change_fd()/__xloop_clr_fd() calls.
 */
static int xloop_global_lock_killable(struct xloop_device *xlo, bool global)
{
	int err;

	if (global) {
		err = mutex_lock_killable(&xloop_validate_mutex);
		if (err)
			return err;
	}
	err = mutex_lock_killable(&xlo->xlo_mutex);
	if (err && global)
		mutex_unlock(&xloop_validate_mutex);
	return err;
}

/**
 * xloop_global_unlock() - release locks taken by xloop_global_lock_killable()
 *
 * @xlo: struct xloop_device
 * @global: true if @xlo was about to bind another "struct xloop_device", false otherwise
 */
static void xloop_global_unlock(struct xloop_device *xlo, bool global)
{
	mutex_unlock(&xlo->xlo_mutex);
	if (global)
		mutex_unlock(&xloop_validate_mutex);
}

static int max_part;
static int part_shift;

struct device *xloop_device_to_dev(struct xloop_device *xlo)
{
	return disk_to_dev(xlo->xlo_disk);
}
EXPORT_SYMBOL(xloop_device_to_dev);

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
	unsigned dio_align = 0;
	bool use_dio;

	if (inode->i_sb->s_bdev) {
		sb_bsize = bdev_logical_block_size(inode->i_sb->s_bdev);
		dio_align = sb_bsize - 1;
	}

	/*
	 * We support direct I/O only if xlo_offset is aligned with the
	 * logical I/O size of backing device, and the logical block
	 * size of xloop is bigger than the backing device's.
	 *
	 * TODO: the above condition may be loosed in the future, and
	 * direct I/O may be switched runtime at that time because most
	 * of requests in sane applications should be PAGE_SIZE aligned
	 */
	if (dio) {
		if (queue_logical_block_size(xlo->xlo_queue) >= sb_bsize &&
		    !(xlo->xlo_offset & dio_align) &&
		    (file->f_mode & FMODE_CAN_ODIRECT))
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
	 * XLO_FLAGS_READ_ONLY, both are set from kernel, and xlosetup
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
 * xloop_set_size() - sets device size and notifies userspace
 * @xlo: struct xloop_device to set the size for
 * @size: new size of the xloop device
 *
 * Callers must validate that the size passed into this function fits into
 * a sector_t, eg using xloop_validate_size()
 */
static void xloop_set_size(struct xloop_device *xlo, loff_t size)
{
	if (!set_capacity_and_notify(xlo->xlo_disk, size))
		kobject_uevent(&disk_to_dev(xlo->xlo_disk)->kobj, KOBJ_CHANGE);
}

static void xlo_complete_rq(struct request *rq)
{
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	blk_status_t ret = BLK_STS_OK;

	if (!cmd->use_aio || cmd->ret < 0 || cmd->ret == blk_rq_bytes(rq) ||
	    req_op(rq) != REQ_OP_READ) {
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
	 * by io submit style function like xloop_file_fmt_read_aio(), one
	 * blocker is that xloop_file_fmt_read() need to call flush_dcache_page
	 * after the page is written from kernel, and it isn't easy to handle
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
	__xloop_update_dio(xlo, (xlo->xlo_backing_file->f_flags & O_DIRECT) |
				xlo->use_dio);
}

static void xloop_reread_partitions(struct xloop_device *xlo)
{
	int rc;

	mutex_lock(&xlo->xlo_disk->open_mutex);
	rc = bdev_disk_changed(xlo->xlo_disk, false);
	mutex_unlock(&xlo->xlo_disk->open_mutex);
	if (rc)
		dev_warn(xloop_device_to_dev(xlo),
			"partition scan of xloop%d (%s) failed (rc=%d)\n",
			xlo->xlo_number, xlo->xlo_file_name, rc);
}

static inline int is_xloop_device(struct file *file)
{
	struct inode *i = file->f_mapping->host;

	return i && S_ISBLK(i->i_mode) && imajor(i) == XLOOP_MAJOR;
}

static int xloop_validate_file(struct file *file, struct block_device *bdev)
{
	struct inode	*inode = file->f_mapping->host;
	struct file	*f = file;

	/* Avoid recursion */
	while (is_xloop_device(f)) {
		struct xloop_device *l;

		lockdep_assert_held(&xloop_validate_mutex);
		if (f->f_mapping->host->i_rdev == bdev->bd_dev)
			return -EBADF;

		l = I_BDEV(f->f_mapping->host)->bd_disk->private_data;
		if (l->xlo_state != Xlo_bound)
			return -EINVAL;
		/* Order wrt setting xlo->xlo_backing_file in xloop_configure(). */
		rmb();
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
static int xloop_change_fd(struct xloop_device *xlo, struct block_device *bdev,
			  unsigned int arg)
{
	struct file *file = fget(arg);
	struct file *old_file;
	int error;
	bool partscan;
	bool is_xloop;

	if (!file)
		return -EBADF;

	/* suppress uevents while reconfiguring the device */
	dev_set_uevent_suppress(disk_to_dev(xlo->xlo_disk), 1);

	is_xloop = is_xloop_device(file);
	error = xloop_global_lock_killable(xlo, is_xloop);
	if (error)
		goto out_putf;
	error = -ENXIO;
	if (xlo->xlo_state != Xlo_bound)
		goto out_err;

	/* the xloop device has to be read-only */
	error = -EINVAL;
	if (!(xlo->xlo_flags & XLO_FLAGS_READ_ONLY))
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
	disk_force_media_change(xlo->xlo_disk);
	blk_mq_freeze_queue(xlo->xlo_queue);
	mapping_set_gfp_mask(old_file->f_mapping, xlo->old_gfp_mask);
	xlo->xlo_backing_file = file;
	xlo->old_gfp_mask = mapping_gfp_mask(file->f_mapping);
	mapping_set_gfp_mask(file->f_mapping,
			     xlo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));
	xloop_update_dio(xlo);
	blk_mq_unfreeze_queue(xlo->xlo_queue);
	partscan = xlo->xlo_flags & XLO_FLAGS_PARTSCAN;
	xloop_global_unlock(xlo, is_xloop);

	/*
	 * Flush xloop_validate_file() before fput(), for l->xlo_backing_file
	 * might be pointing at old_file which might be the last reference.
	 */
	if (!is_xloop) {
		mutex_lock(&xloop_validate_mutex);
		mutex_unlock(&xloop_validate_mutex);
	}
	/*
	 * We must drop file reference outside of xlo_mutex as dropping
	 * the file ref can take open_mutex which creates circular locking
	 * dependency.
	 */
	fput(old_file);
	if (partscan)
		xloop_reread_partitions(xlo);

	error = 0;
done:
	/* enable and uncork uevent now that we are done */
	dev_set_uevent_suppress(disk_to_dev(xlo->xlo_disk), 0);
	return error;

out_err:
	xloop_global_unlock(xlo, is_xloop);
out_putf:
	fput(file);
	goto done;
}

/* xloop sysfs attributes */

static ssize_t xloop_attr_show(struct device *dev, char *page,
			      ssize_t (*callback)(struct xloop_device *, char *))
{
	struct gendisk *disk = dev_to_disk(dev);
	struct xloop_device *xlo = disk->private_data;

	return callback(xlo, page);
}

#define XLOOP_ATTR_RO(_name)						\
static ssize_t xloop_attr_##_name##_show(struct xloop_device *, char *);	\
static ssize_t xloop_attr_do_show_##_name(struct device *d,		\
				struct device_attribute *attr, char *b)	\
{									\
	return xloop_attr_show(d, b, xloop_attr_##_name##_show);		\
}									\
static struct device_attribute xloop_attr_##_name =			\
	__ATTR(_name, 0444, xloop_attr_do_show_##_name, NULL);

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
	/* do not use sysfs_emit here, doesn't work with offset */
	len += sprintf(buf + len, "\n");

	return len;
}

static ssize_t xloop_attr_offset_show(struct xloop_device *xlo, char *buf)
{
	return sysfs_emit(buf, "%llu\n", (unsigned long long)xlo->xlo_offset);
}

static ssize_t xloop_attr_sizelimit_show(struct xloop_device *xlo, char *buf)
{
	return sysfs_emit(buf, "%llu\n", (unsigned long long)xlo->xlo_sizelimit);
}

static ssize_t xloop_attr_autoclear_show(struct xloop_device *xlo, char *buf)
{
	int autoclear = (xlo->xlo_flags & XLO_FLAGS_AUTOCLEAR);

	return sysfs_emit(buf, "%s\n", autoclear ? "1" : "0");
}

static ssize_t xloop_attr_partscan_show(struct xloop_device *xlo, char *buf)
{
	int partscan = (xlo->xlo_flags & XLO_FLAGS_PARTSCAN);

	return sysfs_emit(buf, "%s\n", partscan ? "1" : "0");
}

static ssize_t xloop_attr_dio_show(struct xloop_device *xlo, char *buf)
{
	int dio = (xlo->xlo_flags & XLO_FLAGS_DIRECT_IO);

	return sysfs_emit(buf, "%s\n", dio ? "1" : "0");
}

XLOOP_ATTR_RO(backing_file);
XLOOP_ATTR_RO(file_fmt_type);
XLOOP_ATTR_RO(offset);
XLOOP_ATTR_RO(sizelimit);
XLOOP_ATTR_RO(autoclear);
XLOOP_ATTR_RO(partscan);
XLOOP_ATTR_RO(dio);

static struct attribute *xloop_attrs[] = {
	&xloop_attr_backing_file.attr,
	&xloop_attr_file_fmt_type.attr,
	&xloop_attr_offset.attr,
	&xloop_attr_sizelimit.attr,
	&xloop_attr_autoclear.attr,
	&xloop_attr_partscan.attr,
	&xloop_attr_dio.attr,
	NULL,
};

static struct attribute_group xloop_attribute_group = {
	.name = "xloop",
	.attrs = xloop_attrs,
};

static void xloop_sysfs_init(struct xloop_device *xlo)
{
	xlo->sysfs_inited = !sysfs_create_group(&disk_to_dev(xlo->xlo_disk)->kobj,
						&xloop_attribute_group);
}

static void xloop_sysfs_exit(struct xloop_device *xlo)
{
	if (xlo->sysfs_inited)
		sysfs_remove_group(&disk_to_dev(xlo->xlo_disk)->kobj,
				   &xloop_attribute_group);
}

static void xloop_config_discard(struct xloop_device *xlo,
		struct queue_limits *lim)
{
	struct file *file = xlo->xlo_backing_file;
	struct inode *inode = file->f_mapping->host;
	u32 granularity = 0, max_discard_sectors = 0;
	struct kstatfs sbuf;

	/*
	 * If the backing device is a block device, mirror its zeroing
	 * capability. Set the discard sectors to the block device's zeroing
	 * capabilities because xloop discards result in blkdev_issue_zeroout(),
	 * not blkdev_issue_discard(). This maintains consistent behavior with
	 * file-backed xloop devices: discarded regions read back as zero.
	 */
	if (S_ISBLK(inode->i_mode)) {
		struct request_queue *backingq = bdev_get_queue(I_BDEV(inode));

		max_discard_sectors = backingq->limits.max_write_zeroes_sectors;
		granularity = bdev_discard_granularity(I_BDEV(inode)) ?:
			queue_physical_block_size(backingq);

	/*
	 * We use punch hole to reclaim the free space used by the
	 * image a.k.a. discard.
	 */
	} else if (file->f_op->fallocate && !vfs_statfs(&file->f_path, &sbuf)) {
		max_discard_sectors = UINT_MAX >> 9;
		granularity = sbuf.f_bsize;
	}

	lim->max_hw_discard_sectors = max_discard_sectors;
	lim->max_write_zeroes_sectors = max_discard_sectors;
	if (max_discard_sectors)
		lim->discard_granularity = granularity;
	else
		lim->discard_granularity = 0;
}

struct xloop_worker {
	struct rb_node rb_node;
	struct work_struct work;
	struct list_head cmd_list;
	struct list_head idle_list;
	struct xloop_device *xlo;
	struct cgroup_subsys_state *blkcg_css;
	unsigned long last_ran_at;
};

static void xloop_workfn(struct work_struct *work);

#ifdef CONFIG_BLK_CGROUP
static inline int queue_on_root_worker(struct cgroup_subsys_state *css)
{
	return !css || css == blkcg_root_css;
}
#else
static inline int queue_on_root_worker(struct cgroup_subsys_state *css)
{
	return !css;
}
#endif

static void xloop_queue_work(struct xloop_device *xlo, struct xloop_cmd *cmd)
{
	struct rb_node **node, *parent = NULL;
	struct xloop_worker *cur_worker, *worker = NULL;
	struct work_struct *work;
	struct list_head *cmd_list;

	spin_lock_irq(&xlo->xlo_work_lock);

	if (queue_on_root_worker(cmd->blkcg_css))
		goto queue_work;

	node = &xlo->worker_tree.rb_node;

	while (*node) {
		parent = *node;
		cur_worker = container_of(*node, struct xloop_worker, rb_node);
		if (cur_worker->blkcg_css == cmd->blkcg_css) {
			worker = cur_worker;
			break;
		} else if ((long)cur_worker->blkcg_css < (long)cmd->blkcg_css) {
			node = &(*node)->rb_left;
		} else {
			node = &(*node)->rb_right;
		}
	}
	if (worker)
		goto queue_work;

	worker = kzalloc(sizeof(struct xloop_worker), GFP_NOWAIT | __GFP_NOWARN);
	/*
	 * In the event we cannot allocate a worker, just queue on the
	 * rootcg worker and issue the I/O as the rootcg
	 */
	if (!worker) {
		cmd->blkcg_css = NULL;
		if (cmd->memcg_css)
			css_put(cmd->memcg_css);
		cmd->memcg_css = NULL;
		goto queue_work;
	}

	worker->blkcg_css = cmd->blkcg_css;
	css_get(worker->blkcg_css);
	INIT_WORK(&worker->work, xloop_workfn);
	INIT_LIST_HEAD(&worker->cmd_list);
	INIT_LIST_HEAD(&worker->idle_list);
	worker->xlo = xlo;
	rb_link_node(&worker->rb_node, parent, node);
	rb_insert_color(&worker->rb_node, &xlo->worker_tree);
queue_work:
	if (worker) {
		/*
		 * We need to remove from the idle list here while
		 * holding the lock so that the idle timer doesn't
		 * free the worker
		 */
		if (!list_empty(&worker->idle_list))
			list_del_init(&worker->idle_list);
		work = &worker->work;
		cmd_list = &worker->cmd_list;
	} else {
		work = &xlo->rootcg_work;
		cmd_list = &xlo->rootcg_cmd_list;
	}
	list_add_tail(&cmd->list_entry, cmd_list);
	queue_work(xlo->workqueue, work);
	spin_unlock_irq(&xlo->xlo_work_lock);
}

static void xloop_set_timer(struct xloop_device *xlo)
{
	timer_reduce(&xlo->timer, jiffies + XLOOP_IDLE_WORKER_TIMEOUT);
}

static void xloop_free_idle_workers(struct xloop_device *xlo, bool delete_all)
{
	struct xloop_worker *pos, *worker;

	spin_lock_irq(&xlo->xlo_work_lock);
	list_for_each_entry_safe(worker, pos, &xlo->idle_worker_list,
				idle_list) {
		if (!delete_all &&
		    time_is_after_jiffies(worker->last_ran_at +
					  XLOOP_IDLE_WORKER_TIMEOUT))
			break;
		list_del(&worker->idle_list);
		rb_erase(&worker->rb_node, &xlo->worker_tree);
		css_put(worker->blkcg_css);
		kfree(worker);
	}
	if (!list_empty(&xlo->idle_worker_list))
		xloop_set_timer(xlo);
	spin_unlock_irq(&xlo->xlo_work_lock);
}

static void xloop_free_idle_workers_timer(struct timer_list *timer)
{
	struct xloop_device *xlo = container_of(timer, struct xloop_device, timer);

	return xloop_free_idle_workers(xlo, false);
}

/**
 * xloop_set_status_from_info - configure device from xloop_info
 * @xlo: struct xloop_device to configure
 * @info: struct xloop_info64 to configure the device with
 *
 * Configures the xloop device parameters according to the passed
 * in xloop_info64 configuration.
 */
static int
xloop_set_status_from_info(struct xloop_device *xlo,
			  const struct xloop_info64 *info)
{
	if ((unsigned int) info->xlo_encrypt_key_size > XLO_KEY_SIZE)
		return -EINVAL;

	switch (info->xlo_encrypt_type) {
	case XLO_CRYPT_NONE:
		break;
	case XLO_CRYPT_XOR:
		pr_warn("support for the xor transformation has been removed.\n");
		return -EINVAL;
	case XLO_CRYPT_CRYPTOAPI:
		pr_warn("support for cryptoloop has been removed.  Use dm-crypt instead.\n");
		return -EINVAL;
	default:
		return -EINVAL;
	}

	/* Avoid assigning overflow values */
	if (info->xlo_offset > LLONG_MAX || info->xlo_sizelimit > LLONG_MAX)
		return -EOVERFLOW;

	xlo->xlo_offset = info->xlo_offset;
	xlo->xlo_sizelimit = info->xlo_sizelimit;

	memcpy(xlo->xlo_file_name, info->xlo_file_name, XLO_NAME_SIZE);
	xlo->xlo_file_name[XLO_NAME_SIZE-1] = 0;
	xlo->xlo_flags = info->xlo_flags;
	return 0;
}

static unsigned short xloop_default_blocksize(struct xloop_device *xlo,
		struct block_device *backing_bdev)
{
	/* In case of direct I/O, match underlying block size */
	if ((xlo->xlo_backing_file->f_flags & O_DIRECT) && backing_bdev)
		return bdev_logical_block_size(backing_bdev);
	return SECTOR_SIZE;
}

static int xloop_reconfigure_limits(struct xloop_device *xlo, unsigned short bsize)
{
	struct file *file = xlo->xlo_backing_file;
	struct inode *inode = file->f_mapping->host;
	struct block_device *backing_bdev = NULL;
	struct queue_limits lim;

	if (S_ISBLK(inode->i_mode))
		backing_bdev = I_BDEV(inode);
	else if (inode->i_sb->s_bdev)
		backing_bdev = inode->i_sb->s_bdev;

	if (!bsize)
		bsize = xloop_default_blocksize(xlo, backing_bdev);

	lim = queue_limits_start_update(xlo->xlo_queue);
	lim.logical_block_size = bsize;
	lim.physical_block_size = bsize;
	lim.io_min = bsize;
	lim.features &= ~(BLK_FEAT_WRITE_CACHE | BLK_FEAT_ROTATIONAL);
	if (file->f_op->fsync && !(xlo->xlo_flags & XLO_FLAGS_READ_ONLY))
		lim.features |= BLK_FEAT_WRITE_CACHE;
	if (backing_bdev && !bdev_nonrot(backing_bdev))
		lim.features |= BLK_FEAT_ROTATIONAL;
	xloop_config_discard(xlo, &lim);
	return queue_limits_commit_update(xlo->xlo_queue, &lim);
}

static int xloop_configure(struct xloop_device *xlo, blk_mode_t mode,
			  struct block_device *bdev,
			  const struct xloop_config *config)
{
	struct file *file = fget(config->fd);
	struct address_space *mapping;
	int error;
	loff_t size;
	bool partscan;
	bool is_xloop;

	if (!file)
		return -EBADF;
	is_xloop = is_xloop_device(file);

	/* This is safe, since we have a reference from open(). */
	__module_get(THIS_MODULE);

	/*
	 * If we don't hold exclusive handle for the device, upgrade to it
	 * here to avoid changing device under exclusive owner.
	 */
	if (!(mode & BLK_OPEN_EXCL)) {
		error = bd_prepare_to_claim(bdev, xloop_configure, NULL);
		if (error)
			goto out_putf;
	}

	error = xloop_global_lock_killable(xlo, is_xloop);
	if (error)
		goto out_bdev;

	error = -EBUSY;
	if (xlo->xlo_state != Xlo_unbound)
		goto out_unlock;

	error = xloop_validate_file(file, bdev);
	if (error)
		goto out_unlock;

	mapping = file->f_mapping;

	if ((config->info.xlo_flags & ~XLOOP_CONFIGURE_SETTABLE_FLAGS) != 0) {
		error = -EINVAL;
		goto out_unlock;
	}

	error = xloop_set_status_from_info(xlo, &config->info);
	if (error)
		goto out_unlock;

	if (!(file->f_mode & FMODE_WRITE) || !(mode & BLK_OPEN_WRITE) ||
	    !file->f_op->write_iter)
		xlo->xlo_flags |= XLO_FLAGS_READ_ONLY;

	if (!xlo->workqueue) {
		xlo->workqueue = alloc_workqueue("xloop%d",
						WQ_UNBOUND | WQ_FREEZABLE,
						0, xlo->xlo_number);
		if (!xlo->workqueue) {
			error = -ENOMEM;
			goto out_unlock;
		}
	}

	/* suppress uevents while reconfiguring the device */
	dev_set_uevent_suppress(disk_to_dev(xlo->xlo_disk), 1);

	disk_force_media_change(xlo->xlo_disk);
	set_disk_ro(xlo->xlo_disk, (xlo->xlo_flags & XLO_FLAGS_READ_ONLY) != 0);

	xlo->use_dio = xlo->xlo_flags & XLO_FLAGS_DIRECT_IO;
	xlo->xlo_device = bdev;
	xlo->xlo_backing_file = file;
	xlo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, xlo->old_gfp_mask & ~(__GFP_IO|__GFP_FS));

	error = xloop_reconfigure_limits(xlo, config->block_size);
	if (error)
		goto out_unlock;

	error = xloop_file_fmt_init(xlo->xlo_fmt, config->info.xlo_file_fmt_type);
	if (error) /* TODO: Undo stuff right above */
		goto out_unlock;

	xloop_update_dio(xlo);
	xloop_sysfs_init(xlo);

	size = get_xloop_size(xlo, file);
	xloop_set_size(xlo, size);

	/* Order wrt reading xlo_state in xloop_validate_file(). */
	wmb();

	xlo->xlo_state = Xlo_bound;
	if (part_shift)
		xlo->xlo_flags |= XLO_FLAGS_PARTSCAN;
	partscan = xlo->xlo_flags & XLO_FLAGS_PARTSCAN;
	if (partscan)
		clear_bit(GD_SUPPRESS_PART_SCAN, &xlo->xlo_disk->state);

	/* enable and uncork uevent now that we are done */
	dev_set_uevent_suppress(disk_to_dev(xlo->xlo_disk), 0);

	xloop_global_unlock(xlo, is_xloop);
	if (partscan)
		xloop_reread_partitions(xlo);

	if (!(mode & BLK_OPEN_EXCL))
		bd_abort_claiming(bdev, xloop_configure);

	return 0;

out_unlock:
	xloop_global_unlock(xlo, is_xloop);
out_bdev:
	if (!(mode & BLK_OPEN_EXCL))
		bd_abort_claiming(bdev, xloop_configure);
out_putf:
	fput(file);
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);
	return error;
}

static void __xloop_clr_fd(struct xloop_device *xlo, bool release)
{
	struct queue_limits lim;
	struct file *filp;
	gfp_t gfp = xlo->old_gfp_mask;

	xloop_file_fmt_exit(xlo->xlo_fmt);

	spin_lock_irq(&xlo->xlo_lock);
	filp = xlo->xlo_backing_file;
	xlo->xlo_backing_file = NULL;
	spin_unlock_irq(&xlo->xlo_lock);

	xlo->xlo_device = NULL;
	xlo->xlo_offset = 0;
	xlo->xlo_sizelimit = 0;
	memset(xlo->xlo_file_name, 0, XLO_NAME_SIZE);

	/* reset the block size to the default */
	lim = queue_limits_start_update(xlo->xlo_queue);
	lim.logical_block_size = SECTOR_SIZE;
	lim.physical_block_size = SECTOR_SIZE;
	lim.io_min = SECTOR_SIZE;
	queue_limits_commit_update(xlo->xlo_queue, &lim);

	invalidate_disk(xlo->xlo_disk);
	xloop_sysfs_exit(xlo);
	/* let user-space know about this change */
	kobject_uevent(&disk_to_dev(xlo->xlo_disk)->kobj, KOBJ_CHANGE);
	mapping_set_gfp_mask(filp->f_mapping, gfp);
	/* This is safe: open() is still holding a reference. */
	module_put(THIS_MODULE);

	disk_force_media_change(xlo->xlo_disk);

	if (xlo->xlo_flags & XLO_FLAGS_PARTSCAN) {
		int err;

		/*
		 * open_mutex has been held already in release path, so don't
		 * acquire it if this function is called in such case.
		 *
		 * If the reread partition isn't from release path, xlo_refcnt
		 * must be at least one and it can only become zero when the
		 * current holder is released.
		 */
		err = bdev_disk_changed(xlo->xlo_disk, false);
		if (err)
			pr_warn("%s: partition scan of xloop%d failed (rc=%d)\n",
				__func__, xlo->xlo_number, err);
		/* Device is gone, no point in returning error */
	}

	/*
	 * xlo->xlo_state is set to Xlo_unbound here after above partscan has
	 * finished. There cannot be anybody else entering __xloop_clr_fd() as
	 * Xlo_rundown state protects us from all the other places trying to
	 * change the 'xlo' device.
	 */
	xlo->xlo_flags = 0;
	if (!part_shift)
		set_bit(GD_SUPPRESS_PART_SCAN, &xlo->xlo_disk->state);
	mutex_lock(&xlo->xlo_mutex);
	xlo->xlo_state = Xlo_unbound;
	mutex_unlock(&xlo->xlo_mutex);

	/*
	 * Need not hold xlo_mutex to fput backing file. Calling fput holding
	 * xlo_mutex triggers a circular lock dependency possibility warning as
	 * fput can take open_mutex which is usually taken before xlo_mutex.
	 */
	fput(filp);
}

static int xloop_clr_fd(struct xloop_device *xlo)
{
	int err;

	/*
	 * Since xlo_ioctl() is called without locks held, it is possible that
	 * xloop_configure()/xloop_change_fd() and xloop_clr_fd() run in parallel.
	 *
	 * Therefore, use global lock when setting Xlo_rundown state in order to
	 * make sure that xloop_validate_file() will fail if the "struct file"
	 * which xloop_configure()/xloop_change_fd() found via fget() was this
	 * xloop device.
	 */
	err = xloop_global_lock_killable(xlo, true);
	if (err)
		return err;
	if (xlo->xlo_state != Xlo_bound) {
		xloop_global_unlock(xlo, true);
		return -ENXIO;
	}
	/*
	 * Mark the device for removing the backing device on last close.
	 * If we are the only opener, also switch the state to roundown here to
	 * prevent new openers from coming in.
	 */

	xlo->xlo_flags |= XLO_FLAGS_AUTOCLEAR;
	if (disk_openers(xlo->xlo_disk) == 1)
		xlo->xlo_state = Xlo_rundown;
	xloop_global_unlock(xlo, true);

	return 0;
}

static int
xloop_set_status(struct xloop_device *xlo, const struct xloop_info64 *info)
{
	int err;
	int prev_xlo_flags;
	bool partscan = false;
	bool size_changed = false;

	err = mutex_lock_killable(&xlo->xlo_mutex);
	if (err)
		return err;
	if (xlo->xlo_state != Xlo_bound) {
		err = -ENXIO;
		goto out_unlock;
	}

	if (xlo->xlo_offset != info->xlo_offset ||
	    xlo->xlo_sizelimit != info->xlo_sizelimit) {
		size_changed = true;
		sync_blockdev(xlo->xlo_device);
		invalidate_bdev(xlo->xlo_device);
	}

	/* I/O need to be drained during transfer transition */
	blk_mq_freeze_queue(xlo->xlo_queue);

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

	/* update dio if xlo_offset or transfer is changed */
	__xloop_update_dio(xlo, xlo->use_dio);

out_unfreeze:
	blk_mq_unfreeze_queue(xlo->xlo_queue);

	if (!err && (xlo->xlo_flags & XLO_FLAGS_PARTSCAN) &&
	     !(prev_xlo_flags & XLO_FLAGS_PARTSCAN)) {
		clear_bit(GD_SUPPRESS_PART_SCAN, &xlo->xlo_disk->state);
		partscan = true;
	}
out_unlock:
	mutex_unlock(&xlo->xlo_mutex);
	if (partscan)
		xloop_reread_partitions(xlo);

	return err;
}

static int
xloop_get_status(struct xloop_device *xlo, struct xloop_info64 *info)
{
	struct path path;
	struct kstat stat;
	int ret;

	ret = mutex_lock_killable(&xlo->xlo_mutex);
	if (ret)
		return ret;
	if (xlo->xlo_state != Xlo_bound) {
		mutex_unlock(&xlo->xlo_mutex);
		return -ENXIO;
	}

	memset(info, 0, sizeof(*info));
	info->xlo_number = xlo->xlo_number;
	info->xlo_offset = xlo->xlo_offset;
	info->xlo_sizelimit = xlo->xlo_sizelimit;
	info->xlo_flags = xlo->xlo_flags;
	memcpy(info->xlo_file_name, xlo->xlo_file_name, XLO_NAME_SIZE);

	/* Drop xlo_mutex while we call into the filesystem. */
	path = xlo->xlo_backing_file->f_path;
	path_get(&path);
	mutex_unlock(&xlo->xlo_mutex);
	ret = vfs_getattr(&path, &stat, STATX_INO, AT_STATX_SYNC_AS_STAT);
	if (!ret) {
		info->xlo_device = huge_encode_dev(stat.dev);
		info->xlo_inode = stat.ino;
		info->xlo_rdevice = huge_encode_dev(stat.rdev);
	}
	path_put(&path);
	return ret;
}

static void
xloop_info64_from_old(const struct xloop_info *info, struct xloop_info64 *info64)
{
	memset(info64, 0, sizeof(*info64));
	info64->xlo_number = info->xlo_number;
	info64->xlo_device = info->xlo_device;
	info64->xlo_inode = info->xlo_inode;
	info64->xlo_rdevice = info->xlo_rdevice;
	info64->xlo_offset = info->xlo_offset;
	info64->xlo_sizelimit = 0;
	info64->xlo_flags = info->xlo_flags;
	memcpy(info64->xlo_file_name, info->xlo_name, XLO_NAME_SIZE);
}

static int
xloop_info64_to_old(const struct xloop_info64 *info64, struct xloop_info *info)
{
	memset(info, 0, sizeof(*info));
	info->xlo_number = info64->xlo_number;
	info->xlo_device = info64->xlo_device;
	info->xlo_inode = info64->xlo_inode;
	info->xlo_rdevice = info64->xlo_rdevice;
	info->xlo_offset = info64->xlo_offset;
	info->xlo_flags = info64->xlo_flags;
	memcpy(info->xlo_name, info64->xlo_file_name, XLO_NAME_SIZE);

	/* error in case values were truncated */
	if (info->xlo_device != info64->xlo_device ||
	    info->xlo_rdevice != info64->xlo_rdevice ||
	    info->xlo_inode != info64->xlo_inode ||
	    info->xlo_offset != info64->xlo_offset)
		return -EOVERFLOW;

	return 0;
}

static int
xloop_set_status_old(struct xloop_device *xlo, const struct xloop_info __user *arg)
{
	struct xloop_info info;
	struct xloop_info64 info64;

	if (copy_from_user(&info, arg, sizeof(struct xloop_info)))
		return -EFAULT;
	xloop_info64_from_old(&info, &info64);
	return xloop_set_status(xlo, &info64);
}

static int
xloop_set_status64(struct xloop_device *xlo, const struct xloop_info64 __user *arg)
{
	struct xloop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof(struct xloop_info64)))
		return -EFAULT;
	return xloop_set_status(xlo, &info64);
}

static int
xloop_get_status_old(struct xloop_device *xlo, struct xloop_info __user *arg)
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

static int
xloop_get_status64(struct xloop_device *xlo, struct xloop_info64 __user *arg)
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

	if (xlo->xlo_queue->limits.logical_block_size == arg)
		return 0;

	sync_blockdev(xlo->xlo_device);
	invalidate_bdev(xlo->xlo_device);

	blk_mq_freeze_queue(xlo->xlo_queue);
	err = xloop_reconfigure_limits(xlo, arg);
	xloop_update_dio(xlo);
	blk_mq_unfreeze_queue(xlo->xlo_queue);

	return err;
}

static int xlo_simple_ioctl(struct xloop_device *xlo, unsigned int cmd,
			   unsigned long arg)
{
	int err;

	err = mutex_lock_killable(&xlo->xlo_mutex);
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
		err = -EINVAL;
	}
	mutex_unlock(&xlo->xlo_mutex);
	return err;
}

static int xlo_ioctl(struct block_device *bdev, blk_mode_t mode,
	unsigned int cmd, unsigned long arg)
{
	struct xloop_device *xlo = bdev->bd_disk->private_data;
	void __user *argp = (void __user *) arg;
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
		if ((mode & BLK_OPEN_WRITE) || capable(CAP_SYS_ADMIN))
			err = xloop_set_status_old(xlo, argp);
		break;
	case XLOOP_GET_STATUS:
		return xloop_get_status_old(xlo, argp);
	case XLOOP_SET_STATUS64:
		err = -EPERM;
		if ((mode & BLK_OPEN_WRITE) || capable(CAP_SYS_ADMIN))
			err = xloop_set_status64(xlo, argp);
		break;
	case XLOOP_GET_STATUS64:
		return xloop_get_status64(xlo, argp);
	case XLOOP_SET_CAPACITY:
	case XLOOP_SET_DIRECT_IO:
	case XLOOP_SET_BLOCK_SIZE:
		if (!(mode & BLK_OPEN_WRITE) && !capable(CAP_SYS_ADMIN))
			return -EPERM;
		fallthrough;
	default:
		err = xlo_simple_ioctl(xlo, cmd, arg);
		break;
	}

	return err;
}

#ifdef CONFIG_COMPAT
struct compat_xloop_info {
	compat_int_t	xlo_number;      /* ioctl r/o */
	compat_dev_t	xlo_device;      /* ioctl r/o */
	compat_ulong_t	xlo_inode;       /* ioctl r/o */
	compat_dev_t	xlo_rdevice;     /* ioctl r/o */
	compat_int_t	xlo_offset;
	compat_int_t	xlo_encrypt_type;        /* obsolete, ignored */
	compat_int_t	xlo_encrypt_key_size;    /* ioctl w/o */
	compat_int_t	xlo_flags;       /* ioctl r/o */
	char		xlo_name[XLO_NAME_SIZE];
	unsigned char	xlo_encrypt_key[XLO_KEY_SIZE]; /* ioctl w/o */
	compat_ulong_t	xlo_init[2];
	char		reserved[4];
};

/*
 * Transfer 32-bit compatibility structure in userspace to 64-bit xloop info
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int
xloop_info64_from_compat(const struct compat_xloop_info __user *arg,
			struct xloop_info64 *info64)
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
	info64->xlo_flags = info.xlo_flags;
	memcpy(info64->xlo_file_name, info.xlo_name, XLO_NAME_SIZE);
	return 0;
}

/*
 * Transfer 64-bit xloop info to 32-bit compatibility structure in userspace
 * - noinlined to reduce stack space usage in main part of driver
 */
static noinline int
xloop_info64_to_compat(const struct xloop_info64 *info64,
		      struct compat_xloop_info __user *arg)
{
	struct compat_xloop_info info;

	memset(&info, 0, sizeof(info));
	info.xlo_number = info64->xlo_number;
	info.xlo_device = info64->xlo_device;
	info.xlo_inode = info64->xlo_inode;
	info.xlo_rdevice = info64->xlo_rdevice;
	info.xlo_offset = info64->xlo_offset;
	info.xlo_flags = info64->xlo_flags;
	memcpy(info.xlo_name, info64->xlo_file_name, XLO_NAME_SIZE);

	/* error in case values were truncated */
	if (info.xlo_device != info64->xlo_device ||
	    info.xlo_rdevice != info64->xlo_rdevice ||
	    info.xlo_inode != info64->xlo_inode ||
	    info.xlo_offset != info64->xlo_offset)
		return -EOVERFLOW;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

static int
xloop_set_status_compat(struct xloop_device *xlo,
		       const struct compat_xloop_info __user *arg)
{
	struct xloop_info64 info64;
	int ret;

	ret = xloop_info64_from_compat(arg, &info64);
	if (ret < 0)
		return ret;
	return xloop_set_status(xlo, &info64);
}

static int
xloop_get_status_compat(struct xloop_device *xlo,
		       struct compat_xloop_info __user *arg)
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

static int xlo_compat_ioctl(struct block_device *bdev, blk_mode_t mode,
			   unsigned int cmd, unsigned long arg)
{
	struct xloop_device *xlo = bdev->bd_disk->private_data;
	int err;

	switch (cmd) {
	case XLOOP_SET_STATUS:
		err = xloop_set_status_compat(xlo,
			     (const struct compat_xloop_info __user *)arg);
		break;
	case XLOOP_GET_STATUS:
		err = xloop_get_status_compat(xlo,
				     (struct compat_xloop_info __user *)arg);
		break;
	case XLOOP_SET_CAPACITY:
	case XLOOP_CLR_FD:
	case XLOOP_GET_STATUS64:
	case XLOOP_SET_STATUS64:
	case XLOOP_CONFIGURE:
		arg = (unsigned long) compat_ptr(arg);
		fallthrough;
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

static void xlo_release(struct gendisk *disk)
{
	struct xloop_device *xlo = disk->private_data;

	if (disk_openers(disk) > 0)
		return;

	mutex_lock(&xlo->xlo_mutex);
	if (xlo->xlo_state == Xlo_bound && (xlo->xlo_flags & XLO_FLAGS_AUTOCLEAR)) {
		xlo->xlo_state = Xlo_rundown;
		mutex_unlock(&xlo->xlo_mutex);
		/*
		 * In autoclear mode, stop the xloop thread
		 * and remove configuration after last close.
		 */
		__xloop_clr_fd(xlo, true);
		return;
	}
	mutex_unlock(&xlo->xlo_mutex);
}

static void xlo_free_disk(struct gendisk *disk)
{
	struct xloop_device *xlo = disk->private_data;

	if (xlo->workqueue)
		destroy_workqueue(xlo->workqueue);
	xloop_free_idle_workers(xlo, true);
	timer_shutdown_sync(&xlo->timer);
	mutex_destroy(&xlo->xlo_mutex);
	kfree(xlo);
}

static const struct block_device_operations xlo_fops = {
	.owner =	THIS_MODULE,
	.release =	xlo_release,
	.ioctl =	xlo_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl =	xlo_compat_ioctl,
#endif
	.free_disk =	xlo_free_disk,
};

/*
 * And now the modules code and kernel interface.
 */

/*
 * If max_xloop is specified, create that many devices upfront.
 * This also becomes a hard limit. If max_xloop is not specified,
 * the default isn't a hard limit (as before commit 85c50197716c
 * changed the default value from 0 for max_xloop=0 reasons), just
 * create CONFIG_BLK_DEV_XLOOP_MIN_COUNT xloop devices at module
 * init time. Loop devices can be requested on-demand with the
 * /dev/loop-control interface, or be instantiated by accessing
 * a 'dead' device node.
 */
static int max_xloop = CONFIG_BLK_DEV_XLOOP_MIN_COUNT;

#ifdef CONFIG_BLOCK_LEGACY_AUTOLOAD
static bool max_xloop_specified;

static int max_xloop_param_set_int(const char *val,
				  const struct kernel_param *kp)
{
	int ret;

	ret = param_set_int(val, kp);
	if (ret < 0)
		return ret;

	max_xloop_specified = true;
	return 0;
}

static const struct kernel_param_ops max_xloop_param_ops = {
	.set = max_xloop_param_set_int,
	.get = param_get_int,
};

module_param_cb(max_xloop, &max_xloop_param_ops, &max_xloop, 0444);
MODULE_PARM_DESC(max_xloop, "Maximum number of xloop devices");
#else
module_param(max_xloop, int, 0444);
MODULE_PARM_DESC(max_xloop, "Initial number of xloop devices");
#endif

module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Maximum number of partitions per xloop device");

static int hw_queue_depth = XLOOP_DEFAULT_HW_Q_DEPTH;

static int xloop_set_hw_queue_depth(const char *s, const struct kernel_param *p)
{
	int qd, ret;

	ret = kstrtoint(s, 0, &qd);
	if (ret < 0)
		return ret;
	if (qd < 1)
		return -EINVAL;
	hw_queue_depth = qd;
	return 0;
}

static const struct kernel_param_ops xloop_hw_qdepth_param_ops = {
	.set	= xloop_set_hw_queue_depth,
	.get	= param_get_int,
};

device_param_cb(hw_queue_depth, &xloop_hw_qdepth_param_ops, &hw_queue_depth, 0444);
MODULE_PARM_DESC(hw_queue_depth, "Queue depth for each hardware queue. Default: " __stringify(XLOOP_DEFAULT_HW_Q_DEPTH));

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_VERSION(XLOOP_VERSION);
MODULE_ALIAS_BLOCKDEV_MAJOR(XLOOP_MAJOR);

static blk_status_t xloop_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
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
	cmd->blkcg_css = NULL;
	cmd->memcg_css = NULL;
#ifdef CONFIG_BLK_CGROUP
	if (rq->bio) {
		cmd->blkcg_css = bio_blkcg_css(rq->bio);
#ifdef CONFIG_MEMCG
		if (cmd->blkcg_css) {
			cmd->memcg_css =
				cgroup_get_e_css(cmd->blkcg_css->cgroup,
						&memory_cgrp_subsys);
		}
#endif
	}
#endif
	xloop_queue_work(xlo, cmd);

	return BLK_STS_OK;
}

static void xloop_handle_cmd(struct xloop_cmd *cmd)
{
	struct cgroup_subsys_state *cmd_blkcg_css = cmd->blkcg_css;
	struct cgroup_subsys_state *cmd_memcg_css = cmd->memcg_css;
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	const bool write = op_is_write(req_op(rq));
	struct xloop_device *xlo = rq->q->queuedata;
	int ret = 0;
	struct mem_cgroup *old_memcg = NULL;
	const bool use_aio = cmd->use_aio;

	if (write && (xlo->xlo_flags & XLO_FLAGS_READ_ONLY)) {
		ret = -EIO;
		goto failed;
	}

	if (cmd_blkcg_css)
		kthread_associate_blkcg(cmd_blkcg_css);
	if (cmd_memcg_css)
		old_memcg = set_active_memcg(
			mem_cgroup_from_css(cmd_memcg_css));

	/*
	 * do_req_filebacked() may call blk_mq_complete_request() synchronously
	 * or asynchronously if using aio. Hence, do not touch 'cmd' after
	 * do_req_filebacked() has returned unless we are sure that 'cmd' has
	 * not yet been completed.
	 */
	ret = do_req_filebacked(xlo, rq);

	if (cmd_blkcg_css)
		kthread_associate_blkcg(NULL);

	if (cmd_memcg_css) {
		set_active_memcg(old_memcg);
		css_put(cmd_memcg_css);
	}
 failed:
	/* complete non-aio request */
	if (!use_aio || ret) {
		if (ret == -EOPNOTSUPP)
			cmd->ret = ret;
		else
			cmd->ret = ret ? -EIO : 0;
		if (likely(!blk_should_fake_timeout(rq->q)))
			blk_mq_complete_request(rq);
	}
}

static void xloop_process_work(struct xloop_worker *worker,
			struct list_head *cmd_list, struct xloop_device *xlo)
{
	int orig_flags = current->flags;
	struct xloop_cmd *cmd;

	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
	spin_lock_irq(&xlo->xlo_work_lock);
	while (!list_empty(cmd_list)) {
		cmd = container_of(
			cmd_list->next, struct xloop_cmd, list_entry);
		list_del(cmd_list->next);
		spin_unlock_irq(&xlo->xlo_work_lock);

		xloop_handle_cmd(cmd);
		cond_resched();

		spin_lock_irq(&xlo->xlo_work_lock);
	}

	/*
	 * We only add to the idle list if there are no pending cmds
	 * *and* the worker will not run again which ensures that it
	 * is safe to free any worker on the idle list
	 */
	if (worker && !work_pending(&worker->work)) {
		worker->last_ran_at = jiffies;
		list_add_tail(&worker->idle_list, &xlo->idle_worker_list);
		xloop_set_timer(xlo);
	}
	spin_unlock_irq(&xlo->xlo_work_lock);
	current->flags = orig_flags;
}

static void xloop_workfn(struct work_struct *work)
{
	struct xloop_worker *worker =
		container_of(work, struct xloop_worker, work);
	xloop_process_work(worker, &worker->cmd_list, worker->xlo);
}

static void xloop_rootcg_workfn(struct work_struct *work)
{
	struct xloop_device *xlo =
		container_of(work, struct xloop_device, rootcg_work);
	xloop_process_work(NULL, &xlo->rootcg_cmd_list, xlo);
}

static const struct blk_mq_ops xloop_mq_ops = {
	.queue_rq       = xloop_queue_rq,
	.complete	= xlo_complete_rq,
};

#ifdef CONFIG_DEBUG_FS
static struct dentry *xloop_dbgfs_dir;
#endif

static int xloop_add(int i)
{
	struct queue_limits lim = {
		/*
		 * Random number picked from the historic block max_sectors cap.
		 */
		.max_hw_sectors		= 2560u,
	};
	struct xloop_device *xlo;
	struct gendisk *disk;
	int err;

	err = -ENOMEM;
	xlo = kzalloc(sizeof(*xlo), GFP_KERNEL);
	if (!xlo)
		goto out;
	xlo->worker_tree = RB_ROOT;
	INIT_LIST_HEAD(&xlo->idle_worker_list);
	timer_setup(&xlo->timer, xloop_free_idle_workers_timer, TIMER_DEFERRABLE);
	xlo->xlo_state = Xlo_unbound;

	err = mutex_lock_killable(&xloop_ctl_mutex);
	if (err)
		goto out_free_dev;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&xloop_index_idr, xlo, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&xloop_index_idr, xlo, 0, 0, GFP_KERNEL);
	}
	mutex_unlock(&xloop_ctl_mutex);
	if (err < 0)
		goto out_free_dev;
	i = err;

	xlo->tag_set.ops = &xloop_mq_ops;
	xlo->tag_set.nr_hw_queues = 1;
	xlo->tag_set.queue_depth = hw_queue_depth;
	xlo->tag_set.numa_node = NUMA_NO_NODE;
	xlo->tag_set.cmd_size = sizeof(struct xloop_cmd);
	xlo->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING |
		BLK_MQ_F_NO_SCHED_BY_DEFAULT;
	xlo->tag_set.driver_data = xlo;

	err = blk_mq_alloc_tag_set(&xlo->tag_set);
	if (err)
		goto out_free_idr;

	disk = xlo->xlo_disk = blk_mq_alloc_disk(&xlo->tag_set, &lim, xlo);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_cleanup_tags;
	}
	xlo->xlo_queue = xlo->xlo_disk->queue;

	err = -ENOMEM;
	xlo->xlo_fmt = xloop_file_fmt_alloc();
	if (!xlo->xlo_fmt)
		goto out_cleanup_disk;

	xloop_file_fmt_set_xlo(xlo->xlo_fmt, xlo);

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
		set_bit(GD_SUPPRESS_PART_SCAN, &disk->state);
	mutex_init(&xlo->xlo_mutex);
	xlo->xlo_number		= i;
	spin_lock_init(&xlo->xlo_lock);
	spin_lock_init(&xlo->xlo_work_lock);
	INIT_WORK(&xlo->rootcg_work, xloop_rootcg_workfn);
	INIT_LIST_HEAD(&xlo->rootcg_cmd_list);
	disk->major		= XLOOP_MAJOR;
	disk->first_minor	= i << part_shift;
	disk->minors		= 1 << part_shift;
	disk->fops		= &xlo_fops;
	disk->private_data	= xlo;
	disk->queue		= xlo->xlo_queue;
	disk->events		= DISK_EVENT_MEDIA_CHANGE;
	disk->event_flags	= DISK_EVENT_FLAG_UEVENT;
	sprintf(disk->disk_name, "xloop%d", i);
	/* Make this xloop device reachable from pathname. */
	err = add_disk(disk);
	if (err)
		goto out_free_file_fmt;

	/* Show this xloop device. */
	mutex_lock(&xloop_ctl_mutex);
	xlo->idr_visible = true;
	mutex_unlock(&xloop_ctl_mutex);

	/*
	 * initialize debugfs entries
	 *
	 * create for each xloop device a debugfs directory under 'xloop' if
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

	return i;

out_free_file_fmt:
	xloop_file_fmt_free(xlo->xlo_fmt);
out_cleanup_disk:
	put_disk(disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&xlo->tag_set);
out_free_idr:
	mutex_lock(&xloop_ctl_mutex);
	idr_remove(&xloop_index_idr, i);
	mutex_unlock(&xloop_ctl_mutex);
out_free_dev:
	kfree(xlo);
out:
	return err;
}

static void xloop_remove(struct xloop_device *xlo)
{
	xloop_file_fmt_free(xlo->xlo_fmt);
#ifdef CONFIG_DEBUG_FS
	debugfs_remove(xlo->xlo_dbgfs_dir);
#endif
	/* Make this xloop device unreachable from pathname. */
	del_gendisk(xlo->xlo_disk);
	blk_mq_free_tag_set(&xlo->tag_set);

	mutex_lock(&xloop_ctl_mutex);
	idr_remove(&xloop_index_idr, xlo->xlo_number);
	mutex_unlock(&xloop_ctl_mutex);

	put_disk(xlo->xlo_disk);
}

#ifdef CONFIG_BLOCK_LEGACY_AUTOLOAD
static void xloop_probe(dev_t dev)
{
	int idx = MINOR(dev) >> part_shift;

	if (max_xloop_specified && max_xloop && idx >= max_xloop)
		return;
	xloop_add(idx);
}
#else
#define xloop_probe NULL
#endif /* !CONFIG_BLOCK_LEGACY_AUTOLOAD */

static int xloop_control_remove(int idx)
{
	struct xloop_device *xlo;
	int ret;

	if (idx < 0) {
		pr_warn_once("deleting an unspecified xloop device is not supported.\n");
		return -EINVAL;
	}

	/* Hide this xloop device for serialization. */
	ret = mutex_lock_killable(&xloop_ctl_mutex);
	if (ret)
		return ret;
	xlo = idr_find(&xloop_index_idr, idx);
	if (!xlo || !xlo->idr_visible)
		ret = -ENODEV;
	else
		xlo->idr_visible = false;
	mutex_unlock(&xloop_ctl_mutex);
	if (ret)
		return ret;

	/* Check whether this xloop device can be removed. */
	ret = mutex_lock_killable(&xlo->xlo_mutex);
	if (ret)
		goto mark_visible;
	if (xlo->xlo_state != Xlo_unbound || disk_openers(xlo->xlo_disk) > 0) {
		mutex_unlock(&xlo->xlo_mutex);
		ret = -EBUSY;
		goto mark_visible;
	}
	/* Mark this xloop device as no more bound, but not quite unbound yet */
	xlo->xlo_state = Xlo_deleting;
	mutex_unlock(&xlo->xlo_mutex);

	xloop_remove(xlo);
	return 0;

mark_visible:
	/* Show this xloop device again. */
	mutex_lock(&xloop_ctl_mutex);
	xlo->idr_visible = true;
	mutex_unlock(&xloop_ctl_mutex);
	return ret;
}

static int xloop_control_get_free(int idx)
{
	struct xloop_device *xlo;
	int id, ret;

	ret = mutex_lock_killable(&xloop_ctl_mutex);
	if (ret)
		return ret;
	idr_for_each_entry(&xloop_index_idr, xlo, id) {
		/* Hitting a race results in creating a new xloop device which is harmless. */
		if (xlo->idr_visible && data_race(xlo->xlo_state) == Xlo_unbound)
			goto found;
	}
	mutex_unlock(&xloop_ctl_mutex);
	return xloop_add(-1);
found:
	mutex_unlock(&xloop_ctl_mutex);
	return id;
}

static long xloop_control_ioctl(struct file *file, unsigned int cmd,
			       unsigned long parm)
{
	switch (cmd) {
	case XLOOP_CTL_ADD:
		return xloop_add(parm);
	case XLOOP_CTL_REMOVE:
		return xloop_control_remove(parm);
	case XLOOP_CTL_GET_FREE:
		return xloop_control_get_free(parm);
	default:
		return -ENOSYS;
	}
}

static const struct file_operations xloop_ctl_fops = {
	.open		= nonseekable_open,
	.unlocked_ioctl	= xloop_control_ioctl,
	.compat_ioctl	= xloop_control_ioctl,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

static struct miscdevice xloop_misc = {
	.minor		= XLOOP_CTRL_MINOR,
	.name		= "xloop-control",
	.fops		= &xloop_ctl_fops,
};

MODULE_ALIAS_MISCDEV(XLOOP_CTRL_MINOR);
MODULE_ALIAS("devname:xloop-control");

static int __init xloop_init(void)
{
	int i;
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

	err = misc_register(&xloop_misc);
	if (err < 0)
		goto err_out;


	if (__register_blkdev(XLOOP_MAJOR, "xloop", xloop_probe)) {
		err = -EIO;
		goto misc_out;
	}

#ifdef CONFIG_DEBUG_FS
	xloop_dbgfs_dir = debugfs_create_dir("xloop", NULL);
	if (IS_ERR_OR_NULL(xloop_dbgfs_dir)) {
		err = -ENODEV;
		goto blkdev_out;
	}
#endif

	/* pre-create number of devices given by config or max_xloop */
	for (i = 0; i < max_xloop; i++)
		xloop_add(i);

	pr_info("module (version %s) loaded\n", XLOOP_VERSION);
	return 0;

#ifdef CONFIG_DEBUG_FS
blkdev_out:
	unregister_blkdev(XLOOP_MAJOR, "xloop");
#endif
misc_out:
	misc_deregister(&xloop_misc);
err_out:
	return err;
}

static void __exit xloop_exit(void)
{
	struct xloop_device *xlo;
	int id;

	unregister_blkdev(XLOOP_MAJOR, "xloop");
	misc_deregister(&xloop_misc);

	/*
	 * There is no need to use xloop_ctl_mutex here, for nobody else can
	 * access xloop_index_idr when this module is unloading (unless forced
	 * module unloading is requested). If this is not a clean unloading,
	 * we have no means to avoid kernel crash.
	 */
	idr_for_each_entry(&xloop_index_idr, xlo, id)
		xloop_remove(xlo);

	idr_destroy(&xloop_index_idr);

#ifdef CONFIG_DEBUG_FS
	debugfs_remove(xloop_dbgfs_dir);
#endif

	pr_info("exit module\n");
}

module_init(xloop_init);
module_exit(xloop_exit);

#ifndef MODULE
static int __init max_xloop_setup(char *str)
{
	max_xloop = simple_strtol(str, NULL, 0);
#ifdef CONFIG_BLOCK_LEGACY_AUTOLOAD
	max_xloop_specified = true;
#endif
	return 1;
}

__setup("max_xloop=", max_xloop_setup);
#endif
