// SPDX-License-Identifier: GPL-2.0
/*
 * xloop_file_fmt_raw.c
 *
 * RAW file format driver for the xloop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/compiler.h>
#include <linux/blk-cgroup.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/version.h>

#include <xloop/version.h>

#include "xloop_file_fmt.h"

static inline loff_t __raw_file_fmt_rq_get_pos(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);

	return ((loff_t)blk_rq_pos(rq) << 9) + xlo->xlo_offset;
}

static int raw_file_fmt_read(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct iov_iter i;
	ssize_t len;
	struct xloop_device *xlo;
	loff_t pos;

	xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len); // READ -> ITER_DEST at some point
		len = vfs_iter_read(xlo->xlo_backing_file, &i, &pos, 0);
		if (len < 0)
			return len;

		flush_dcache_page(bvec.bv_page);

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);
			break;
		}
		cond_resched();
	}

	return 0;
}

static void __raw_file_fmt_rw_aio_do_completion(struct xloop_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);

	if (!atomic_dec_and_test(&cmd->ref))
		return;
	kfree(cmd->bvec);
	cmd->bvec = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	if (likely(!blk_should_fake_timeout(rq->q)))
		blk_mq_complete_request(rq);
#else
	blk_mq_complete_request(rq);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) && !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 2))
static void __raw_file_fmt_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
#else
static void __raw_file_fmt_rw_aio_complete(struct kiocb *iocb, long ret)
#endif
{
	struct xloop_cmd *cmd = container_of(iocb, struct xloop_cmd, iocb);


#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	if (cmd->css)
		css_put(cmd->css);
#endif

	cmd->ret = ret;
	__raw_file_fmt_rw_aio_do_completion(cmd);
}

static int __raw_file_fmt_rw_aio(struct xloop_device *xlo, struct xloop_cmd *cmd, loff_t pos, bool rw)
{
	struct iov_iter iter;
	struct req_iterator rq_iter;
	struct bio_vec *bvec;
	struct request *rq = blk_mq_rq_from_pdu(cmd);
	struct bio *bio = rq->bio;
	struct file *file = xlo->xlo_backing_file;
	struct bio_vec tmp;
	unsigned int offset;
	int nr_bvec = 0;
	int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
	rq_for_each_bvec(tmp, rq, rq_iter)
		nr_bvec++;
#endif

	if (rq->bio != rq->biotail) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
		__rq_for_each_bio(bio, rq)
			nr_bvec += bio_segments(bio);
#endif
		bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec), GFP_NOIO);
		if (!bvec)
			return -EIO;
		cmd->bvec = bvec;

		/*
		 * The bios of the request may be started from the middle of
		 * the 'bvec' because of bio splitting, so we can't directly
		 * copy bio->bi_iov_vec to new bvec. The rq_for_each_bvec
		 * API will take care of all details for us.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
		rq_for_each_bvec(tmp, rq, rq_iter) {
#else
		rq_for_each_segment(tmp, rq, rq_iter) {
#endif
			*bvec = tmp;
			bvec++;
		}
		bvec = cmd->bvec;
		offset = 0;
	} else {
		/*
		 * Same here, this bio may be started from the middle of the
		 * 'bvec' because of bio splitting, so offset from the bvec
		 * must be passed to iov iterator
		 */
		offset = bio->bi_iter.bi_bvec_done;
		bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
		nr_bvec = bio_segments(bio);
#endif
	}
	atomic_set(&cmd->ref, 2);

	iov_iter_bvec(&iter, rw, bvec, nr_bvec, blk_rq_bytes(rq));
	iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
	cmd->iocb.ki_complete = __raw_file_fmt_rw_aio_complete;
	cmd->iocb.ki_flags = IOCB_DIRECT;
	cmd->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	if (cmd->css)
		kthread_associate_blkcg(cmd->css);
#endif

	if (rw == WRITE)
		ret = call_write_iter(file, &cmd->iocb, &iter);
	else
		ret = call_read_iter(file, &cmd->iocb, &iter);

	__raw_file_fmt_rw_aio_do_completion(cmd);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	kthread_associate_blkcg(NULL);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0) && !RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 2))
	if (ret != -EIOCBQUEUED)
		cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
#else
	if (ret != -EIOCBQUEUED)
		cmd->iocb.ki_complete(&cmd->iocb, ret);
#endif
	return 0;
}

static int raw_file_fmt_read_aio(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	return __raw_file_fmt_rw_aio(xlo, cmd, pos, READ);
}

static int __raw_file_fmt_write_bvec(struct file *file, struct bio_vec *bvec, loff_t *ppos)
{
	struct iov_iter i;
	ssize_t bw;

	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);

	file_start_write(file);
	bw = vfs_iter_write(file, &i, ppos, 0);
	file_end_write(file);

	if (likely(bw == bvec->bv_len))
		return 0;

	pr_err_ratelimited("write error at byte offset %llu, length %i.\n", (unsigned long long)*ppos, bvec->bv_len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}

static int raw_file_fmt_write(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int ret = 0;
	struct xloop_device *xlo;
	loff_t pos;

	xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		ret = __raw_file_fmt_write_bvec(xlo->xlo_backing_file, &bvec, &pos);
		if (ret < 0)
			break;
		cond_resched();
	}

	return ret;
}

static int raw_file_fmt_write_aio(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	return __raw_file_fmt_rw_aio(xlo, cmd, pos, WRITE);
}

static int __raw_file_fmt_fallocate(struct xloop_device *xlo, struct request *rq, loff_t pos, int mode)
{
	/*
	 * We use fallocate to manipulate the space mappings used by the image
	 * a.k.a. discard/zerorange.
	 */
	struct file *file = xlo->xlo_backing_file;
	int ret;

	mode |= FALLOC_FL_KEEP_SIZE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0) || RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
	if (!bdev_max_discard_sectors(xlo->xlo_device))
#else
	if (!blk_queue_discard(xlo->xlo_queue))
#endif
		return -EOPNOTSUPP;

	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;
	return ret;
}

static int raw_file_fmt_write_zeros(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);

	/*
	 * If the caller doesn't want deallocation, call zeroout to
	 * write zeroes the range. Otherwise, punch them out.
	 */
	return __raw_file_fmt_fallocate(xlo, rq, pos,
					(rq->cmd_flags & REQ_NOUNMAP) ? FALLOC_FL_ZERO_RANGE : FALLOC_FL_PUNCH_HOLE);
}

static int raw_file_fmt_discard(struct xloop_file_fmt *xlo_fmt, struct request *rq)
{
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);

	return __raw_file_fmt_fallocate(xlo, rq, pos, FALLOC_FL_PUNCH_HOLE);
}

static int raw_file_fmt_flush(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct file *file = xlo->xlo_backing_file;
	int ret = vfs_fsync(file, 0);

	if (unlikely(ret && ret != -EINVAL))
		ret = -EIO;

	return ret;
}

static loff_t raw_file_fmt_sector_size(struct xloop_file_fmt *xlo_fmt, struct file *file, loff_t offset,
				       loff_t sizelimit)
{
	loff_t xloopsize;

	/* Compute xloopsize in bytes */
	xloopsize = i_size_read(file->f_mapping->host);
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

static struct xloop_file_fmt_ops raw_file_fmt_ops = {
	.init        = NULL,
	.exit        = NULL,
	.read        = raw_file_fmt_read,
	.write       = raw_file_fmt_write,
	.read_aio    = raw_file_fmt_read_aio,
	.write_aio   = raw_file_fmt_write_aio,
	.write_zeros = raw_file_fmt_write_zeros,
	.discard     = raw_file_fmt_discard,
	.flush       = raw_file_fmt_flush,
	.sector_size = raw_file_fmt_sector_size,
};

static struct xloop_file_fmt_driver raw_file_fmt_driver = {
	.name          = "RAW",
	.file_fmt_type = XLO_FILE_FMT_RAW,
	.ops           = &raw_file_fmt_ops,
	.owner         = THIS_MODULE,
};

static int __init xloop_file_fmt_raw_init(void)
{
	pr_info("init xloop device RAW file format driver\n");
	return xloop_file_fmt_register_driver(&raw_file_fmt_driver);
}

static void __exit xloop_file_fmt_raw_exit(void)
{
	pr_info("exit xloop device RAW file format driver\n");
	xloop_file_fmt_unregister_driver(&raw_file_fmt_driver);
}

module_init(xloop_file_fmt_raw_init);
module_exit(xloop_file_fmt_raw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_DESCRIPTION("xloop device RAW file format driver");
MODULE_SOFTDEP("pre: xloop");
MODULE_VERSION(XLOOP_VERSION);
