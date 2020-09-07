/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xloop_file_fmt_raw.c
 *
 * RAW file format driver for the xloop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

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

#include "loop_file_fmt.h"

static inline loff_t __raw_file_fmt_rq_get_pos(struct xloop_file_fmt *xlo_fmt,
					       struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	return ((loff_t) blk_rq_pos(rq) << 9) + xlo->xlo_offset;
}

/* transfer function for DEPRECATED cryptoxloop support */
static inline int __raw_file_fmt_do_transfer(struct xloop_device *xlo, int cmd,
					struct page *rpage, unsigned roffs,
					struct page *lpage, unsigned loffs,
					int size, sector_t rblock)
{
	int ret;

	ret = xlo->transfer(xlo, cmd, rpage, roffs, lpage, loffs, size, rblock);
	if (likely(!ret))
		return 0;

	printk_ratelimited(KERN_ERR
		"xloop_file_fmt_raw: Transfer error at byte offset %llu, length %i.\n",
		(unsigned long long)rblock << 9, size);
	return ret;
}

static int __raw_file_fmt_read_transfer(struct xloop_device *xlo,
		struct request *rq, loff_t pos)
{
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct iov_iter i;
	struct page *page;
	ssize_t len;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		loff_t offset = pos;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;

		iov_iter_bvec(&i, READ, &b, 1, b.bv_len);
		len = vfs_iter_read(xlo->xlo_backing_file, &i, &pos, 0);
		if (len < 0) {
			ret = len;
			goto out_free_page;
		}

		ret = __raw_file_fmt_do_transfer(xlo, READ, page, 0, bvec.bv_page,
			bvec.bv_offset, len, offset >> 9);
		if (ret)
			goto out_free_page;

		flush_dcache_page(bvec.bv_page);

		if (len != bvec.bv_len) {
			struct bio *bio;

			__rq_for_each_bio(bio, rq)
				zero_fill_bio(bio);
			break;
		}
	}

	ret = 0;
out_free_page:
	__free_page(page);
	return ret;
}

static int raw_file_fmt_read(struct xloop_file_fmt *xlo_fmt,
			     struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct iov_iter i;
	ssize_t len;
	struct xloop_device *xlo;
	loff_t pos;

	xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	if (xlo->transfer)
		return __raw_file_fmt_read_transfer(xlo, rq, pos);

	rq_for_each_segment(bvec, rq, iter) {
		iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
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

static void __raw_file_fmt_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct xloop_cmd *cmd = container_of(iocb, struct xloop_cmd, iocb);

	if (cmd->css)
		css_put(cmd->css);
	cmd->ret = ret;
	__raw_file_fmt_rw_aio_do_completion(cmd);
}

static int __raw_file_fmt_rw_aio(struct xloop_device *xlo,
			struct xloop_cmd *cmd, loff_t pos, bool rw)
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

	rq_for_each_bvec(tmp, rq, rq_iter)
		nr_bvec++;

	if (rq->bio != rq->biotail) {

		bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec),
				     GFP_NOIO);
		if (!bvec)
			return -EIO;
		cmd->bvec = bvec;

		/*
		 * The bios of the request may be started from the middle of
		 * the 'bvec' because of bio splitting, so we can't directly
		 * copy bio->bi_iov_vec to new bvec. The rq_for_each_bvec
		 * API will take care of all details for us.
		 */
		rq_for_each_bvec(tmp, rq, rq_iter) {
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
	}
	atomic_set(&cmd->ref, 2);

	iov_iter_bvec(&iter, rw, bvec, nr_bvec, blk_rq_bytes(rq));
	iter.iov_offset = offset;

	cmd->iocb.ki_pos = pos;
	cmd->iocb.ki_filp = file;
	cmd->iocb.ki_complete = __raw_file_fmt_rw_aio_complete;
	cmd->iocb.ki_flags = IOCB_DIRECT;
	cmd->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
	if (cmd->css)
		kthread_associate_blkcg(cmd->css);

	if (rw == WRITE)
		ret = call_write_iter(file, &cmd->iocb, &iter);
	else
		ret = call_read_iter(file, &cmd->iocb, &iter);

	__raw_file_fmt_rw_aio_do_completion(cmd);
	kthread_associate_blkcg(NULL);

	if (ret != -EIOCBQUEUED)
		cmd->iocb.ki_complete(&cmd->iocb, ret, 0);
	return 0;
}

static int raw_file_fmt_read_aio(struct xloop_file_fmt *xlo_fmt,
				 struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	return __raw_file_fmt_rw_aio(xlo, cmd, pos, READ);
}

static int __raw_file_fmt_write_bvec(struct file *file,
				     struct bio_vec *bvec,
				     loff_t *ppos)
{
	struct iov_iter i;
	ssize_t bw;

	iov_iter_bvec(&i, WRITE, bvec, 1, bvec->bv_len);

	file_start_write(file);
	bw = vfs_iter_write(file, &i, ppos, 0);
	file_end_write(file);

	if (likely(bw ==  bvec->bv_len))
		return 0;

	printk_ratelimited(KERN_ERR
		"xloop_file_fmt_raw: Write error at byte offset %llu, length "
		"%i.\n", (unsigned long long)*ppos, bvec->bv_len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}

/*
 * This is the slow, transforming version that needs to double buffer the
 * data as it cannot do the transformations in place without having direct
 * access to the destination pages of the backing file.
 */
static int __raw_file_fmt_write_transfer(struct xloop_device *xlo,
		struct request *rq, loff_t pos)
{
struct bio_vec bvec, b;
	struct req_iterator iter;
	struct page *page;
	int ret = 0;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		ret = __raw_file_fmt_do_transfer(xlo, WRITE, page, 0, bvec.bv_page,
			bvec.bv_offset, bvec.bv_len, pos >> 9);
		if (unlikely(ret))
			break;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;
		ret = __raw_file_fmt_write_bvec(xlo->xlo_backing_file, &b, &pos);
		if (ret < 0)
			break;
	}

	__free_page(page);
	return ret;
}

static int raw_file_fmt_write(struct xloop_file_fmt *xlo_fmt,
			      struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int ret = 0;
	struct xloop_device *xlo;
	loff_t pos;

	xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	if (xlo->transfer)
		return __raw_file_fmt_write_transfer(xlo, rq, pos);

	rq_for_each_segment(bvec, rq, iter) {
		ret = __raw_file_fmt_write_bvec(xlo->xlo_backing_file, &bvec, &pos);
		if (ret < 0)
			break;
		cond_resched();
	}

	return ret;
}

static int raw_file_fmt_write_aio(struct xloop_file_fmt *xlo_fmt,
				  struct request *rq)
{
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);
	struct xloop_cmd *cmd = blk_mq_rq_to_pdu(rq);
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);

	return __raw_file_fmt_rw_aio(xlo, cmd, pos, WRITE);
}

static int __raw_file_fmt_fallocate(struct xloop_device *xlo,
			struct request *rq, loff_t pos, int mode)
{
	/*
	 * We use fallocate to manipulate the space mappings used by the image
	 * a.k.a. discard/zerorange. However we do not support this if
	 * encryption is enabled, because it may give an attacker useful
	 * information.
	 */
	struct file *file = xlo->xlo_backing_file;
	struct request_queue *q = xlo->xlo_queue;
	int ret;

	mode |= FALLOC_FL_KEEP_SIZE;

	if (!blk_queue_discard(q)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;
out:
	return ret;
}

static int raw_file_fmt_write_zeros(struct xloop_file_fmt *xlo_fmt,
				struct request *rq)
{
	loff_t pos = __raw_file_fmt_rq_get_pos(xlo_fmt, rq);
	struct xloop_device *xlo = xloop_file_fmt_get_xlo(xlo_fmt);

	/*
	 * If the caller doesn't want deallocation, call zeroout to
	 * write zeroes the range. Otherwise, punch them out.
	 */
	return __raw_file_fmt_fallocate(xlo, rq, pos,
			(rq->cmd_flags & REQ_NOUNMAP) ?
			 FALLOC_FL_ZERO_RANGE :
			 FALLOC_FL_PUNCH_HOLE);
}

static int raw_file_fmt_discard(struct xloop_file_fmt *xlo_fmt,
				struct request *rq)
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

static loff_t raw_file_fmt_sector_size(struct xloop_file_fmt *xlo_fmt,
				struct file *file, loff_t offset, loff_t sizelimit)
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
	.init = NULL,
	.exit = NULL,
	.read = raw_file_fmt_read,
	.write = raw_file_fmt_write,
	.read_aio = raw_file_fmt_read_aio,
	.write_aio = raw_file_fmt_write_aio,
	.write_zeros = raw_file_fmt_write_zeros,
	.discard = raw_file_fmt_discard,
	.flush = raw_file_fmt_flush,
	.sector_size = raw_file_fmt_sector_size,
};

static struct xloop_file_fmt_driver raw_file_fmt_driver = {
	.name = "RAW",
	.file_fmt_type = XLO_FILE_FMT_RAW,
	.ops = &raw_file_fmt_ops,
	.owner = THIS_MODULE,
};

static int __init xloop_file_fmt_raw_init(void)
{
	printk(KERN_INFO "xloop_file_fmt_raw: init xloop device RAW file format "
		"driver");
	return xloop_file_fmt_register_driver(&raw_file_fmt_driver);
}

static void __exit xloop_file_fmt_raw_exit(void)
{
	printk(KERN_INFO "xloop_file_fmt_raw: exit xloop device RAW file format "
		"driver");
	xloop_file_fmt_unregister_driver(&raw_file_fmt_driver);
}

module_init(xloop_file_fmt_raw_init);
module_exit(xloop_file_fmt_raw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_DESCRIPTION("xloop device RAW file format driver");
MODULE_SOFTDEP("pre: xloop");
