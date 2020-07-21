/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt_raw.c
 *
 * RAW file format driver for the loop device module.
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

#include "loop_file_fmt.h"

static inline loff_t __raw_file_fmt_rq_get_pos(struct loop_file_fmt *lo_fmt,
					       struct request *rq)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	return ((loff_t) blk_rq_pos(rq) << 9) + lo->lo_offset;
}

/* transfer function for DEPRECATED cryptoloop support */
static inline int __raw_file_fmt_do_transfer(struct loop_file_fmt *lo_fmt,
					     int cmd,
					     struct page *rpage,
					     unsigned roffs,
					     struct page *lpage,
					     unsigned loffs,
					     int size,
					     sector_t rblock)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	int ret;

	ret = lo->transfer(lo, cmd, rpage, roffs, lpage, loffs, size, rblock);
	if (likely(!ret))
		return 0;

	printk_ratelimited(KERN_ERR
		"loop: Transfer error at byte offset %llu, length %i.\n",
		(unsigned long long)rblock << 9, size);
	return ret;
}

static int raw_file_fmt_read_transfer(struct loop_file_fmt *lo_fmt,
				      struct request *rq)
{
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct iov_iter i;
	struct page *page;
	struct loop_device *lo;
	ssize_t len;
	int ret = 0;
	loff_t pos;

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	lo = loop_file_fmt_get_lo(lo_fmt);
	pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		loff_t offset = pos;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;

		iov_iter_bvec(&i, READ, &b, 1, b.bv_len);
		len = vfs_iter_read(lo->lo_backing_file, &i, &pos, 0);
		if (len < 0) {
			ret = len;
			goto out_free_page;
		}

		ret = __raw_file_fmt_do_transfer(lo_fmt, READ, page, 0,
			bvec.bv_page, bvec.bv_offset, len, offset >> 9);
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

static int raw_file_fmt_read(struct loop_file_fmt *lo_fmt,
			     struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct iov_iter i;
	struct loop_device *lo;
	ssize_t len;
	loff_t pos;

	lo = loop_file_fmt_get_lo(lo_fmt);

	if (lo->transfer)
		return raw_file_fmt_read_transfer(lo_fmt, rq);

	pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		iov_iter_bvec(&i, READ, &bvec, 1, bvec.bv_len);
		len = vfs_iter_read(lo->lo_backing_file, &i, &pos, 0);
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

static void __raw_file_fmt_rw_aio_do_completion(struct loop_cmd *cmd)
{
	struct request *rq = blk_mq_rq_from_pdu(cmd);

	if (!atomic_dec_and_test(&cmd->ref))
		return;
	kfree(cmd->bvec);
	cmd->bvec = NULL;
	blk_mq_complete_request(rq);
}

static void __raw_file_fmt_rw_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct loop_cmd *cmd = container_of(iocb, struct loop_cmd, iocb);

	if (cmd->css)
		css_put(cmd->css);
	cmd->ret = ret;
	__raw_file_fmt_rw_aio_do_completion(cmd);
}

static int __raw_file_fmt_rw_aio(struct loop_file_fmt *lo_fmt,
				 struct request *rq,
				 bool rw)
{
	struct iov_iter iter;
	struct req_iterator rq_iter;
	struct bio_vec *bvec;
	struct bio *bio = rq->bio;
	struct file *file;
	struct bio_vec tmp;
	struct loop_device *lo;
	struct loop_cmd *cmd;
	unsigned int offset;
	int nr_bvec = 0;
	int ret;
	loff_t pos;

	lo = loop_file_fmt_get_lo(lo_fmt);
	file = lo->lo_backing_file;
	cmd = blk_mq_rq_to_pdu(rq);
	pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);

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

static int raw_file_fmt_read_aio(struct loop_file_fmt *lo_fmt,
				 struct request *rq)
{
	return __raw_file_fmt_rw_aio(lo_fmt, rq, READ);
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
		"loop_file_fmt_raw: Write error at byte offset %llu, length "
		"%i.\n", (unsigned long long)*ppos, bvec->bv_len);
	if (bw >= 0)
		bw = -EIO;
	return bw;
}

static int raw_file_fmt_write_transfer(struct loop_file_fmt *lo_fmt,
				       struct request *rq)
{
	struct bio_vec bvec, b;
	struct req_iterator iter;
	struct page *page;
	struct loop_device *lo;
	int ret = 0;
	loff_t pos;

	lo = loop_file_fmt_get_lo(lo_fmt);
	pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);

	page = alloc_page(GFP_NOIO);
	if (unlikely(!page))
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		ret = __raw_file_fmt_do_transfer(lo_fmt, WRITE, page, 0,
			bvec.bv_page, bvec.bv_offset, bvec.bv_len, pos >> 9);
		if (unlikely(ret))
			break;

		b.bv_page = page;
		b.bv_offset = 0;
		b.bv_len = bvec.bv_len;
		ret = __raw_file_fmt_write_bvec(lo->lo_backing_file, &b,
			&pos);
		if (ret < 0)
			break;
	}

	__free_page(page);
	return ret;
}

static int raw_file_fmt_write(struct loop_file_fmt *lo_fmt,
			      struct request *rq)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	struct loop_device *lo;
	int ret = 0;
	loff_t pos;

	lo = loop_file_fmt_get_lo(lo_fmt);

	if (lo->transfer)
		return raw_file_fmt_write_transfer(lo_fmt, rq);

	pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);

	rq_for_each_segment(bvec, rq, iter) {
		ret = __raw_file_fmt_write_bvec(lo->lo_backing_file, &bvec,
			&pos);
		if (ret < 0)
			break;
		cond_resched();
	}

	return ret;
}

static int raw_file_fmt_write_aio(struct loop_file_fmt *lo_fmt,
				  struct request *rq)
{
	return __raw_file_fmt_rw_aio(lo_fmt, rq, WRITE);
}

static int raw_file_fmt_discard(struct loop_file_fmt *lo_fmt,
				struct request *rq)
{
	loff_t pos = __raw_file_fmt_rq_get_pos(lo_fmt, rq);
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);

	/*
	 * We use punch hole to reclaim the free space used by the
	 * image a.k.a. discard. However we do not support discard if
	 * encryption is enabled, because it may give an attacker
	 * useful information.
	 */
	struct file *file = lo->lo_backing_file;
	int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	int ret;

	if ((!file->f_op->fallocate) || lo->lo_encrypt_key_size) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = file->f_op->fallocate(file, mode, pos, blk_rq_bytes(rq));
	if (unlikely(ret && ret != -EINVAL && ret != -EOPNOTSUPP))
		ret = -EIO;
 out:
	return ret;
}

static int raw_file_fmt_flush(struct loop_file_fmt *lo_fmt)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	struct file *file = lo->lo_backing_file;
	int ret = vfs_fsync(file, 0);
	if (unlikely(ret && ret != -EINVAL))
		ret = -EIO;

	return ret;
}

static loff_t raw_file_fmt_sector_size(struct loop_file_fmt *lo_fmt)
{
	struct loop_device *lo = loop_file_fmt_get_lo(lo_fmt);
	loff_t loopsize;

	/* Compute loopsize in bytes */
	loopsize = i_size_read(lo->lo_backing_file->f_mapping->host);
	if (lo->lo_offset > 0)
		loopsize -= lo->lo_offset;
	/* offset is beyond i_size, weird but possible */
	if (loopsize < 0)
		return 0;

	if (lo->lo_sizelimit > 0 && lo->lo_sizelimit < loopsize)
		loopsize = lo->lo_sizelimit;

	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	return loopsize >> 9;
}

static struct loop_file_fmt_ops raw_file_fmt_ops = {
	.init = NULL,
	.exit = NULL,
	.read = raw_file_fmt_read,
	.write = raw_file_fmt_write,
	.read_aio = raw_file_fmt_read_aio,
	.write_aio = raw_file_fmt_write_aio,
	.discard = raw_file_fmt_discard,
	.flush = raw_file_fmt_flush,
	.sector_size = raw_file_fmt_sector_size
};

static struct loop_file_fmt_driver raw_file_fmt_driver = {
	.name = "RAW",
	.file_fmt_type = LO_FILE_FMT_RAW,
	.ops = &raw_file_fmt_ops,
	.owner = THIS_MODULE
};

static int __init loop_file_fmt_raw_init(void)
{
	printk(KERN_INFO "loop_file_fmt_raw: init loop device RAW file format "
		"driver");
	return loop_file_fmt_register_driver(&raw_file_fmt_driver);
}

static void __exit loop_file_fmt_raw_exit(void)
{
	printk(KERN_INFO "loop_file_fmt_raw: exit loop device RAW file format "
		"driver");
	loop_file_fmt_unregister_driver(&raw_file_fmt_driver);
}

module_init(loop_file_fmt_raw_init);
module_exit(loop_file_fmt_raw_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manuel Bentele <development@manuel-bentele.de>");
MODULE_DESCRIPTION("Loop device RAW file format driver");
MODULE_SOFTDEP("pre: loop");
