/*
 * loop_main.h
 *
 * Written by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 */
#ifndef _LINUX_XLOOP_H
#define _LINUX_XLOOP_H

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include "uapi/linux/xloop.h"
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include "xloop_file_fmt.h"

/* Possible states of device */
enum {
	Xlo_unbound,
	Xlo_bound,
	Xlo_rundown,
};

struct xloop_func_table;

struct xloop_device {
	int		xlo_number;
	atomic_t	xlo_refcnt;
	loff_t		xlo_offset;
	loff_t		xlo_sizelimit;
	int		xlo_flags;
	int		(*transfer)(struct xloop_device *, int cmd,
				    struct page *raw_page, unsigned raw_off,
				    struct page *xloop_page, unsigned xloop_off,
				    int size, sector_t real_block);
	char		xlo_file_name[XLO_NAME_SIZE];
	char		xlo_crypt_name[XLO_NAME_SIZE];
	char		xlo_encrypt_key[XLO_KEY_SIZE];
	int		xlo_encrypt_key_size;
	struct xloop_func_table *xlo_encryption;
	__u32           xlo_init[2];
	kuid_t		xlo_key_owner;	/* Who set the key */
	int		(*ioctl)(struct xloop_device *, int cmd, 
				 unsigned long arg); 

	struct xloop_file_fmt *xlo_fmt;

	struct file *	xlo_backing_file;
	struct block_device *xlo_device;
	void		*key_data; 

	gfp_t		old_gfp_mask;

	spinlock_t		xlo_lock;
	int			xlo_state;
	struct kthread_worker	worker;
	struct task_struct	*worker_task;
	bool			use_dio;
	bool			sysfs_inited;

	struct request_queue	*xlo_queue;
	struct blk_mq_tag_set	tag_set;
	struct gendisk		*xlo_disk;

#ifdef CONFIG_DEBUG_FS
	struct dentry *xlo_dbgfs_dir;
#endif
};

struct xloop_cmd {
	struct kthread_work work;
	bool use_aio; /* use AIO interface to handle I/O */
	atomic_t ref; /* only for aio */
	long ret;
	struct kiocb iocb;
	struct bio_vec *bvec;
	struct cgroup_subsys_state *css;
};

/* Support for loadable transfer modules */
struct xloop_func_table {
	int number;	/* filter type */ 
	int (*transfer)(struct xloop_device *xlo, int cmd,
			struct page *raw_page, unsigned raw_off,
			struct page *xloop_page, unsigned xloop_off,
			int size, sector_t real_block);
	int (*init)(struct xloop_device *, const struct xloop_info64 *); 
	/* release is called from xloop_unregister_transfer or clr_fd */
	int (*release)(struct xloop_device *); 
	int (*ioctl)(struct xloop_device *, int cmd, unsigned long arg);
	struct module *owner;
}; 

extern inline struct device *xloop_device_to_dev(struct xloop_device *xlo);

int xloop_register_transfer(struct xloop_func_table *funcs);
int xloop_unregister_transfer(int number); 

#endif
