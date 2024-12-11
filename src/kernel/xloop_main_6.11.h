/* SPDX-License-Identifier: GPL-2.0 */
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
#include "uapi_xloop.h"
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include "xloop_file_fmt.h"

/* Possible states of device */
enum {
	Xlo_unbound,
	Xlo_bound,
	Xlo_rundown,
	Xlo_deleting,
};

struct xloop_func_table;

struct xloop_device {
	int                     xlo_number;
	loff_t                  xlo_offset;
	loff_t                  xlo_sizelimit;
	int                     xlo_flags;
	char                    xlo_file_name[XLO_NAME_SIZE];

	struct xloop_file_fmt   *xlo_fmt;

	struct file             *xlo_backing_file;
	struct block_device     *xlo_device;

	gfp_t                   old_gfp_mask;

	spinlock_t              xlo_lock;
	int                     xlo_state;
	spinlock_t              xlo_work_lock;
	struct workqueue_struct *workqueue;
	struct work_struct      rootcg_work;
	struct list_head        rootcg_cmd_list;
	struct list_head        idle_worker_list;
	struct rb_root          worker_tree;
	struct timer_list       timer;
	bool                    use_dio;
	bool                    sysfs_inited;

	struct request_queue    *xlo_queue;
	struct blk_mq_tag_set   tag_set;
	struct gendisk          *xlo_disk;
	struct mutex            xlo_mutex;
	bool                    idr_visible;

#ifdef CONFIG_DEBUG_FS
	struct dentry           *xlo_dbgfs_dir;
#endif
};

struct xloop_cmd {
	struct list_head           list_entry;
	bool                       use_aio;  /* use AIO interface to handle I/O */
	atomic_t                   ref;  /* only for aio */
	long                       ret;
	struct kiocb               iocb;
	struct bio_vec             *bvec;
	struct cgroup_subsys_state *blkcg_css;
	struct cgroup_subsys_state *memcg_css;
};

/* Support for loadable transfer modules */
struct xloop_func_table {
	int           number;  /* filter type */
	int           (*transfer)(struct xloop_device *xlo, int cmd, struct page *raw_page, unsigned raw_off, struct page *xloop_page, unsigned xloop_off, int size, sector_t real_block);
	int           (*init)(struct xloop_device *xlo, const struct xloop_info64 *info);
	/* release is called from xloop_unregister_transfer or clr_fd */
	int           (*release)(struct xloop_device *xlo);
	struct module *owner;
};

extern inline struct device *xloop_device_to_dev(struct xloop_device *xlo);

int xloop_register_transfer(struct xloop_func_table *funcs);
int xloop_unregister_transfer(int number);

#endif
