/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt.c
 *
 * File format subsystem for the loop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "loop_file_fmt.h"

/* storage for all registered file format drivers */
static struct loop_file_fmt_driver *loop_file_fmt_drivers[MAX_LO_FILE_FMT] = {
	NULL
};

int loop_file_fmt_register_driver(struct loop_file_fmt_driver *drv)
{
	int ret = 0;

	if (drv == NULL)
		return -EFAULT;

	if (drv->file_fmt_type > MAX_LO_FILE_FMT)
		return -EINVAL;

	if (loop_file_fmt_drivers[drv->file_fmt_type] == NULL) {
		loop_file_fmt_drivers[drv->file_fmt_type] = drv;
		printk(KERN_INFO "loop_file_fmt: successfully registered file "
			"format driver %s", drv->name);
	} else {
		printk(KERN_WARNING "loop_file_fmt: driver for file format "
			"already registered");
		ret = -EBUSY;
	}

	return ret;
}
EXPORT_SYMBOL(loop_file_fmt_register_driver);

void loop_file_fmt_unregister_driver(struct loop_file_fmt_driver *drv)
{
	if (drv == NULL)
		return;

	if (drv->file_fmt_type > MAX_LO_FILE_FMT)
		return;

	loop_file_fmt_drivers[drv->file_fmt_type] = NULL;
	printk(KERN_INFO "loop_file_fmt: successfully unregistered file "
		"format driver %s", drv->name);
}
EXPORT_SYMBOL(loop_file_fmt_unregister_driver);

struct loop_file_fmt *loop_file_fmt_alloc(void)
{
	return kzalloc(sizeof(struct loop_file_fmt), GFP_KERNEL);
}

void loop_file_fmt_free(struct loop_file_fmt *lo_fmt)
{
	kfree(lo_fmt);
}

int loop_file_fmt_set_lo(struct loop_file_fmt *lo_fmt, struct loop_device *lo)
{
	if (lo_fmt == NULL)
		return -EINVAL;

	lo_fmt->lo = lo;

	return 0;
}
EXPORT_SYMBOL(loop_file_fmt_set_lo);

struct loop_device *loop_file_fmt_get_lo(struct loop_file_fmt *lo_fmt)
{
	return lo_fmt->lo;
}
EXPORT_SYMBOL(loop_file_fmt_get_lo);

int loop_file_fmt_init(struct loop_file_fmt *lo_fmt,
		       u32 file_fmt_type)
{
	struct loop_file_fmt_ops *ops;
	struct module *drv;
	int ret = 0;

	if (file_fmt_type > MAX_LO_FILE_FMT)
		return -EINVAL;

	lo_fmt->file_fmt_type = file_fmt_type;

	if (lo_fmt->file_fmt_state != file_fmt_uninitialized) {
		printk(KERN_WARNING "loop_file_fmt: file format is "
			"initialized already");
		return -EINVAL;
	}

	/* check if new file format driver is registered */
	if (loop_file_fmt_drivers[lo_fmt->file_fmt_type] == NULL) {
		printk(KERN_ERR "loop_file_fmt: file format driver is not "
			"available");
		return -ENODEV;
	}

	printk(KERN_INFO "loop_file_fmt: use file format driver %s",
		loop_file_fmt_drivers[lo_fmt->file_fmt_type]->name);

	drv = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->owner;
	if (!try_module_get(drv)) {
		printk(KERN_ERR "loop_file_fmt: file format driver %s can not "
			"be accessed",
			loop_file_fmt_drivers[lo_fmt->file_fmt_type]->name);
		return -ENODEV;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->init)) {
		ret = ops->init(lo_fmt);
		if (ret < 0)
			goto free_drv;
	}

	/* after increasing the refcount of file format driver module and
	 * the successful initialization, the file format is initialized */
	lo_fmt->file_fmt_state = file_fmt_initialized;

	return ret;

free_drv:
	module_put(drv);
	lo_fmt->file_fmt_state = file_fmt_uninitialized;
	return ret;
}

void loop_file_fmt_exit(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_ops *ops;
	struct module *drv;

	if (lo_fmt->file_fmt_state != file_fmt_initialized) {
		printk(KERN_WARNING "loop_file_fmt: file format is "
			"uninitialized already");
		return;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->exit))
		ops->exit(lo_fmt);

	drv = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->owner;
	module_put(drv);

	/* after decreasing the refcount of file format driver module,
	 * the file format is uninitialized */
	lo_fmt->file_fmt_state = file_fmt_uninitialized;
}

int loop_file_fmt_read(struct loop_file_fmt *lo_fmt,
		       struct request *rq)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
			"not initialized, can not read");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->read))
		return ops->read(lo_fmt, rq);
	else
		return -EIO;
}

int loop_file_fmt_read_aio(struct loop_file_fmt *lo_fmt,
			   struct request *rq)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not read aio");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->read_aio))
		return ops->read_aio(lo_fmt, rq);
	else
		return -EIO;
}

int loop_file_fmt_write(struct loop_file_fmt *lo_fmt,
			struct request *rq)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not write");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->write))
		return ops->write(lo_fmt, rq);
	else
		return -EIO;
}

int loop_file_fmt_write_aio(struct loop_file_fmt *lo_fmt,
			    struct request *rq)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not write aio");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->write_aio))
		return ops->write_aio(lo_fmt, rq);
	else
		return -EIO;
}

int loop_file_fmt_discard(struct loop_file_fmt *lo_fmt,
			  struct request *rq)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not discard");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->discard))
		return ops->discard(lo_fmt, rq);
	else
		return -EIO;
}

int loop_file_fmt_flush(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not flush");
		return -EINVAL;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->flush))
		return ops->flush(lo_fmt);

	return 0;
}

loff_t loop_file_fmt_sector_size(struct loop_file_fmt *lo_fmt)
{
	struct loop_file_fmt_ops *ops;

	if (unlikely(lo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "loop_file_fmt: file format is "
				"not initialized, can not read sector size");
		return 0;
	}

	ops = loop_file_fmt_drivers[lo_fmt->file_fmt_type]->ops;
	if (likely(ops->sector_size))
		return ops->sector_size(lo_fmt);
	else
		return 0;
}

int loop_file_fmt_change(struct loop_file_fmt *lo_fmt,
			 u32 file_fmt_type_new)
{
	if (file_fmt_type_new > MAX_LO_FILE_FMT)
		return -EINVAL;

	/* Unload the old file format driver if the file format is
	 * initialized */
	if (lo_fmt->file_fmt_state == file_fmt_initialized)
		loop_file_fmt_exit(lo_fmt);

	/* Load the new file format driver because the file format is
	 * uninitialized now */
	return loop_file_fmt_init(lo_fmt, file_fmt_type_new);
}

ssize_t loop_file_fmt_print_type(u32 file_fmt_type, char *file_fmt_name)
{
	ssize_t len = 0;

	switch (file_fmt_type) {
	case LO_FILE_FMT_RAW:
		len = sprintf(file_fmt_name, "%s", "RAW");
		break;
	case LO_FILE_FMT_QCOW:
		len = sprintf(file_fmt_name, "%s", "QCOW");
		break;
	case LO_FILE_FMT_VDI:
		len = sprintf(file_fmt_name, "%s", "VDI");
		break;
	case LO_FILE_FMT_VMDK:
		len = sprintf(file_fmt_name, "%s", "VMDK");
		break;
	default:
		len = sprintf(file_fmt_name, "%s", "ERROR: Unsupported loop "
			"file format!");
		break;
	}

	return len;
}
EXPORT_SYMBOL(loop_file_fmt_print_type);
