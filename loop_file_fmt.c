/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt.c
 *
 * File format subsystem for the xloop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "loop_file_fmt.h"

/* storage for all registered file format drivers */
static struct xloop_file_fmt_driver *xloop_file_fmt_drivers[MAX_XLO_FILE_FMT] = {
	NULL
};

int xloop_file_fmt_register_driver(struct xloop_file_fmt_driver *drv)
{
	int ret = 0;

	if (drv == NULL)
		return -EFAULT;

	if (drv->file_fmt_type > MAX_XLO_FILE_FMT)
		return -EINVAL;

	if (xloop_file_fmt_drivers[drv->file_fmt_type] == NULL) {
		xloop_file_fmt_drivers[drv->file_fmt_type] = drv;
		printk(KERN_INFO "xloop_file_fmt: successfully registered file "
			"format driver %s", drv->name);
	} else {
		printk(KERN_WARNING "xloop_file_fmt: driver for file format "
			"already registered");
		ret = -EBUSY;
	}

	return ret;
}
EXPORT_SYMBOL(xloop_file_fmt_register_driver);

void xloop_file_fmt_unregister_driver(struct xloop_file_fmt_driver *drv)
{
	if (drv == NULL)
		return;

	if (drv->file_fmt_type > MAX_XLO_FILE_FMT)
		return;

	xloop_file_fmt_drivers[drv->file_fmt_type] = NULL;
	printk(KERN_INFO "xloop_file_fmt: successfully unregistered file "
		"format driver %s", drv->name);
}
EXPORT_SYMBOL(xloop_file_fmt_unregister_driver);

struct xloop_file_fmt *xloop_file_fmt_alloc(void)
{
	return kzalloc(sizeof(struct xloop_file_fmt), GFP_KERNEL);
}

void xloop_file_fmt_free(struct xloop_file_fmt *xlo_fmt)
{
	kfree(xlo_fmt);
}

int xloop_file_fmt_set_xlo(struct xloop_file_fmt *xlo_fmt, struct xloop_device *xlo)
{
	if (xlo_fmt == NULL)
		return -EINVAL;

	xlo_fmt->xlo = xlo;

	return 0;
}
EXPORT_SYMBOL(xloop_file_fmt_set_xlo);

struct xloop_device *xloop_file_fmt_get_xlo(struct xloop_file_fmt *xlo_fmt)
{
	return xlo_fmt->xlo;
}
EXPORT_SYMBOL(xloop_file_fmt_get_xlo);

int xloop_file_fmt_init(struct xloop_file_fmt *xlo_fmt,
		       u32 file_fmt_type)
{
	struct xloop_file_fmt_ops *ops;
	struct module *drv;
	int ret = 0;

	if (file_fmt_type > MAX_XLO_FILE_FMT)
		return -EINVAL;

	xlo_fmt->file_fmt_type = file_fmt_type;

	if (xlo_fmt->file_fmt_state != file_fmt_uninitialized) {
		printk(KERN_WARNING "xloop_file_fmt: file format is "
			"initialized already");
		return -EINVAL;
	}

	/* check if new file format driver is registered */
	if (xloop_file_fmt_drivers[xlo_fmt->file_fmt_type] == NULL) {
		printk(KERN_ERR "xloop_file_fmt: file format driver is not "
			"available");
		return -ENODEV;
	}

	printk(KERN_INFO "xloop_file_fmt: use file format driver %s",
		xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->name);

	drv = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->owner;
	if (!try_module_get(drv)) {
		printk(KERN_ERR "xloop_file_fmt: file format driver %s can not "
			"be accessed",
			xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->name);
		return -ENODEV;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->init)) {
		ret = ops->init(xlo_fmt);
		if (ret < 0)
			goto free_drv;
	}

	/* after increasing the refcount of file format driver module and
	 * the successful initialization, the file format is initialized */
	xlo_fmt->file_fmt_state = file_fmt_initialized;

	return ret;

free_drv:
	module_put(drv);
	xlo_fmt->file_fmt_state = file_fmt_uninitialized;
	return ret;
}

void xloop_file_fmt_exit(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_ops *ops;
	struct module *drv;

	if (xlo_fmt->file_fmt_state != file_fmt_initialized) {
		printk(KERN_WARNING "xloop_file_fmt: file format is "
			"uninitialized already");
		return;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->exit))
		ops->exit(xlo_fmt);

	drv = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->owner;
	module_put(drv);

	/* after decreasing the refcount of file format driver module,
	 * the file format is uninitialized */
	xlo_fmt->file_fmt_state = file_fmt_uninitialized;
}

int xloop_file_fmt_read(struct xloop_file_fmt *xlo_fmt,
		       struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
			"not initialized, can not read");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->read))
		return ops->read(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_read_aio(struct xloop_file_fmt *xlo_fmt,
			   struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not read aio");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->read_aio))
		return ops->read_aio(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_write(struct xloop_file_fmt *xlo_fmt,
			struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not write");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->write))
		return ops->write(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_write_aio(struct xloop_file_fmt *xlo_fmt,
			    struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not write aio");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->write_aio))
		return ops->write_aio(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_write_zeros(struct xloop_file_fmt *xlo_fmt,
			  struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not write zeros");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->write_zeros))
		return ops->write_zeros(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_discard(struct xloop_file_fmt *xlo_fmt,
			  struct request *rq)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not discard");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->discard))
		return ops->discard(xlo_fmt, rq);
	else
		return -EIO;
}

int xloop_file_fmt_flush(struct xloop_file_fmt *xlo_fmt)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not flush");
		return -EINVAL;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->flush))
		return ops->flush(xlo_fmt);

	return 0;
}

loff_t xloop_file_fmt_sector_size(struct xloop_file_fmt *xlo_fmt,
			struct file *file, loff_t offset, loff_t sizelimit)
{
	struct xloop_file_fmt_ops *ops;

	if (unlikely(xlo_fmt->file_fmt_state != file_fmt_initialized)) {
		printk(KERN_ERR "xloop_file_fmt: file format is "
				"not initialized, can not read sector size");
		return 0;
	}

	ops = xloop_file_fmt_drivers[xlo_fmt->file_fmt_type]->ops;
	if (likely(ops->sector_size))
		return ops->sector_size(xlo_fmt, file, offset, sizelimit);
	else
		return 0;
}

int xloop_file_fmt_change(struct xloop_file_fmt *xlo_fmt,
			 u32 file_fmt_type_new)
{
	if (file_fmt_type_new > MAX_XLO_FILE_FMT)
		return -EINVAL;

	/* Unload the old file format driver if the file format is
	 * initialized */
	if (xlo_fmt->file_fmt_state == file_fmt_initialized)
		xloop_file_fmt_exit(xlo_fmt);

	/* Load the new file format driver because the file format is
	 * uninitialized now */
	return xloop_file_fmt_init(xlo_fmt, file_fmt_type_new);
}

ssize_t xloop_file_fmt_print_type(u32 file_fmt_type, char *file_fmt_name)
{
	ssize_t len = 0;

	switch (file_fmt_type) {
	case XLO_FILE_FMT_RAW:
		len = sprintf(file_fmt_name, "%s", "RAW");
		break;
	case XLO_FILE_FMT_QCOW:
		len = sprintf(file_fmt_name, "%s", "QCOW");
		break;
	case XLO_FILE_FMT_VDI:
		len = sprintf(file_fmt_name, "%s", "VDI");
		break;
	case XLO_FILE_FMT_VMDK:
		len = sprintf(file_fmt_name, "%s", "VMDK");
		break;
	default:
		len = sprintf(file_fmt_name, "%s", "ERROR: Unsupported xloop "
			"file format!");
		break;
	}

	return len;
}
EXPORT_SYMBOL(xloop_file_fmt_print_type);
