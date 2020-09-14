/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xloop_file_fmt.h
 *
 * File format subsystem for the xloop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#ifndef _LINUX_XLOOP_FILE_FMT_H
#define _LINUX_XLOOP_FILE_FMT_H

#include "xloop_main.h"

struct xloop_file_fmt;

#define XLO_FILE_FMT_RAW         0
#define XLO_FILE_FMT_QCOW        1
#define XLO_FILE_FMT_VDI         2
#define XLO_FILE_FMT_VMDK        3
#define MAX_XLO_FILE_FMT         (XLO_FILE_FMT_VMDK + 1)

/**
 * struct xloop_file_fmt_ops - File format subsystem operations
 *
 * Data structure representing the file format subsystem interface.
 */
struct xloop_file_fmt_ops {
	/**
	 * @init: Initialization callback function
	 */
	int (*init) (struct xloop_file_fmt *xlo_fmt);

	/**
	 * @exit: Release callback function
	 */
	void (*exit) (struct xloop_file_fmt *xlo_fmt);

	/**
	 * @read: Read IO callback function
	 */
	int (*read) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @write: Write IO callback function
	 */
	int (*write) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @read_aio: Asynchronous read IO callback function
	 */
	int (*read_aio) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @write_aio: Asynchronous write IO callback function
	 */
	int (*write_aio) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @zero: Zero (discard) IO callback function
	 */
	int (*write_zeros) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @discard: Discard IO callback function
	 */
	int (*discard) (struct xloop_file_fmt *xlo_fmt,
			struct request *rq);

	/**
	 * @flush: Flush callback function
	 */
	int (*flush) (struct xloop_file_fmt *xlo_fmt);

	/**
	 * @sector_size: Get sector size callback function
	 */
	loff_t (*sector_size) (struct xloop_file_fmt *xlo_fmt,
				struct file *file, loff_t offset, loff_t sizelimit);
};

/**
 * struct xloop_file_fmt_driver - File format subsystem driver
 *
 * Data structure to implement file format drivers for the file format
 * subsystem.
 */
struct xloop_file_fmt_driver {
	/**
	 * @name: Name of the file format driver
	 */
	const char *name;

	/**
	 * @file_fmt_type: xloop file format type of the file format driver
	 */
	const u32 file_fmt_type;

	/**
	 * @ops: Driver's implemented file format operations
	 */
	struct xloop_file_fmt_ops *ops;

	/**
	 * @ops: Owner of the file format driver
	 */
	struct module *owner;
};

/*
 * states of the file format
 *
 * transitions:
 *                    xloop_file_fmt_init(...)
 * ---> uninitialized ------------------------------> initialized
 *                    xloop_file_fmt_exit(...)
 *      initialized   ------------------------------> uninitialized
 *                    xloop_file_fmt_read(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_read_aio(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_write(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_write_aio(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_discard(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_flush(...)
 *      initialized   ------------------------------> initialized
 *                    xloop_file_fmt_sector_size(...)
 *      initialized   ------------------------------> initialized
 *
 *                    xloop_file_fmt_change(...)
 *    +-----------------------------------------------------------+
 *    |               exit(...)              init(...)            |
 *    | initialized   -------> uninitialized -------> initialized |
 *    +-----------------------------------------------------------+
 */
enum {
	file_fmt_uninitialized = 0,
	file_fmt_initialized
};

/**
 * struct xloop_file_fmt - xloop file format
 *
 * Data structure to use with the file format the xloop file format subsystem.
 */
struct xloop_file_fmt {
	/**
	 * @file_fmt_type: Current type of the xloop file format
	 */
	u32 file_fmt_type;

	/**
	 * @file_fmt_state: Current state of the xloop file format
	 */
	int file_fmt_state;

	/**
	 * @xlo: Link to a file format's xloop device
	 */
	struct xloop_device *xlo;

	/**
	 * @private_data: Optional link to a file format's driver specific data
	 */
	void *private_data;
};


/* subsystem functions for the driver implementation */

/**
 * xloop_file_fmt_register_driver - Register a xloop file format driver
 * @drv: File format driver
 *
 * Registers the specified xloop file format driver @drv by the xloop file format
 * subsystem.
 */
extern int xloop_file_fmt_register_driver(struct xloop_file_fmt_driver *drv);

/**
 * xloop_file_fmt_unregister_driver - Unregister a xloop file format driver
 * @drv: File format driver
 *
 * Unregisters the specified xloop file format driver @drv from the xloop file
 * format subsystem.
 */
extern void xloop_file_fmt_unregister_driver(struct xloop_file_fmt_driver *drv);


/* subsystem functions for subsystem usage */

/**
 * xloop_file_fmt_alloc - Allocate a xloop file format
 *
 * Dynamically allocates a xloop file format and returns a pointer to the
 * created xloop file format.
 */
extern struct xloop_file_fmt *xloop_file_fmt_alloc(void);

/**
 * xloop_file_fmt_free - Free an allocated xloop file format
 * @xlo_fmt: xloop file format
 *
 * Frees the already allocated xloop file format @xlo_fmt.
 */
extern void xloop_file_fmt_free(struct xloop_file_fmt *xlo_fmt);

/**
 * xloop_file_fmt_set_xlo - Set the xloop file format's xloop device
 * @xlo_fmt: xloop file format
 * @xlo: xloop device
 *
 * The link to the xloop device @xlo is set in the xloop file format @xlo_fmt.
 */
extern int xloop_file_fmt_set_xlo(struct xloop_file_fmt *xlo_fmt,
				struct xloop_device *xlo);

/**
 * xloop_file_fmt_get_xlo - Get the xloop file format's xloop device
 * @xlo_fmt: xloop file format
 *
 * Returns a pointer to the xloop device of the xloop file format @xlo_fmt.
 */
extern struct xloop_device *xloop_file_fmt_get_xlo(struct xloop_file_fmt *xlo_fmt);

/**
 * xloop_file_fmt_to_dev - Get the xloop file format's disk device
 * @xlo_fmt: xloop file format
 *
 * Returns a pointer to the disk device of the xloop file format's xloop device.
 */
extern inline struct device *xloop_file_fmt_to_dev(struct xloop_file_fmt *xlo_fmt);

/**
 * xloop_file_fmt_init - Initialize a xloop file format
 * @xlo_fmt: xloop file format
 * @file_fmt_type: Type of the file format
 *
 * Initializes the specified xloop file format @xlo_fmt and sets up the correct
 * file format type @file_fmt_type. Depending on @file_fmt_type, the correct
 * xloop file format driver is loaded in the subsystems backend. If no xloop file
 * format driver for the specified file format is available an error is
 * returned.
 */
extern int xloop_file_fmt_init(struct xloop_file_fmt *xlo_fmt,
			      u32 file_fmt_type);

/**
 * xloop_file_fmt_exit - Release a xloop file format
 * @xlo_fmt: xloop file format
 *
 * Releases the specified xloop file format @xlo_fmt and all its resources.
 */
extern void xloop_file_fmt_exit(struct xloop_file_fmt *xlo_fmt);

/**
 * xloop_file_fmt_read - Read IO from a xloop file format
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Reads IO from the file format's xloop device by sending the IO read request
 * @rq to the xloop file format subsystem. The subsystem calls the registered
 * callback function of the suitable xloop file format driver.
 */
extern int xloop_file_fmt_read(struct xloop_file_fmt *xlo_fmt,
			      struct request *rq);

/**
 * xloop_file_fmt_read_aio - Read IO from a xloop file format asynchronously
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Reads IO from the file format's xloop device asynchronously by sending the
 * IO read aio request @rq to the xloop file format subsystem. The subsystem
 * calls the registered callback function of the suitable xloop file format
 * driver.
 */
extern int xloop_file_fmt_read_aio(struct xloop_file_fmt *xlo_fmt,
				  struct request *rq);

/**
 * xloop_file_fmt_write - Write IO to a xloop file format
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Write IO to the file format's xloop device by sending the IO write request
 * @rq to the xloop file format subsystem. The subsystem calls the registered
 * callback function of the suitable xloop file format driver.
 */
extern int xloop_file_fmt_write(struct xloop_file_fmt *xlo_fmt,
			       struct request *rq);

/**
 * xloop_file_fmt_write_aio - Write IO to a xloop file format asynchronously
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Write IO to the file format's xloop device asynchronously by sending the
 * IO write aio request @rq to the xloop file format subsystem. The subsystem
 * calls the registered callback function of the suitable xloop file format
 * driver.
 */
extern int xloop_file_fmt_write_aio(struct xloop_file_fmt *xlo_fmt,
				   struct request *rq);

/**
 * xloop_file_fmt_write_zeros - Zero (discard) IO on a xloop file format
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Zero (discard) IO on the file format's xloop device by sending the IO write
 * zeros request @rq to the xloop file format subsystem. The subsystem calls the
 * registered callback function of the suitable xloop file format driver.
 */
extern int xloop_file_fmt_write_zeros(struct xloop_file_fmt *xlo_fmt,
				 struct request *rq);

/**
 * xloop_file_fmt_discard - Discard IO on a xloop file format
 * @xlo_fmt: xloop file format
 * @rq: IO Request
 *
 * Discard IO on the file format's xloop device by sending the IO discard
 * request @rq to the xloop file format subsystem. The subsystem calls the
 * registered callback function of the suitable xloop file format driver.
 */
extern int xloop_file_fmt_discard(struct xloop_file_fmt *xlo_fmt,
				 struct request *rq);

/**
 * xloop_file_fmt_flush - Flush a xloop file format
 * @xlo_fmt: xloop file format
 *
 * Flush the file format's xloop device by calling the registered callback
 * function of the suitable xloop file format driver.
 */
extern int xloop_file_fmt_flush(struct xloop_file_fmt *xlo_fmt);

/**
 * xloop_file_fmt_sector_size - Get sector size of a xloop file format
 * @xlo_fmt: xloop file format
 * @file: xloop file formats file for sector size calculation
 * @offset: Offset within the file for sector size calculation
 * @sizelimit: Sizelimit of the file for sector size calculation
 *
 * Returns the physical sector size of the given xloop file format's file.
 * If the xloop file format implements a sparse disk image format, then this
 * function returns the virtual sector size.
 */
extern loff_t xloop_file_fmt_sector_size(struct xloop_file_fmt *xlo_fmt,
				struct file *file, loff_t offset, loff_t sizelimit);

/**
 * xloop_file_fmt_change - Change the xloop file format's type
 * @xlo_fmt: xloop file format
 * @file_fmt_type_new: xloop file format type
 *
 * Changes the file format type of the already initialized xloop file format
 * @xlo_fmt. Therefore, the function releases the old file format and frees all
 * of its resources before the xloop file format @xlo_fmt is initialized and set
 * up with the new file format @file_fmt_type_new.
 */
extern int xloop_file_fmt_change(struct xloop_file_fmt *xlo_fmt,
				u32 file_fmt_type_new);


/* helper functions of the subsystem */

/**
 * xloop_file_fmt_print_type - Convert file format type to string
 * @file_fmt_type: xloop file format type
 * @file_fmt_name: xloop file format type string
 *
 * Converts the specified numeric @file_fmt_type value into a human readable
 * string stating the file format as string in @file_fmt_name.
 */
extern ssize_t xloop_file_fmt_print_type(u32 file_fmt_type,
					char *file_fmt_name);

#endif
