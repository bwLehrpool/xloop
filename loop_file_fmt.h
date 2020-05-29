/* SPDX-License-Identifier: GPL-2.0 */
/*
 * loop_file_fmt.h
 *
 * File format subsystem for the loop device module.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#ifndef _LINUX_LOOP_FILE_FMT_H
#define _LINUX_LOOP_FILE_FMT_H

#include "loop_main.h"

struct loop_file_fmt;

/**
 * struct loop_file_fmt_ops - File format subsystem operations
 *
 * Data structure representing the file format subsystem interface.
 */
struct loop_file_fmt_ops {
	/**
	 * @init: Initialization callback function
	 */
	int (*init) (struct loop_file_fmt *lo_fmt);

	/**
	 * @exit: Release callback function
	 */
	void (*exit) (struct loop_file_fmt *lo_fmt);

	/**
	 * @read: Read IO callback function
	 */
	int (*read) (struct loop_file_fmt *lo_fmt,
		     struct request *rq);

	/**
	 * @write: Write IO callback function
	 */
	int (*write) (struct loop_file_fmt *lo_fmt,
		      struct request *rq);

	/**
	 * @read_aio: Asynchronous read IO callback function
	 */
	int (*read_aio) (struct loop_file_fmt *lo_fmt,
			 struct request *rq);

	/**
	 * @write_aio: Asynchronous write IO callback function
	 */
	int (*write_aio) (struct loop_file_fmt *lo_fmt,
			  struct request *rq);

	/**
	 * @discard: Discard IO callback function
	 */
	int (*discard) (struct loop_file_fmt *lo_fmt,
			struct request *rq);

	/**
	 * @flush: Flush callback function
	 */
	int (*flush) (struct loop_file_fmt *lo_fmt);

	/**
	 * @sector_size: Get sector size callback function
	 */
	loff_t (*sector_size) (struct loop_file_fmt *lo_fmt);
};

/**
 * struct loop_file_fmt_driver - File format subsystem driver
 *
 * Data structure to implement file format drivers for the file format
 * subsystem.
 */
struct loop_file_fmt_driver {
	/**
	 * @name: Name of the file format driver
	 */
	const char *name;

	/**
	 * @file_fmt_type: Loop file format type of the file format driver
	 */
	const u32 file_fmt_type;

	/**
	 * @ops: Driver's implemented file format operations
	 */
	struct loop_file_fmt_ops *ops;

	/**
	 * @ops: Owner of the file format driver
	 */
	struct module *owner;
};

/*
 * states of the file format
 *
 * transitions:
 *                    loop_file_fmt_init(...)
 * ---> uninitialized ------------------------------> initialized
 *                    loop_file_fmt_exit(...)
 *      initialized   ------------------------------> uninitialized
 *                    loop_file_fmt_read(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_read_aio(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_write(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_write_aio(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_discard(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_flush(...)
 *      initialized   ------------------------------> initialized
 *                    loop_file_fmt_sector_size(...)
 *      initialized   ------------------------------> initialized
 *
 *                    loop_file_fmt_change(...)
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
 * struct loop_file_fmt - Loop file format
 *
 * Data structure to use with the file format the loop file format subsystem.
 */
struct loop_file_fmt {
	/**
	 * @file_fmt_type: Current type of the loop file format
	 */
	u32 file_fmt_type;

	/**
	 * @file_fmt_state: Current state of the loop file format
	 */
	int file_fmt_state;

	/**
	 * @lo: Link to a file format's loop device
	 */
	struct loop_device *lo;

	/**
	 * @private_data: Optional link to a file format's driver specific data
	 */
	void *private_data;
};


/* subsystem functions for the driver implementation */

/**
 * loop_file_fmt_register_driver - Register a loop file format driver
 * @drv: File format driver
 *
 * Registers the specified loop file format driver @drv by the loop file format
 * subsystem.
 */
extern int loop_file_fmt_register_driver(struct loop_file_fmt_driver *drv);

/**
 * loop_file_fmt_unregister_driver - Unregister a loop file format driver
 * @drv: File format driver
 *
 * Unregisters the specified loop file format driver @drv from the loop file
 * format subsystem.
 */
extern void loop_file_fmt_unregister_driver(struct loop_file_fmt_driver *drv);


/* subsystem functions for subsystem usage */

/**
 * loop_file_fmt_alloc - Allocate a loop file format
 *
 * Dynamically allocates a loop file format and returns a pointer to the
 * created loop file format.
 */
extern struct loop_file_fmt *loop_file_fmt_alloc(void);

/**
 * loop_file_fmt_free - Free an allocated loop file format
 * @lo_fmt: Loop file format
 *
 * Frees the already allocated loop file format @lo_fmt.
 */
extern void loop_file_fmt_free(struct loop_file_fmt *lo_fmt);

/**
 * loop_file_fmt_set_lo - Set the loop file format's loop device
 * @lo_fmt: Loop file format
 * @lo: Loop device
 *
 * The link to the loop device @lo is set in the loop file format @lo_fmt.
 */
extern int loop_file_fmt_set_lo(struct loop_file_fmt *lo_fmt,
				struct loop_device *lo);

/**
 * loop_file_fmt_get_lo - Get the loop file format's loop device
 * @lo_fmt: Loop file format
 *
 * Returns a pointer to the loop device of the loop file format @lo_fmt.
 */
extern struct loop_device *loop_file_fmt_get_lo(struct loop_file_fmt *lo_fmt);

/**
 * loop_file_fmt_init - Initialize a loop file format
 * @lo_fmt: Loop file format
 * @file_fmt_type: Type of the file format
 *
 * Initializes the specified loop file format @lo_fmt and sets up the correct
 * file format type @file_fmt_type. Depending on @file_fmt_type, the correct
 * loop file format driver is loaded in the subsystems backend. If no loop file
 * format driver for the specified file format is available an error is
 * returned.
 */
extern int loop_file_fmt_init(struct loop_file_fmt *lo_fmt,
			      u32 file_fmt_type);

/**
 * loop_file_fmt_exit - Release a loop file format
 * @lo_fmt: Loop file format
 *
 * Releases the specified loop file format @lo_fmt and all its resources.
 */
extern void loop_file_fmt_exit(struct loop_file_fmt *lo_fmt);

/**
 * loop_file_fmt_read - Read IO from a loop file format
 * @lo_fmt: Loop file format
 * @rq: IO Request
 *
 * Reads IO from the file format's loop device by sending the IO read request
 * @rq to the loop file format subsystem. The subsystem calls the registered
 * callback function of the suitable loop file format driver.
 */
extern int loop_file_fmt_read(struct loop_file_fmt *lo_fmt,
			      struct request *rq);

/**
 * loop_file_fmt_read_aio - Read IO from a loop file format asynchronously
 * @lo_fmt: Loop file format
 * @rq: IO Request
 *
 * Reads IO from the file format's loop device asynchronously by sending the
 * IO read aio request @rq to the loop file format subsystem. The subsystem
 * calls the registered callback function of the suitable loop file format
 * driver.
 */
extern int loop_file_fmt_read_aio(struct loop_file_fmt *lo_fmt,
				  struct request *rq);

/**
 * loop_file_fmt_write - Write IO to a loop file format
 * @lo_fmt: Loop file format
 * @rq: IO Request
 *
 * Write IO to the file format's loop device by sending the IO write request
 * @rq to the loop file format subsystem. The subsystem calls the registered
 * callback function of the suitable loop file format driver.
 */
extern int loop_file_fmt_write(struct loop_file_fmt *lo_fmt,
			       struct request *rq);

/**
 * loop_file_fmt_write_aio - Write IO to a loop file format asynchronously
 * @lo_fmt: Loop file format
 * @rq: IO Request
 *
 * Write IO to the file format's loop device asynchronously by sending the
 * IO write aio request @rq to the loop file format subsystem. The subsystem
 * calls the registered callback function of the suitable loop file format
 * driver.
 */
extern int loop_file_fmt_write_aio(struct loop_file_fmt *lo_fmt,
				   struct request *rq);

/**
 * loop_file_fmt_discard - Discard IO on a loop file format
 * @lo_fmt: Loop file format
 * @rq: IO Request
 *
 * Discard IO on the file format's loop device by sending the IO discard
 * request @rq to the loop file format subsystem. The subsystem calls the
 * registered callback function of the suitable loop file format driver.
 */
extern int loop_file_fmt_discard(struct loop_file_fmt *lo_fmt,
				 struct request *rq);

/**
 * loop_file_fmt_flush - Flush a loop file format
 * @lo_fmt: Loop file format
 *
 * Flush the file format's loop device by calling the registered callback
 * function of the suitable loop file format driver.
 */
extern int loop_file_fmt_flush(struct loop_file_fmt *lo_fmt);

/**
 * loop_file_fmt_sector_size - Get sector size of a loop file format
 * @lo_fmt: Loop file format
 *
 * Returns the physical sector size of the loop file format's loop device.
 * If the loop file format implements a sparse disk image format, then this
 * function returns the virtual sector size.
 */
extern loff_t loop_file_fmt_sector_size(struct loop_file_fmt *lo_fmt);

/**
 * loop_file_fmt_change - Change the loop file format's type
 * @lo_fmt: Loop file format
 * @file_fmt_type_new: Loop file format type
 *
 * Changes the file format type of the already initialized loop file format
 * @lo_fmt. Therefore, the function releases the old file format and frees all
 * of its resources before the loop file format @lo_fmt is initialized and set
 * up with the new file format @file_fmt_type_new.
 */
extern int loop_file_fmt_change(struct loop_file_fmt *lo_fmt,
				u32 file_fmt_type_new);


/* helper functions of the subsystem */

/**
 * loop_file_fmt_print_type - Convert file format type to string
 * @file_fmt_type: Loop file format type
 * @file_fmt_name: Loop file format type string
 *
 * Converts the specified numeric @file_fmt_type value into a human readable
 * string stating the file format as string in @file_fmt_name.
 */
extern ssize_t loop_file_fmt_print_type(u32 file_fmt_type,
					char *file_fmt_name);

#endif
