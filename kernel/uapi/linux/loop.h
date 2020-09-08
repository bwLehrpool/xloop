/* SPDX-License-Identifier: GPL-1.0+ WITH Linux-syscall-note */
/*
 * include/linux/loop.h
 *
 * Written by Theodore Ts'o, 3/29/93.
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 */
#ifndef _UAPI_LINUX_XLOOP_H
#define _UAPI_LINUX_XLOOP_H


#define XLO_NAME_SIZE     64
#define XLO_KEY_SIZE      32


/*
 * xloop flags
 */
enum {
	XLO_FLAGS_READ_ONLY	=  1,
	XLO_FLAGS_AUTOCLEAR	=  4,
	XLO_FLAGS_PARTSCAN	=  8,
	XLO_FLAGS_DIRECT_IO	= 16,
};

/* XLO_FLAGS that can be set using XLOOP_SET_STATUS(64) */
#define XLOOP_SET_STATUS_SETTABLE_FLAGS (XLO_FLAGS_AUTOCLEAR | XLO_FLAGS_PARTSCAN)

/* XLO_FLAGS that can be cleared using XLOOP_SET_STATUS(64) */
#define XLOOP_SET_STATUS_CLEARABLE_FLAGS (XLO_FLAGS_AUTOCLEAR)

/* XLO_FLAGS that can be set using XLOOP_CONFIGURE */
#define XLOOP_CONFIGURE_SETTABLE_FLAGS (XLO_FLAGS_READ_ONLY | XLO_FLAGS_AUTOCLEAR \
				       | XLO_FLAGS_PARTSCAN | XLO_FLAGS_DIRECT_IO)

#include <asm/posix_types.h>  /* for __kernel_old_dev_t */
#include <linux/types.h>	  /* for __u64 */

/* Backwards compatibility version */
struct xloop_info {
	int                xlo_number;                    /* ioctl r/o */
	__kernel_old_dev_t xlo_device;                    /* ioctl r/o */
	unsigned long      xlo_inode;                     /* ioctl r/o */
	__kernel_old_dev_t xlo_rdevice;                   /* ioctl r/o */
	int                xlo_offset;
	int                xlo_encrypt_type;
	int                xlo_encrypt_key_size;          /* ioctl w/o */
	int                xlo_flags;
	char               xlo_name[XLO_NAME_SIZE];
	unsigned char      xlo_encrypt_key[XLO_KEY_SIZE]; /* ioctl w/o */
	unsigned long      xlo_init[2];
	char               reserved[4];
	int                xlo_file_fmt_type;
};

struct xloop_info64 {
	__u64              xlo_device;                     /* ioctl r/o */
	__u64              xlo_inode;                      /* ioctl r/o */
	__u64              xlo_rdevice;                    /* ioctl r/o */
	__u64              xlo_offset;
	__u64              xlo_sizelimit;  /* bytes, 0 == max available */
	__u32              xlo_number;                     /* ioctl r/o */
	__u32              xlo_encrypt_type;
	__u32              xlo_encrypt_key_size;           /* ioctl w/o */
	__u32              xlo_flags;
	__u8               xlo_file_name[XLO_NAME_SIZE];
	__u8               xlo_crypt_name[XLO_NAME_SIZE];
	__u8               xlo_encrypt_key[XLO_KEY_SIZE];  /* ioctl w/o */
	__u64              xlo_init[2];
	__u32              xlo_file_fmt_type;
};

/**
 * struct xloop_config - Complete configuration for a xloop device.
 * @fd: fd of the file to be used as a backing file for the xloop device.
 * @block_size: block size to use; ignored if 0.
 * @info: struct xloop_info64 to configure the xloop device with.
 *
 * This structure is used with the XLOOP_CONFIGURE ioctl, and can be used to
 * atomically setup and configure all xloop device parameters at once.
 */
struct xloop_config {
	__u32               fd;
	__u32               block_size;
	struct xloop_info64	info;
	__u64               __reserved[8];
};

/*
 * xloop filter types
 */
#define XLO_CRYPT_NONE        0
#define XLO_CRYPT_XOR         1
#define XLO_CRYPT_DES         2
#define XLO_CRYPT_FISH2       3  /* Twofish encryption */
#define XLO_CRYPT_BLOW        4
#define XLO_CRYPT_CAST128     5
#define XLO_CRYPT_IDEA        6
#define XLO_CRYPT_DUMMY       9
#define XLO_CRYPT_SKIPJACK   10
#define XLO_CRYPT_CRYPTOAPI  18
#define MAX_XLO_CRYPT        20

/*
 * IOCTL commands --- we will commandeer 0x4C ('L')
 */
#define XLOOP_SET_FD         0x4C00
#define XLOOP_CLR_FD         0x4C01
#define XLOOP_SET_STATUS     0x4C02
#define XLOOP_GET_STATUS     0x4C03
#define XLOOP_SET_STATUS64   0x4C04
#define XLOOP_GET_STATUS64   0x4C05
#define XLOOP_CHANGE_FD      0x4C06
#define XLOOP_SET_CAPACITY   0x4C07
#define XLOOP_SET_DIRECT_IO  0x4C08
#define XLOOP_SET_BLOCK_SIZE 0x4C09
#define XLOOP_CONFIGURE      0x4C0A

/* /dev/xloop-control interface */
#define XLOOP_CTL_ADD        0x4C80
#define XLOOP_CTL_REMOVE     0x4C81
#define XLOOP_CTL_GET_FREE   0x4C82
#endif /* _UAPI_LINUX_XLOOP_H */
