// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about xloopdevice.
 *
 * It is designed to test XLOOP_SET_DIRECT_IO can update a live
 * xloop device dio mode. It needs the backing file also supports
 * dio mode and the xlo_offset is aligned with the logical block size.
 *
 * The direct I/O error handling is a bit messy on Linux, some filesystems
 * return error when it coudln't be enabled, some silently fall back to regular
 * buffered I/O.
 *
 * The XLOOP_SET_DIRECT_IO ioctl() may ignore all checks if it cannot get the
 * logical block size which is the case if the block device pointer in the
 * backing file inode is not set. In this case the direct I/O appears to be
 * enabled but falls back to buffered I/O later on. This is the case at least
 * for Btrfs. Because of that the test passes both with failure as well as
 * success with non-zero offset.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>
#include "lapi/xloop.h"
#include "tst_test.h"

#define DIO_MESSAGE "In dio mode"
#define NON_DIO_MESSAGE "In non dio mode"

static char dev_path[1024], sys_xloop_diopath[1024], backing_file_path[1024];;
static int dev_num, dev_fd, block_devfd, attach_flag, logical_block_size;

static void check_dio_value(int flag)
{
	struct xloop_info xloopinfoget;

	memset(&xloopinfoget, 0, sizeof(xloopinfoget));

	SAFE_IOCTL(dev_fd, XLOOP_GET_STATUS, &xloopinfoget);
	tst_res(TINFO, "%s", flag ? DIO_MESSAGE : NON_DIO_MESSAGE);

	if (xloopinfoget.xlo_flags & XLO_FLAGS_DIRECT_IO)
		tst_res(flag ? TPASS : TFAIL, "xlo_flags has XLO_FLAGS_DIRECT_IO flag");
	else
		tst_res(flag ? TFAIL : TPASS, "xlo_flags doesn't have XLO_FLAGS_DIRECT_IO flag");

	TST_ASSERT_INT(sys_xloop_diopath, flag);
}

static void verify_ioctl_xloop(void)
{
	struct xloop_info xloopinfo;

	memset(&xloopinfo, 0, sizeof(xloopinfo));
	TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_STATUS, &xloopinfo), TST_RETVAL_EQ0);

	tst_res(TINFO, "Without setting xlo_offset or sizelimit");
	SAFE_IOCTL(dev_fd, XLOOP_SET_DIRECT_IO, 1);
	check_dio_value(1);

	SAFE_IOCTL(dev_fd, XLOOP_SET_DIRECT_IO, 0);
	check_dio_value(0);

	tst_res(TINFO, "With offset equal to logical_block_size");
	xloopinfo.xlo_offset = logical_block_size;
	TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_STATUS, &xloopinfo), TST_RETVAL_EQ0);
	TEST(ioctl(dev_fd, XLOOP_SET_DIRECT_IO, 1));
	if (TST_RET == 0) {
		tst_res(TPASS, "XLOOP_SET_DIRECT_IO succeeded");
		check_dio_value(1);
		SAFE_IOCTL(dev_fd, XLOOP_SET_DIRECT_IO, 0);
	} else {
		tst_res(TFAIL | TTERRNO, "XLOOP_SET_DIRECT_IO failed");
	}

	tst_res(TINFO, "With nonzero offset less than logical_block_size");
	xloopinfo.xlo_offset = logical_block_size / 2;
	TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_STATUS, &xloopinfo), TST_RETVAL_EQ0);

	TEST(ioctl(dev_fd, XLOOP_SET_DIRECT_IO, 1));
	if (TST_RET == 0) {
		tst_res(TPASS, "XLOOP_SET_DIRECT_IO succeeded, offset is ignored");
		SAFE_IOCTL(dev_fd, XLOOP_SET_DIRECT_IO, 0);
		return;
	}
	if (TST_ERR == EINVAL)
		tst_res(TPASS | TTERRNO, "XLOOP_SET_DIRECT_IO failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "XLOOP_SET_DIRECT_IO failed expected EINVAL got");
}

static void setup(void)
{
	char bd_path[100];

	if (tst_fs_type(".") == TST_TMPFS_MAGIC)
		tst_brk(TCONF, "tmpfd doesn't support O_DIRECT flag");

	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	sprintf(sys_xloop_diopath, "/sys/block/xloop%d/xloop/dio", dev_num);
	tst_fill_file("test.img", 0, 1024, 1024);

	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;
	dev_fd = SAFE_OPEN(dev_path, O_RDWR);

	if (ioctl(dev_fd, XLOOP_SET_DIRECT_IO, 0) && errno == EINVAL)
		tst_brk(TCONF, "XLOOP_SET_DIRECT_IO is not supported");

	/*
	 * from __xloop_update_dio():
	 *   We support direct I/O only if xlo_offset is aligned with the
	 *   logical I/O size of backing device, and the logical block
	 *   size of xloop is bigger than the backing device's and the xloop
	 *   needn't transform transfer.
	 */
	sprintf(backing_file_path, "%s/test.img", tst_get_tmpdir());
	tst_find_backing_dev(backing_file_path, bd_path);
	block_devfd = SAFE_OPEN(bd_path, O_RDWR);
	SAFE_IOCTL(block_devfd, BLKSSZGET, &logical_block_size);
	tst_res(TINFO, "backing dev(%s) logical_block_size is %d", bd_path, logical_block_size);
	SAFE_CLOSE(block_devfd);
	if (logical_block_size > 512)
		TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_BLOCK_SIZE, logical_block_size), TST_RETVAL_EQ0);
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (block_devfd > 0)
		SAFE_CLOSE(block_devfd);
	if (attach_flag)
		tst_detach_device(dev_path);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_ioctl_xloop,
	.needs_root = 1,
	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"xloop",
		"xloop_file_fmt_raw",
		NULL
	}
};
