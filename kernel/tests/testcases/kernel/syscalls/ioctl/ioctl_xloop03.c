// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about xloopdevice.
 *
 * It is designed to test XLOOP_CHANGE_FD can not succeed (get EINVAL error)
 * when xloop_dev is not read only.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "lapi/xloop.h"
#include "tst_test.h"

static char dev_path[1024];
static int dev_num, dev_fd, file_fd, attach_flag;

static void verify_ioctl_xloop(void)
{
	TEST(ioctl(dev_fd, XLOOP_CHANGE_FD, file_fd));
	if (TST_RET == 0) {
		tst_res(TFAIL, "XLOOP_CHANGE_FD succeeded unexpectedly");
		return;
	}
	if (TST_ERR == EINVAL)
		tst_res(TPASS | TTERRNO, "XLOOP_CHANGE_FD failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "XLOOP_CHANGE_FD failed expected EINVAL got");
}

static void setup(void)
{
	struct xloop_info xloopinfoget;

	memset(&xloopinfoget, 0, sizeof(xloopinfoget));
	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	tst_fill_file("test.img", 0, 1024, 10);
	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	file_fd = SAFE_OPEN("test.img", O_RDWR);
	SAFE_IOCTL(dev_fd, XLOOP_GET_STATUS, &xloopinfoget);

	if (xloopinfoget.xlo_flags & XLO_FLAGS_READ_ONLY)
		tst_brk(TCONF, "Current environment has unexpected XLO_FLAGS_READ_ONLY flag");
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (file_fd > 0)
		SAFE_CLOSE(file_fd);
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
