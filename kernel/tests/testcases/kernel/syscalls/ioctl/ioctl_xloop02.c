// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about xloopdevice.
 *
 * It is designed to test XLO_FLAGS_READ_ONLY (similar as xlosetup -r)
 * and XLOOP_CHANGE_FD.
 *
 * For XLOOP_CHANGE_FD, this operation is possible only if the xloop device
 * is read-only and the new backing store is the same size and type as the
 * old backing store.
 *
 * If using XLOOP_CONFIGURE ioctl, we can set XLO_FLAGS_READ_ONLY
 * flag even though backing file with write mode.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "lapi/xloop.h"
#include "tst_test.h"

static int file_fd, file_change_fd, file_fd_invalid;
static char backing_path[1024], backing_file_path[1024], backing_file_change_path[1024];
static int attach_flag, dev_fd, xloop_configure_sup = 1;
static char xloop_ro_path[1024], dev_path[1024];
static struct xloop_config xloopconfig;

static struct tcase {
	int mode;
	int ioctl;
	char *message;
} tcases[] = {
	{O_RDONLY, XLOOP_SET_FD, "Using XLOOP_SET_FD to setup xloopdevice"},
	{O_RDWR, XLOOP_CONFIGURE, "Using XLOOP_CONFIGURE with read_only flag"},
};

static void verify_ioctl_xloop(unsigned int n)
{
	struct tcase *tc = &tcases[n];
	struct xloop_info xloopinfoget;

	if (tc->ioctl == XLOOP_CONFIGURE && !xloop_configure_sup) {
		tst_res(TCONF, "XLOOP_CONFIGURE ioctl not supported");
		return;
	}

	tst_res(TINFO, "%s", tc->message);
	file_fd = SAFE_OPEN("test.img", tc->mode);

	if (tc->ioctl == XLOOP_SET_FD) {
		SAFE_IOCTL(dev_fd, XLOOP_SET_FD, file_fd);
	} else {
		xloopconfig.fd = file_fd;
		SAFE_IOCTL(dev_fd, XLOOP_CONFIGURE, &xloopconfig);
	}
	attach_flag = 1;

	TST_ASSERT_INT(xloop_ro_path, 1);
	TST_ASSERT_STR(backing_path, backing_file_path);

	memset(&xloopinfoget, 0, sizeof(xloopinfoget));

	SAFE_IOCTL(dev_fd, XLOOP_GET_STATUS, &xloopinfoget);

	if (xloopinfoget.xlo_flags & ~XLO_FLAGS_READ_ONLY)
		tst_res(TFAIL, "xlo_flags has unexpected %d flag", xloopinfoget.xlo_flags);
	else
		tst_res(TPASS, "xlo_flags only has default XLO_FLAGS_READ_ONLY flag");

	TEST(write(dev_fd, "xx", 2));
	if (TST_RET != -1)
		tst_res(TFAIL, "write succeed unexpectedly");
	else
		tst_res(TPASS | TTERRNO, "Can not write data in RO mode");

	TEST(ioctl(dev_fd, XLOOP_CHANGE_FD, file_change_fd));
	if (TST_RET) {
		tst_res(TFAIL | TTERRNO, "XLOOP_CHANGE_FD failed");
	} else {
		tst_res(TPASS, "XLOOP_CHANGE_FD succeeded");
		TST_ASSERT_INT(xloop_ro_path, 1);
		TST_ASSERT_STR(backing_path, backing_file_change_path);
	}

	TEST(ioctl(dev_fd, XLOOP_CHANGE_FD, file_fd_invalid));
	if (TST_RET) {
		if (TST_ERR == EINVAL)
			tst_res(TPASS | TTERRNO, "XLOOP_CHANGE_FD failed as expected");
		else
			tst_res(TFAIL | TTERRNO, "XLOOP_CHANGE_FD failed expected EINVAL got");
	} else {
		tst_res(TFAIL, "XLOOP_CHANGE_FD succeeded");
	}

	SAFE_CLOSE(file_fd);
	tst_detach_device_by_fd(dev_path, dev_fd);
	attach_flag = 0;
}

static void setup(void)
{
	int dev_num;
	int ret;

	char *tmpdir = tst_get_tmpdir();
	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	tst_fill_file("test.img", 0, 1024, 10);
	tst_fill_file("test1.img", 0, 1024, 10);
	tst_fill_file("test2.img", 0, 2048, 20);

	sprintf(backing_path, "/sys/block/xloop%d/xloop/backing_file", dev_num);
	sprintf(backing_file_path, "%s/test.img", tmpdir);
	sprintf(backing_file_change_path, "%s/test1.img", tmpdir);
	sprintf(xloop_ro_path, "/sys/block/xloop%d/ro", dev_num);

	free(tmpdir);

	file_change_fd = SAFE_OPEN("test1.img", O_RDWR);
	file_fd_invalid = SAFE_OPEN("test2.img", O_RDWR);

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	xloopconfig.fd = -1;
	ret = ioctl(dev_fd, XLOOP_CONFIGURE, &xloopconfig);

	if (ret && errno != EBADF) {
		tst_res(TINFO | TERRNO, "XLOOP_CONFIGURE is not supported");
		xloop_configure_sup = 0;
	}
	xloopconfig.info.xlo_flags = XLO_FLAGS_READ_ONLY;
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (file_fd > 0)
		SAFE_CLOSE(file_fd);
	if (file_change_fd > 0)
		SAFE_CLOSE(file_change_fd);
	if (file_fd_invalid > 0)
		SAFE_CLOSE(file_fd_invalid);
	if (attach_flag)
		tst_detach_device(dev_path);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.tcnt = ARRAY_SIZE(tcases),
	.test = verify_ioctl_xloop,
	.needs_root = 1,
	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"xloop",
		"xloop_file_fmt_raw",
		NULL
	}
};
