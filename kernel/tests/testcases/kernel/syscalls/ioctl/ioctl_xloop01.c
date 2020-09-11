// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about xloopdevice.
 * It is designed to test XLO_FLAGS_AUTOCLEAR and XLO_FLAGS_PARTSCAN flag.
 *
 * For XLO_FLAGS_AUTOCLEAR flag, we only check autoclear field value in sys
 * directory and also get xlo_flags by using XLOOP_GET_STATUS.
 *
 * For XLO_FLAGS_PARTSCAN flag, it is the same as XLO_FLAGS_AUTOCLEAR flag.
 * But we also check whether we can scan partition table correctly ie check
 * whether /dev/xloopnp1 and /sys/bloclk/xloop0/xloop0p1 existed.
 *
 * For XLO_FLAGS_AUTOCLEAR flag, it can be clear. For XLO_FLAGS_PARTSCAN flag,
 * it cannot be clear. We also check this.
 *
 * It is also a regression test for kernel
 * commit 10c70d95c0f2 ("block: remove the bd_openers checks in blk_drop_partitions")
 * commit 6ac92fb5cdff ("xloop: Fix wrong masking of status flags").
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "lapi/xloop.h"
#include "tst_test.h"

static char dev_path[1024], backing_path[1024], backing_file_path[1024];
static int dev_num, attach_flag, dev_fd, parted_sup;

/*
 * In drivers/block/xloop.c code, set status function doesn't handle
 * XLO_FLAGS_READ_ONLY flag and ingore it. Only xloop_set_fd with read only mode
 * file_fd, xlo_flags will include XLO_FLAGS_READ_ONLY and it's the same for
 * XLO_FLAGS_DIRECT_IO.
 */
#define SET_FLAGS (XLO_FLAGS_AUTOCLEAR | XLO_FLAGS_PARTSCAN | XLO_FLAGS_READ_ONLY | XLO_FLAGS_DIRECT_IO)
#define GET_FLAGS (XLO_FLAGS_AUTOCLEAR | XLO_FLAGS_PARTSCAN)

static char partscan_path[1024], autoclear_path[1024];
static char xloop_partpath[1026], sys_xloop_partpath[1026];

static void check_xloop_value(int set_flag, int get_flag, int autoclear_field)
{
	struct xloop_info xloopinfo = {0}, xloopinfoget = {0};
	int ret;

	xloopinfo.xlo_flags = set_flag;
	SAFE_IOCTL(dev_fd, XLOOP_SET_STATUS, &xloopinfo);
	SAFE_IOCTL(dev_fd, XLOOP_GET_STATUS, &xloopinfoget);

	if (xloopinfoget.xlo_flags & ~get_flag)
		tst_res(TFAIL, "expect %d but got %d", get_flag, xloopinfoget.xlo_flags);
	else
		tst_res(TPASS, "get expected xlo_flag %d", xloopinfoget.xlo_flags);

	TST_ASSERT_INT(partscan_path, 1);
	TST_ASSERT_INT(autoclear_path, autoclear_field);

	if (!parted_sup) {
		tst_res(TINFO, "Current environment doesn't have parted disk, skip it");
		return;
	}

	ret = TST_RETRY_FN_EXP_BACKOFF(access(xloop_partpath, F_OK), TST_RETVAL_EQ0, 30);
	if (ret == 0)
		tst_res(TPASS, "access %s succeeds", xloop_partpath);
	else
		tst_res(TFAIL, "access %s fails", xloop_partpath);

	ret = TST_RETRY_FN_EXP_BACKOFF(access(sys_xloop_partpath, F_OK), TST_RETVAL_EQ0, 30);
	if (ret == 0)
		tst_res(TPASS, "access %s succeeds", sys_xloop_partpath);
	else
		tst_res(TFAIL, "access %s fails", sys_xloop_partpath);
}

static void verify_ioctl_xloop(void)
{
	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;

	TST_ASSERT_INT(partscan_path, 0);
	TST_ASSERT_INT(autoclear_path, 0);
	TST_ASSERT_STR(backing_path, backing_file_path);

	check_xloop_value(SET_FLAGS, GET_FLAGS, 1);

	tst_res(TINFO, "Test flag can be clear");
	check_xloop_value(0, XLO_FLAGS_PARTSCAN, 0);

	tst_detach_device_by_fd(dev_path, dev_fd);
	attach_flag = 0;
}

static void setup(void)
{
	int ret;
	const char *const cmd_parted[] = {"parted", "-s", "test.img", "mklabel", "msdos", "mkpart",
	                                  "primary", "ext4", "1M", "10M", NULL};

	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	tst_fill_file("test.img", 0, 1024 * 1024, 10);

	ret = tst_cmd(cmd_parted, NULL, NULL, TST_CMD_PASS_RETVAL);
	switch (ret) {
	case 0:
		parted_sup = 1;
	break;
	case 255:
		tst_res(TCONF, "parted binary not installed or failed");
	break;
	default:
		tst_res(TCONF, "parted exited with %i", ret);
	break;
	}

	sprintf(partscan_path, "/sys/block/xloop%d/xloop/partscan", dev_num);
	sprintf(autoclear_path, "/sys/block/xloop%d/xloop/autoclear", dev_num);
	sprintf(backing_path, "/sys/block/xloop%d/xloop/backing_file", dev_num);
	sprintf(sys_xloop_partpath, "/sys/block/xloop%d/xloop%dp1", dev_num, dev_num);
	sprintf(backing_file_path, "%s/test.img", tst_get_tmpdir());
	sprintf(xloop_partpath, "%sp1", dev_path);
	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (attach_flag)
		tst_detach_device(dev_path);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = verify_ioctl_xloop,
	.needs_root = 1,
	.needs_drivers = (const char *const []) {
		"xloop",
		"xloop_file_fmt_raw",
		NULL
	},
	.tags = (const struct tst_tag[]) {
		{"linux-git", "10c70d95c0f2"},
		{"linux-git", "6ac92fb5cdff"},
		{}
	},
	.needs_tmpdir = 1,
};
