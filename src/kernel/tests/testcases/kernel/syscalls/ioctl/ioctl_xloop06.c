// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic error test about the invalid block size of xloopdevice
 * by using XLOOP_SET_BLOCK_SIZE or XLOOP_CONFIGURE ioctl.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include "lapi/xloop.h"
#include "tst_test.h"

static char dev_path[1024];
static int dev_num, dev_fd, file_fd, attach_flag, xloop_configure_sup = 1;
static unsigned int invalid_value, half_value, unalign_value;
static struct xloop_config xloopconfig;

static struct tcase {
	unsigned int *setvalue;
	int ioctl_flag;
	char *message;
} tcases[] = {
	{&half_value, XLOOP_SET_BLOCK_SIZE,
	"Using XLOOP_SET_BLOCK_SIZE with arg < 512"},

	{&invalid_value, XLOOP_SET_BLOCK_SIZE,
	"Using XLOOP_SET_BLOCK_SIZE with arg > PAGE_SIZE"},

	{&unalign_value, XLOOP_SET_BLOCK_SIZE,
	"Using XLOOP_SET_BLOCK_SIZE with arg != power_of_2"},

	{&half_value, XLOOP_CONFIGURE,
	"Using XLOOP_CONFIGURE with block_size < 512"},

	{&invalid_value, XLOOP_CONFIGURE,
	"Using XLOOP_CONFIGURE with block_size > PAGE_SIZE"},

	{&unalign_value, XLOOP_CONFIGURE,
	"Using XLOOP_CONFIGURE with block_size != power_of_2"},
};

static void verify_ioctl_xloop(unsigned int n)
{
	if (tcases[n].ioctl_flag == XLOOP_CONFIGURE)
		TEST(ioctl(dev_fd, XLOOP_CONFIGURE, &xloopconfig));
	else
		TEST(ioctl(dev_fd, XLOOP_SET_BLOCK_SIZE, *(tcases[n].setvalue)));

	if (TST_RET == 0) {
		tst_res(TFAIL, "Set block size succeed unexpectedly");
		if (tcases[n].ioctl_flag == XLOOP_CONFIGURE)
			tst_detach_device_by_fd(dev_path, dev_fd);
		return;
	}
	if (TST_ERR == EINVAL)
		tst_res(TPASS | TTERRNO, "Set block size failed as expected");
	else
		tst_res(TFAIL | TTERRNO, "Set block size failed expected EINVAL got");
}

static void run(unsigned int n)
{
	struct tcase *tc = &tcases[n];

	tst_res(TINFO, "%s", tc->message);
	if (tc->ioctl_flag == XLOOP_SET_BLOCK_SIZE) {
		if (!attach_flag) {
			tst_attach_device(dev_path, "test.img");
			attach_flag = 1;
		}
		verify_ioctl_xloop(n);
		return;
	}

	if (tc->ioctl_flag == XLOOP_CONFIGURE && !xloop_configure_sup) {
		tst_res(TCONF, "XLOOP_CONFIGURE ioctl not supported");
		return;
	}
	if (attach_flag) {
		tst_detach_device_by_fd(dev_path, dev_fd);
		attach_flag = 0;
	}
	xloopconfig.block_size = *(tc->setvalue);
	verify_ioctl_xloop(n);
}

static void setup(void)
{
	unsigned int pg_size;
	int ret;

	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	tst_fill_file("test.img", 0, 1024, 1024);
	half_value = 256;
	pg_size = getpagesize();
	invalid_value = pg_size * 2 ;
	unalign_value = pg_size - 1;

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);

	if (ioctl(dev_fd, XLOOP_SET_BLOCK_SIZE, 512) && errno == EINVAL)
		tst_brk(TCONF, "XLOOP_SET_BLOCK_SIZE is not supported");

	file_fd = SAFE_OPEN("test.img", O_RDWR);
	xloopconfig.fd = -1;
	ret = ioctl(dev_fd, XLOOP_CONFIGURE, &xloopconfig);
	if (ret && errno != EBADF) {
		tst_res(TINFO | TERRNO, "XLOOP_CONFIGURE is not supported");
		xloop_configure_sup = 0;
		return;
	}
	xloopconfig.fd = file_fd;
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
	.test = run,
	.tcnt = ARRAY_SIZE(tcases),
	.needs_root = 1,
	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"xloop",
		"xloop_file_fmt_raw",
		NULL
	}
};
