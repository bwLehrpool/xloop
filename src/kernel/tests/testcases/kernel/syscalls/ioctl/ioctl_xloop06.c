/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

static int check_direct_io(int device_fd, const char *sysfs_dio, int expected)
{
	struct xloop_info info;
	memset(&info, 0, sizeof(info));
	if (retry_ioctl(device_fd, XLOOP_GET_STATUS, &info) != 0) {
		tst_res(TFAIL, "XLOOP_GET_STATUS failed: %s", strerror(errno));
		return -1;
	}
	if (((info.xlo_flags & XLO_FLAGS_DIRECT_IO) != 0) == (expected != 0))
		tst_res(TPASS, "direct-I/O status flag is %s", expected != 0 ? "set" : "clear");
	else
		tst_res(TFAIL, "direct-I/O status flag has the wrong value");
	return assert_int(sysfs_dio, expected);
}

int main(void)
{
	char device_path[PATH_MAX];
	char sysfs_dio[PATH_MAX];
	char backing_device[PATH_MAX];
	int device_number;
	int device_fd = -1;
	int backing_fd = -1;
	int attached = 0;
	int logical_block_size = 512;
	long filesystem_type;
	struct xloop_info status;
	if (test_begin() != 0)
		return test_finish();
	if (fs_type(".", &filesystem_type) == 0 && filesystem_type == 0x01021994L) {
		tst_res(TCONF, "tmpfs does not support direct I/O");
		return test_finish();
	}
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", 1024U * 1024U, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		goto cleanup;
	}
	(void)snprintf(sysfs_dio, sizeof(sysfs_dio), "/sys/block/xloop%d/xloop/dio", device_number);
	device_fd = attach_device(device_path, "test.img", 0U);
	if (device_fd < 0) {
		tst_res(TBROK, "cannot attach xloop device: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	if (ioctl(device_fd, XLOOP_SET_DIRECT_IO, 0UL) != 0 && errno == EINVAL) {
		tst_res(TCONF, "XLOOP_SET_DIRECT_IO is unsupported");
		goto cleanup;
	}
	if (find_backing_device("test.img", backing_device, sizeof(backing_device)) != 0) {
		tst_res(TCONF, "cannot locate the backing filesystem block device");
		goto cleanup;
	}
	backing_fd = open(backing_device, O_RDONLY | O_CLOEXEC);
	if (backing_fd < 0 || ioctl(backing_fd, BLKSSZGET, &logical_block_size) != 0) {
		tst_res(TCONF, "cannot determine backing-device logical block size");
		goto cleanup;
	}
	(void)close(backing_fd);
	backing_fd = -1;
	if (logical_block_size > 512 &&
		ioctl(device_fd, XLOOP_SET_BLOCK_SIZE, (unsigned long)logical_block_size) != 0) {
		tst_res(TCONF, "cannot set xloop logical block size: %s", strerror(errno));
		goto cleanup;
	}
	memset(&status, 0, sizeof(status));
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS, &status) != 0 ||
		ioctl(device_fd, XLOOP_SET_DIRECT_IO, 1UL) != 0) {
		tst_res(TFAIL, "cannot enable direct I/O at offset zero: %s", strerror(errno));
		goto cleanup;
	}
	(void)check_direct_io(device_fd, sysfs_dio, 1);
	if (ioctl(device_fd, XLOOP_SET_DIRECT_IO, 0UL) != 0) {
		tst_res(TFAIL, "cannot disable direct I/O: %s", strerror(errno));
		goto cleanup;
	}
	(void)check_direct_io(device_fd, sysfs_dio, 0);
	status.xlo_offset = (uint64_t)logical_block_size;
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS, &status) != 0 ||
		ioctl(device_fd, XLOOP_SET_DIRECT_IO, 1UL) != 0) {
		tst_res(TFAIL, "direct I/O failed at aligned offset: %s", strerror(errno));
		goto cleanup;
	}
	(void)check_direct_io(device_fd, sysfs_dio, 1);
	(void)ioctl(device_fd, XLOOP_SET_DIRECT_IO, 0UL);
	status.xlo_offset = (uint64_t)(logical_block_size / 2);
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS, &status) != 0) {
		tst_res(TFAIL, "cannot set unaligned offset: %s", strerror(errno));
		goto cleanup;
	}
	if (ioctl(device_fd, XLOOP_SET_DIRECT_IO, 1UL) == 0) {
		tst_res(TPASS, "direct-I/O ioctl accepts the unaligned offset");
		(void)ioctl(device_fd, XLOOP_SET_DIRECT_IO, 0UL);
	} else if (errno == EINVAL) {
		tst_res(TPASS, "direct-I/O ioctl rejects the unaligned offset with EINVAL");
	} else {
		tst_res(TFAIL, "direct-I/O ioctl failed unexpectedly: %s", strerror(errno));
	}
cleanup:
	if (attached != 0)
		(void)detach_by_fd(device_path, device_fd);
	if (backing_fd >= 0)
		(void)close(backing_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	return test_finish();
}
