/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

static int change_backing_file(int device_fd, int backing_fd)
{
	return ioctl(device_fd, XLOOP_CHANGE_FD, backing_fd);
}

int main(void)
{
	char device_path[PATH_MAX];
	char sysfs_ro[PATH_MAX];
	char sysfs_backing[PATH_MAX];
	char expected_path[PATH_MAX];
	int device_number;
	int device_fd = -1;
	int readonly_fd = -1;
	int same_size_fd = -1;
	int invalid_size_fd = -1;
	int config_fd = -1;
	int attached = 0;
	struct xloop_config probe;
	int configure_supported;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", 10U * 1024U, 0U) != 0 ||
		fill_file("same.img", 10U * 1024U, 1U) != 0 ||
		fill_file("large.img", 20U * 1024U, 2U) != 0) {
		tst_res(TBROK, "cannot create backing files: %s", strerror(errno));
		goto cleanup;
	}
	device_fd = open_device(device_path);
	readonly_fd = open("test.img", O_RDONLY | O_CLOEXEC);
	same_size_fd = open("same.img", O_RDWR | O_CLOEXEC);
	invalid_size_fd = open("large.img", O_RDWR | O_CLOEXEC);
	if (device_fd < 0 || readonly_fd < 0 || same_size_fd < 0 || invalid_size_fd < 0) {
		tst_res(TBROK, "cannot open test files or device: %s", strerror(errno));
		goto cleanup;
	}
	if (ioctl(device_fd, XLOOP_SET_FD, readonly_fd) != 0) {
		tst_res(TBROK, "XLOOP_SET_FD failed: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	(void)snprintf(sysfs_ro, sizeof(sysfs_ro), "/sys/block/xloop%d/ro", device_number);
	(void)snprintf(sysfs_backing, sizeof(sysfs_backing), "/sys/block/xloop%d/xloop/backing_file", device_number);
	if (append_path(expected_path, sizeof(expected_path), xloop_test_tmpdir,
		"/test.img") != 0) {
		tst_res(TBROK, "cannot construct backing path: %s", strerror(errno));
		goto cleanup;
	}
	(void)assert_int(sysfs_ro, 1);
	(void)assert_str(sysfs_backing, expected_path);
	{
		struct xloop_info info;
		memset(&info, 0, sizeof(info));
		if (retry_ioctl(device_fd, XLOOP_GET_STATUS, &info) == 0 &&
			(info.xlo_flags & XLO_FLAGS_READ_ONLY) != 0)
			tst_res(TPASS, "read-only flag is reported");
		else
			tst_res(TFAIL, "read-only flag is missing");
	}
	if (write(device_fd, "x", 1U) < 0 && errno == EROFS)
		tst_res(TPASS, "writes are rejected on the read-only xloop device");
	else
		tst_res(TFAIL, "write unexpectedly succeeded on read-only xloop device");
	if (change_backing_file(device_fd, same_size_fd) == 0) {
		tst_res(TPASS, "XLOOP_CHANGE_FD accepts an equal-size backing file");
		if (append_path(expected_path, sizeof(expected_path), xloop_test_tmpdir,
			"/same.img") != 0) {
			tst_res(TBROK, "cannot construct backing path: %s", strerror(errno));
			goto cleanup;
		}
		(void)assert_str(sysfs_backing, expected_path);
	} else {
		tst_res(TFAIL, "XLOOP_CHANGE_FD rejected an equal-size backing file: %s", strerror(errno));
	}
	if (change_backing_file(device_fd, invalid_size_fd) != 0 && errno == EINVAL)
		tst_res(TPASS, "XLOOP_CHANGE_FD rejects a different-size backing file");
	else
		tst_res(TFAIL, "XLOOP_CHANGE_FD did not reject a different-size backing file");
	(void)detach_by_fd(device_path, device_fd);
	attached = 0;
	memset(&probe, 0, sizeof(probe));
	probe.fd = UINT32_MAX;
	configure_supported = ioctl(device_fd, XLOOP_CONFIGURE, &probe) != 0 && errno == EBADF;
	if (configure_supported != 0) {
		memset(&probe, 0, sizeof(probe));
		config_fd = open("test.img", O_RDWR | O_CLOEXEC);
		probe.fd = config_fd < 0 ? UINT32_MAX : (uint32_t)config_fd;
		probe.info.xlo_flags = XLO_FLAGS_READ_ONLY;
		if (config_fd < 0 || ioctl(device_fd, XLOOP_CONFIGURE, &probe) != 0) {
			tst_res(TFAIL, "XLOOP_CONFIGURE read-only setup failed: %s", strerror(errno));
		} else {
			attached = 1;
			if (append_path(expected_path, sizeof(expected_path), xloop_test_tmpdir,
				"/test.img") != 0) {
				tst_res(TBROK, "cannot construct backing path: %s", strerror(errno));
				goto cleanup;
			}
			(void)assert_int(sysfs_ro, 1);
			(void)assert_str(sysfs_backing, expected_path);
			(void)detach_by_fd(device_path, device_fd);
			attached = 0;
		}
	} else {
		tst_res(TCONF, "XLOOP_CONFIGURE is unsupported");
	}
cleanup:
	if (attached != 0 && device_fd >= 0)
		(void)detach_by_fd(device_path, device_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	if (readonly_fd >= 0)
		(void)close(readonly_fd);
	if (same_size_fd >= 0)
		(void)close(same_size_fd);
	if (invalid_size_fd >= 0)
		(void)close(invalid_size_fd);
	if (config_fd >= 0)
		(void)close(config_fd);
	return test_finish();
}
