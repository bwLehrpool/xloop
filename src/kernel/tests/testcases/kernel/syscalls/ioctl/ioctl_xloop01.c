/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

#define SET_FLAGS (XLO_FLAGS_AUTOCLEAR | XLO_FLAGS_PARTSCAN | XLO_FLAGS_READ_ONLY | XLO_FLAGS_DIRECT_IO)
#define GET_FLAGS (XLO_FLAGS_AUTOCLEAR | XLO_FLAGS_PARTSCAN)

int main(void)
{
	char device_path[PATH_MAX];
	char sysfs[PATH_MAX];
	char backing_sysfs[PATH_MAX];
	char expected_backing[PATH_MAX];
	char partition_device[PATH_MAX];
	char partition_sysfs[PATH_MAX];
	char *parted_arguments[] = { "parted", "-s", "test.img", "mklabel", "msdos", "mkpart",
		"primary", "ext4", "1M", "10M", NULL };
	struct xloop_info set_status;
	struct xloop_info get_status;
	int device_number;
	int device_fd = -1;
	int attached = 0;
	int parted_available = 0;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", 10U * 1024U * 1024U, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		return test_finish();
	}
	if (run_cmd(parted_arguments) == 0)
		parted_available = 1;
	else
		tst_res(TCONF, "parted is unavailable or could not create a partition table");
	(void)snprintf(sysfs, sizeof(sysfs), "/sys/block/xloop%d/xloop", device_number);
	if (append_path(expected_backing, sizeof(expected_backing), xloop_test_tmpdir,
		"/test.img") != 0 || append_path(partition_device, sizeof(partition_device),
		device_path, "p1") != 0) {
		tst_res(TBROK, "cannot construct test paths: %s", strerror(errno));
		goto cleanup;
	}
	(void)snprintf(partition_sysfs, sizeof(partition_sysfs), "/sys/block/xloop%d/xloop%dp1",
		device_number, device_number);
	device_fd = open_device(device_path);
	if (device_fd < 0 || attach_by_fd(device_fd, "test.img", 0U, 0U, 0U, 0U) != 0) {
		tst_res(TBROK, "cannot attach xloop device: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	if (append_path(backing_sysfs, sizeof(backing_sysfs), sysfs, "/backing_file") != 0) {
		tst_res(TBROK, "cannot construct sysfs path: %s", strerror(errno));
		goto cleanup;
	}
	(void)snprintf(sysfs, sizeof(sysfs), "/sys/block/xloop%d/xloop", device_number);
	{
		char attribute[PATH_MAX];
		if (append_path(attribute, sizeof(attribute), sysfs, "/partscan") != 0) {
			tst_res(TBROK, "cannot construct sysfs path: %s", strerror(errno));
			goto cleanup;
		}
		(void)assert_int(attribute, 0);
		if (append_path(attribute, sizeof(attribute), sysfs, "/autoclear") != 0) {
			tst_res(TBROK, "cannot construct sysfs path: %s", strerror(errno));
			goto cleanup;
		}
		(void)assert_int(attribute, 0);
		(void)assert_str(backing_sysfs, expected_backing);
	}
	memset(&set_status, 0, sizeof(set_status));
	set_status.xlo_flags = SET_FLAGS;
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS, &set_status) != 0) {
		tst_res(TFAIL, "XLOOP_SET_STATUS failed: %s", strerror(errno));
		goto cleanup;
	}
	memset(&get_status, 0, sizeof(get_status));
	if (retry_ioctl(device_fd, XLOOP_GET_STATUS, &get_status) != 0) {
		tst_res(TFAIL, "XLOOP_GET_STATUS failed: %s", strerror(errno));
		goto cleanup;
	}
	if ((get_status.xlo_flags & ~GET_FLAGS) == 0)
		tst_res(TPASS, "status flags contain only autoclear and partscan");
	else
		tst_res(TFAIL, "unexpected status flags: %d", get_status.xlo_flags);
	{
		char attribute[PATH_MAX];
		(void)snprintf(attribute, sizeof(attribute), "/sys/block/xloop%d/xloop/partscan", device_number);
		(void)assert_int(attribute, 1);
		(void)snprintf(attribute, sizeof(attribute), "/sys/block/xloop%d/xloop/autoclear", device_number);
		(void)assert_int(attribute, 1);
	}
	if (parted_available != 0) {
		if (retry_access(partition_device, 1) == 0 && retry_access(partition_sysfs, 1) == 0)
			tst_res(TPASS, "partition device and sysfs entries appeared");
		else
			tst_res(TFAIL, "partition device or sysfs entry did not appear");
	}
	memset(&set_status, 0, sizeof(set_status));
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS, &set_status) != 0) {
		tst_res(TFAIL, "failed to clear xloop status flags: %s", strerror(errno));
		goto cleanup;
	}
	memset(&get_status, 0, sizeof(get_status));
	if (retry_ioctl(device_fd, XLOOP_GET_STATUS, &get_status) != 0 ||
		(get_status.xlo_flags & GET_FLAGS) != 0)
		tst_res(TFAIL, "xloop flags did not clear");
	else
		tst_res(TPASS, "autoclear and partscan flags were cleared");
cleanup:
	if (attached != 0)
		(void)detach_by_fd(device_path, device_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	return test_finish();
}
