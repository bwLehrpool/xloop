/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef XLOOP_TEST_H
#define XLOOP_TEST_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>

#include "uapi_xloop.h"

#define TPASS 0
#define TFAIL 1
#define TCONF 2
#define TBROK 3
#define XLOOP_TEST_RETRIES 30U

static unsigned int xloop_test_failures;
static char xloop_test_tmpdir[PATH_MAX];

static inline void tst_res(int status, const char *format, ...)
{
	va_list args;
	const char *label = status == TPASS ? "PASS" : status == TFAIL ? "FAIL" :
		status == TCONF ? "CONF" : "BROK";
	if (status == TFAIL || status == TBROK)
		xloop_test_failures++;
	(void)fprintf(status == TFAIL || status == TBROK ? stderr : stdout, "%s: ", label);
	va_start(args, format);
	(void)vfprintf(status == TFAIL || status == TBROK ? stderr : stdout, format, args);
	va_end(args);
	(void)fputc('\n', status == TFAIL || status == TBROK ? stderr : stdout);
}

static inline int tmpdir_create(void)
{
	const char template[] = "/tmp/ioctl_xloop_XXXXXX";
	memcpy(xloop_test_tmpdir, template, sizeof(template));
	if (mkdtemp(xloop_test_tmpdir) == NULL || chdir(xloop_test_tmpdir) != 0) {
		tst_res(TBROK, "cannot create test directory: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static inline int append_path(char *destination, size_t capacity, const char *base,
	const char *suffix)
{
	size_t base_length = strlen(base);
	size_t suffix_length = strlen(suffix);
	if (base_length >= capacity || suffix_length >= capacity - base_length) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(destination, base, base_length);
	memcpy(destination + base_length, suffix, suffix_length + 1U);
	return 0;
}

static inline void tmpdir_cleanup(void)
{
	DIR *directory;
	struct dirent *entry;
	if (xloop_test_tmpdir[0] == '\0')
		return;
	if (chdir("/") != 0)
		return;
	directory = opendir(xloop_test_tmpdir);
	if (directory != NULL) {
		while ((entry = readdir(directory)) != NULL) {
			char path[PATH_MAX];
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;
			if (snprintf(path, sizeof(path), "%s/%s", xloop_test_tmpdir, entry->d_name) < (int)sizeof(path))
				(void)unlink(path);
		}
		(void)closedir(directory);
	}
	(void)rmdir(xloop_test_tmpdir);
	xloop_test_tmpdir[0] = '\0';
}

static inline int check_root_and_control(void)
{
	int fd;
	if (geteuid() != 0) {
		tst_res(TCONF, "test requires root privileges");
		return -1;
	}
	fd = open("/dev/xloop-control", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		tst_res(TCONF, "xloop-control is unavailable: %s", strerror(errno));
		return -1;
	}
	(void)close(fd);
	return 0;
}

static inline int find_free_xloopdev(char *path, size_t path_size)
{
	struct stat directory_stat;
	int control_fd = open("/dev/xloop-control", O_RDWR | O_CLOEXEC);
	int number;
	unsigned int attempt;
	if (control_fd < 0)
		return -1;
	number = ioctl(control_fd, XLOOP_CTL_GET_FREE);
	(void)close(control_fd);
	if (number < 0)
		return -1;
	if (stat("/dev/xloop", &directory_stat) == 0 && S_ISDIR(directory_stat.st_mode)) {
		if (snprintf(path, path_size, "/dev/xloop/%d", number) >= (int)path_size)
			return -1;
	} else if (snprintf(path, path_size, "/dev/xloop%d", number) >= (int)path_size) {
		return -1;
	}
	for (attempt = 0U; attempt < XLOOP_TEST_RETRIES; attempt++) {
		int device_fd = open(path, O_RDWR | O_CLOEXEC);
		if (device_fd >= 0) {
			(void)close(device_fd);
			return number;
		}
		if (errno != ENOENT && errno != ENXIO)
			return -1;
		control_fd = open("/dev/xloop-control", O_RDWR | O_CLOEXEC);
		if (control_fd >= 0) {
			(void)ioctl(control_fd, XLOOP_CTL_ADD, number);
			(void)close(control_fd);
		}
		{
			const struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
			(void)nanosleep(&delay, NULL);
		}
	}
	return -1;
}

static inline int test_begin(void)
{
	if (check_root_and_control() != 0)
		return -1;
	if (tmpdir_create() != 0)
		return -1;
	return 0;
}

static inline int test_finish(void)
{
	tmpdir_cleanup();
	return xloop_test_failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}

static inline int open_device(const char *path)
{
	return open(path, O_RDWR | O_CLOEXEC);
}

static inline int retry_ioctl(int fd, unsigned long request, void *argument)
{
	unsigned int attempt;
	for (attempt = 0U; attempt < XLOOP_TEST_RETRIES; attempt++) {
		if (ioctl(fd, request, argument) == 0)
			return 0;
		if (errno != EAGAIN && errno != EINTR)
			return -1;
		{
			const struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
			(void)nanosleep(&delay, NULL);
		}
	}
	errno = EAGAIN;
	return -1;
}

static inline int attach_by_fd(int device_fd, const char *backing_file, uint32_t flags,
		uint64_t offset, uint64_t sizelimit, uint32_t block_size)
{
	struct xloop_config config;
	struct xloop_info64 status;
	int backing_fd = open(backing_file, (flags & XLO_FLAGS_READ_ONLY) != 0U ? O_RDONLY : O_RDWR);
	int result;
	if (backing_fd < 0)
		return -1;
	memset(&config, 0, sizeof(config));
	config.fd = (uint32_t)backing_fd;
	config.block_size = block_size;
	config.info.xlo_offset = offset;
	config.info.xlo_sizelimit = sizelimit;
	config.info.xlo_flags = flags;
	result = retry_ioctl(device_fd, XLOOP_CONFIGURE, &config);
	if (result != 0 && (errno == EINVAL || errno == ENOTTY)) {
		if (retry_ioctl(device_fd, XLOOP_SET_FD, (void *)(uintptr_t)(unsigned int)backing_fd) != 0) {
			(void)close(backing_fd);
			return -1;
		}
		memset(&status, 0, sizeof(status));
		status.xlo_offset = offset;
		status.xlo_sizelimit = sizelimit;
		status.xlo_flags = flags;
		if (retry_ioctl(device_fd, XLOOP_SET_STATUS64, &status) != 0) {
			int saved_errno = errno;
			(void)ioctl(device_fd, XLOOP_CLR_FD);
			(void)close(backing_fd);
			errno = saved_errno;
			return -1;
		}
		result = 0;
	}
	{
		int saved_errno = errno;
		(void)close(backing_fd);
		errno = saved_errno;
	}
	return result;
}

static inline int attach_device(const char *device_path, const char *backing_file, uint32_t flags)
{
	int fd = open_device(device_path);
	if (fd < 0)
		return -1;
	if (attach_by_fd(fd, backing_file, flags, 0U, 0U, 0U) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	return fd;
}

static inline int detach_by_fd(const char *device_path, int device_fd)
{
	int fd = device_fd;
	int close_fd = 0;
	int result;
	if (fd < 0) {
		fd = open_device(device_path);
		if (fd < 0)
			return -1;
		close_fd = 1;
	}
	result = ioctl(fd, XLOOP_CLR_FD);
	if (close_fd != 0)
		(void)close(fd);
	return result;
}

static inline int detach_device(const char *device_path)
{
	return detach_by_fd(device_path, -1);
}

static inline int fill_file(const char *path, size_t size, unsigned char byte)
{
	unsigned char buffer[8192];
	size_t remaining = size;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	memset(buffer, byte, sizeof(buffer));
	while (remaining != 0U) {
		size_t amount = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
		ssize_t written = write(fd, buffer, amount);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			(void)close(fd);
			return -1;
		}
		if (written == 0) {
			(void)close(fd);
			errno = EIO;
			return -1;
		}
		remaining -= (size_t)written;
	}
	return close(fd);
}

static inline int assert_int(const char *path, int64_t expected)
{
	char value[128];
	char *end;
	long long actual;
	FILE *file = fopen(path, "r");
	if (file == NULL || fgets(value, sizeof(value), file) == NULL) {
		if (file != NULL)
			(void)fclose(file);
		tst_res(TFAIL, "cannot read integer from %s", path);
		return -1;
	}
	(void)fclose(file);
	errno = 0;
	actual = strtoll(value, &end, 10);
	if (errno != 0 || end == value || actual != expected) {
		tst_res(TFAIL, "%s: expected %" PRId64 ", got %s", path, expected, value);
		return -1;
	}
	tst_res(TPASS, "%s is %" PRId64, path, expected);
	return 0;
}

static inline int assert_str(const char *path, const char *expected)
{
	char value[PATH_MAX];
	FILE *file = fopen(path, "r");
	size_t length;
	if (file == NULL || fgets(value, sizeof(value), file) == NULL) {
		if (file != NULL)
			(void)fclose(file);
		tst_res(TFAIL, "cannot read string from %s", path);
		return -1;
	}
	(void)fclose(file);
	length = strlen(value);
	while (length != 0U && (value[length - 1U] == '\n' || value[length - 1U] == '\r'))
		value[--length] = '\0';
	if (strcmp(value, expected) != 0) {
		tst_res(TFAIL, "%s: expected '%s', got '%s'", path, expected, value);
		return -1;
	}
	tst_res(TPASS, "%s matches '%s'", path, expected);
	return 0;
}

static inline int retry_access(const char *path, int should_exist)
{
	unsigned int attempt;
	for (attempt = 0U; attempt < XLOOP_TEST_RETRIES; attempt++) {
		int result = access(path, F_OK);
		if ((result == 0) == (should_exist != 0))
			return 0;
		{
			const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
			(void)nanosleep(&delay, NULL);
		}
	}
	errno = ENOENT;
	return -1;
}

static inline int run_cmd(char *const arguments[])
{
	pid_t child = fork();
	int status;
	if (child < 0)
		return -1;
	if (child == 0) {
		execvp(arguments[0], arguments);
		_exit(errno == ENOENT ? 127 : 126);
	}
	if (waitpid(child, &status, 0) < 0)
		return -1;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 128;
}

static inline int fs_type(const char *path, long *type)
{
	struct statfs info;
	if (statfs(path, &info) != 0)
		return -1;
	*type = (long)info.f_type;
	return 0;
}

static inline int find_backing_device(const char *path, char *device_path, size_t path_size)
{
	struct stat info;
	char uevent_path[PATH_MAX];
	char line[PATH_MAX];
	FILE *file;
	if (stat(path, &info) != 0 ||
		snprintf(uevent_path, sizeof(uevent_path), "/sys/dev/block/%u:%u/uevent",
			(unsigned int)major(info.st_dev), (unsigned int)minor(info.st_dev)) >= (int)sizeof(uevent_path))
		return -1;
	file = fopen(uevent_path, "r");
	if (file == NULL)
		return -1;
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strncmp(line, "DEVNAME=", 8U) == 0) {
			char *newline = strchr(line + 8, '\n');
			if (newline != NULL)
				*newline = '\0';
			if (snprintf(device_path, path_size, "/dev/%s", line + 8) >= (int)path_size) {
				(void)fclose(file);
				return -1;
			}
			(void)fclose(file);
			return 0;
		}
	}
	(void)fclose(file);
	return -1;
}

#endif
