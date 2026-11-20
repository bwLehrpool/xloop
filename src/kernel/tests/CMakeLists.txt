cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test
        LANGUAGES C)

# include parent directory for the xloop UAPI header
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

add_subdirectory(testcases/kernel/syscalls/ioctl)
