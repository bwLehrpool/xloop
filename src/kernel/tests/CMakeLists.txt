cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test
        LANGUAGES C)

# requires 'cap' library in tests for include header <sys/capability.h>
find_package(Libcap REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/old)

# include parent directory for the xloop's uapi
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

add_subdirectory(lib)
add_subdirectory(testcases/kernel/syscalls/ioctl)
