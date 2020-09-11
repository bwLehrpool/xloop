cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/old)

# configure configuration config.h and add it to the include directories
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(lib)
add_subdirectory(testcases/kernel/syscalls/ioctl)