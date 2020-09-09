cmake_minimum_required(VERSION 3.12)

# set the project name
project(xloop-kernel)

set (CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(kernel)

# set Linux kernel directory
set(KERNEL_DIR "/lib/modules/${CMAKE_SYSTEM_VERSION}"
    CACHE PATH "Path to kernel sources to compile against")

# define xloop device specific options
set(BLK_DEV_XLOOP_MIN_COUNT 8
               CACHE STRING "Number of xloop devices to pre-create at init time")
set(XLOOP_MAJOR 120
   CACHE STRING "Major number for xloop devices")

# print configured settings
message(STATUS "Kernel module path is " ${KERNEL_DIR})
message(STATUS "Number of xloop devices to pre-create at init time is " ${BLK_DEV_XLOOP_MIN_COUNT})
message(STATUS "Major number for xloop devices is " ${XLOOP_MAJOR})

# set C flags for a Linux kernel module
set(KERNEL_C_FLAGS "-DCONFIG_BLK_DEV_XLOOP_MIN_COUNT=${BLK_DEV_XLOOP_MIN_COUNT} -DXLOOP_MAJOR=${XLOOP_MAJOR}"
      CACHE STRING "C flags to be used for building the kernel module")
# set C flags for the debug mode of a Linux kernel module
set(KERNEL_C_FLAGS_DEBUG "-g -DDEBUG"
            CACHE STRING "Additional C flags to be used for building the kernel module in debug mode")

# append debug C flags if debug mode is enabled
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(KERNEL_C_FLAGS "${KERNEL_C_FLAGS} ${KERNEL_C_FLAGS_DEBUG}")
endif(CMAKE_BUILD_TYPE MATCHES Debug)

# preparation of the Kbuild file
add_kernel_build(prepare ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild)

# xloop main Linux kernel module
set(KERNEL_MODULE_XLOOP_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/loop_main.c)
set(KERNEL_MODULE_XLOOP_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/loop_main.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/uapi)
add_kernel_module(xloop "${KERNEL_DIR}"
                        "CONFIG_BLK_DEV_XLOOP=m"
                        "${KERNEL_MODULE_XLOOP_SOURCE_FILES}"
                        "${KERNEL_MODULE_XLOOP_HEADER_FILES}"
                        ${CMAKE_CURRENT_BINARY_DIR}/Kbuild)

# xloop_file_fmt_raw Linux kernel module
set(KERNEL_MODULE_XLOOP_RAW_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_raw.c)
set(KERNEL_MODULE_XLOOP_RAW_HEADER_FILES )
add_kernel_module(loop_file_fmt_raw "${KERNEL_DIR}"
                                     "CONFIG_BLK_DEV_XLOOP_FILE_FMT_RAW=m"
                                     "${KERNEL_MODULE_XLOOP_RAW_SOURCE_FILES}"
                                     "${KERNEL_MODULE_XLOOP_RAW_HEADER_FILES}"
                                     ${CMAKE_CURRENT_BINARY_DIR}/Kbuild
                                     xloop)

# xloop_file_fmt_qcow Linux kernel module
set(KERNEL_MODULE_XLOOP_QCOW_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_cache.c
                                          ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_cluster.c
                                          ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_main.c)
set(KERNEL_MODULE_XLOOP_QCOW_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_cache.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_cluster.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/loop_file_fmt_qcow_main.h)
add_kernel_module(loop_file_fmt_qcow "${KERNEL_DIR}"
                                      "CONFIG_BLK_DEV_XLOOP_FILE_FMT_QCOW=m"
                                      "${KERNEL_MODULE_XLOOP_QCOW_SOURCE_FILES}"
                                      "${KERNEL_MODULE_XLOOP_QCOW_HEADER_FILES}"
                                      ${CMAKE_CURRENT_BINARY_DIR}/Kbuild
                                      xloop)
