cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-kernel-modules
        LANGUAGES C)

# include macros to define Linux kernel build targets
include(Kernel)

# set C flags for a Linux kernel module
set(KERNEL_C_FLAGS "-DCONFIG_BLK_DEV_XLOOP_MIN_COUNT=${BLK_DEV_XLOOP_MIN_COUNT} -DXLOOP_MAJOR=${XLOOP_MAJOR} -DXLOOP_CTRL_MINOR=${XLOOP_CTRL_MINOR} -I ${PROJECT_INCLUDE_GEN_DIR}"
    CACHE STRING "C flags to be used for building the kernel module")
# set C flags for the debug mode of a Linux kernel module
set(KERNEL_C_FLAGS_DEBUG "-g -DDEBUG"
    CACHE STRING "Additional C flags to be used for building the kernel module in debug mode")

# append include directories to the C flags
get_property(KERNEL_INCLUDE_DIRS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(KERNEL_INCLUDE_DIR ${KERNEL_INCLUDE_DIRS})
    set(KERNEL_C_FLAGS "${KERNEL_C_FLAGS} -I ${KERNEL_INCLUDE_DIR}")
endforeach(KERNEL_INCLUDE_DIR ${KERNEL_INCLUDE_DIRS})

# append debug C flags if debug mode is enabled
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(KERNEL_C_FLAGS "${KERNEL_C_FLAGS} ${KERNEL_C_FLAGS_DEBUG}")
endif(CMAKE_BUILD_TYPE MATCHES "Debug")

# xloop main Linux kernel module
set(KERNEL_MODULE_XLOOP_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt.c
                                     ${CMAKE_CURRENT_SOURCE_DIR}/xloop_main.c)
set(KERNEL_MODULE_XLOOP_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/xloop_main.h
                                     ${CMAKE_CURRENT_SOURCE_DIR}/uapi_xloop.h)
add_kernel_module(xloop "${KERNEL_BUILD_DIR}"
                        "${KERNEL_INSTALL_DIR}"
                        "CONFIG_BLK_DEV_XLOOP=m"
                        "${KERNEL_MODULE_XLOOP_SOURCE_FILES}"
                        "${KERNEL_MODULE_XLOOP_HEADER_FILES}"
                        ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild)
# add dependency to generate project version header before xloop.ko is built
add_dependencies(xloop xloop-generate-version)

# xloop_file_fmt_raw Linux kernel module
set(KERNEL_MODULE_XLOOP_RAW_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_raw.c)
set(KERNEL_MODULE_XLOOP_RAW_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt.h
                                         ${CMAKE_CURRENT_SOURCE_DIR}/xloop_main.h
                                         ${CMAKE_CURRENT_SOURCE_DIR}/uapi_xloop.h)
add_kernel_module(xloop_file_fmt_raw "${KERNEL_BUILD_DIR}"
                                     "${KERNEL_INSTALL_DIR}"
                                     "CONFIG_BLK_DEV_XLOOP_FILE_FMT_RAW=m"
                                     "${KERNEL_MODULE_XLOOP_RAW_SOURCE_FILES}"
                                     "${KERNEL_MODULE_XLOOP_RAW_HEADER_FILES}"
                                     ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
                                     xloop)
# add dependency to generate project version header before xloop_file_fmt_raw.ko is built
add_dependencies(xloop_file_fmt_raw xloop-generate-version)

# xloop_file_fmt_qcow Linux kernel module
set(KERNEL_MODULE_XLOOP_QCOW_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_cache.c
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_cluster.c
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_main.c)
set(KERNEL_MODULE_XLOOP_QCOW_HEADER_FILES ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_cache.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_cluster.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt_qcow_main.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_file_fmt.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/xloop_main.h
                                          ${CMAKE_CURRENT_SOURCE_DIR}/uapi_xloop.h)
add_kernel_module(xloop_file_fmt_qcow "${KERNEL_BUILD_DIR}"
                                      "${KERNEL_INSTALL_DIR}"
                                      "CONFIG_BLK_DEV_XLOOP_FILE_FMT_QCOW=m"
                                      "${KERNEL_MODULE_XLOOP_QCOW_SOURCE_FILES}"
                                      "${KERNEL_MODULE_XLOOP_QCOW_HEADER_FILES}"
                                      ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild
                                      xloop)
# add dependency to generate project version header before xloop_file_fmt_qcow.ko is built
add_dependencies(xloop_file_fmt_qcow xloop-generate-version)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    add_subdirectory(tests)
endif(CMAKE_BUILD_TYPE MATCHES "Debug")

# install udev rules for xloop devices exposed by the xloop kernel module
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/udev/50-xloop.rules
        DESTINATION /lib/udev/rules.d
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        COMPONENT kernel)
