# SPDX-License-Identifier: GPL-2.0
#
# CMake macros to get version numbers
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# macro to get Linux kernel version
macro(get_kernel_version LINUX_KERNEL_VERSION)
    execute_process(COMMAND uname -r 
                    OUTPUT_VARIABLE UNAME_RESULT
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "[0-9]+.[0-9]+.[0-9]+" LINUX_KERNEL_VERSION ${UNAME_RESULT})
endmacro(get_kernel_version)

# macro to get short hash of latest commit
macro(get_repository_version REPOSITORY_VERSION)
    execute_process(COMMAND git rev-parse --short HEAD
                    OUTPUT_VARIABLE SHORT_HASH_RESULT
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "[0-9a-fA-F]+" REPOSITORY_VERSION ${SHORT_HASH_RESULT})
endmacro(get_repository_version)
