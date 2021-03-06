# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# set current build type of the project
set(XLOOP_BUILD ${BUILD_TYPE})

# write dnbd3 build type into a new C source file based on the specified build file template
configure_file(${BUILD_INPUT_FILE_TEMPLATE} ${BUILD_OUTPUT_FILE})
