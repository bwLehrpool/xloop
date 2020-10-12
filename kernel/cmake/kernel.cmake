# SPDX-License-Identifier: GPL-2.0
#
# CMake macros to build and install Linux kernel modules
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# macro to define kernel module targets
macro(add_kernel_module MODULE_NAME KERNEL_BUILD_DIR KERNEL_INSTALL_DIR MODULE_MACRO MODULE_SOURCE_FILES MODULE_HEADER_FILES BUILD_SOURCE_FILE)
    # copy build source file
    file(COPY ${BUILD_SOURCE_FILE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME})
    # copy source files
    foreach(MODULE_SOURCE_FILE ${MODULE_SOURCE_FILES})
	    file(COPY ${MODULE_SOURCE_FILE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME})
    endforeach()
    # copy header files
    foreach(MODULE_HEADER_FILE ${MODULE_HEADER_FILES})
        file(COPY ${MODULE_HEADER_FILE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME})
    endforeach()
    # check if module depends on another module
    if(NOT ${ARGV7} STREQUAL "")
        set(MODULE_EXTRA_SYMBOLS ${CMAKE_CURRENT_BINARY_DIR}/${ARGV7}/Module.symvers)
    endif()
    # define build command
    set(MODULE_BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} ${MODULE_MACRO}
                                                   -C ${KERNEL_BUILD_DIR}
                                                    M=${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME} modules
                                                    EXTRA_CFLAGS=${KERNEL_C_FLAGS}
                                                    KBUILD_EXTRA_SYMBOLS=${MODULE_EXTRA_SYMBOLS})
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}/${MODULE_NAME}.ko
                       COMMAND ${MODULE_BUILD_COMMAND}
		               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}
                       DEPENDS ${MODULE_SOURCE_FILES} ${MODULE_HEADER_FILES} ${BUILD_SOURCE_FILE}
		               VERBATIM)
    add_custom_target(${MODULE_NAME} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}/${MODULE_NAME}.ko ${ARGV7})
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}/${MODULE_NAME}.ko
            DESTINATION ${KERNEL_INSTALL_DIR}
            PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
            COMPONENT main)
endmacro(add_kernel_module)
