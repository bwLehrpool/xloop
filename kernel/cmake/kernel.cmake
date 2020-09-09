# SPDX-License-Identifier: GPL-2.0
#
# CMake macros to build and install Linux kernel modules
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# macro to define target for preparing the Kbuild file
macro(add_kernel_build BUILD_SOURCE_TARGET BUILD_SOURCE_FILE)
    get_filename_component(BUILD_SOURCE_FILE_NAME ${BUILD_SOURCE_FILE} NAME)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${BUILD_SOURCE_FILE_NAME}
                       COMMAND ${CMAKE_COMMAND}
                       ARGS -E copy ${BUILD_SOURCE_FILE} ${CMAKE_CURRENT_BINARY_DIR}/${BUILD_SOURCE_FILE_NAME}
		               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		               DEPENDS ${BUILD_SOURCE_FILE}
		               VERBATIM)
    add_custom_target(${BUILD_SOURCE_TARGET} DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${BUILD_SOURCE_FILE_NAME})
endmacro(add_kernel_build)

# macro to define kernel module targets
macro(add_kernel_module MODULE_NAME KERNEL_DIR MODULE_MACRO MODULE_SOURCE_FILES MODULE_HEADER_FILES BUILD_SOURCE_TARGET)
    # copy source files
    foreach(MODULE_SOURCE_FILE ${MODULE_SOURCE_FILES})
	    file(COPY ${MODULE_SOURCE_FILE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    endforeach()
    # copy header files
    foreach(MODULE_HEADER_FILE ${MODULE_HEADER_FILES})
        file(COPY ${MODULE_HEADER_FILE} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
    endforeach()
    # define build command
    set(MODULE_BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} ${MODULE_MACRO}
                                                   -C ${KERNEL_DIR}/build
                                                    M=${CMAKE_CURRENT_BINARY_DIR} modules
                                                    EXTRA_CFLAGS=${KERNEL_C_FLAGS})
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}.ko
                       COMMAND ${MODULE_BUILD_COMMAND}
		               WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		               DEPENDS ${MODULE_SOURCE_FILES} ${MODULE_HEADER_FILES} ${BUILD_SOURCE_TARGET}
		               VERBATIM)
    add_custom_target(${MODULE_NAME} ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}.ko ${ARGV6})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${MODULE_NAME}.ko
            DESTINATION ${KERNEL_DIR}/extra
            PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endmacro(add_kernel_module)