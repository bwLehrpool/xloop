# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

macro(gen_project_version VERSION_INPUT_FILE VERSION_INPUT_FILE_TEMPLATE VERSION_OUTPUT_FILE GIT_EXECUTABLE REPOSITORY_DIR)
    get_filename_component(VERSION_OUTPUT_FILENAME ${VERSION_OUTPUT_FILE} NAME)
    # command that will trigger a rebuild of version.h every time
    add_custom_command(OUTPUT regenerate-version-file
                       COMMAND ${CMAKE_COMMAND} -E sleep 0
                       COMMENT "Trigger generating ${VERSION_OUTPUT_FILENAME}")

    # call the GenerateVersion.cmake file to generate the version.c file
    add_custom_command(OUTPUT ${VERSION_OUTPUT_FILE}
                       COMMAND ${CMAKE_COMMAND} -D VERSION_MODULE_PATH=${PROJECT_MODULES_DIR}
                                                -D VERSION_INPUT_FILE=${VERSION_INPUT_FILE}
                                                -D VERSION_INPUT_FILE_TEMPLATE=${VERSION_INPUT_FILE_TEMPLATE}
                                                -D VERSION_OUTPUT_FILE=${VERSION_OUTPUT_FILE}
                                                -D VERSION_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                                                -D GIT_EXECUTABLE=${GIT_EXECUTABLE}
                                                -D REPOSITORY_DIR=${REPOSITORY_DIR}
                                                -P ${PROJECT_MODULES_DIR}/GenerateVersion.cmake
                       COMMENT "Generating ${VERSION_OUTPUT_FILENAME}"
                       DEPENDS regenerate-version-file)
    add_custom_target(xloop-generate-version DEPENDS ${VERSION_OUTPUT_FILE})

    # create target to expose project version
    add_library(xloop-version INTERFACE)
    target_include_directories(xloop-version INTERFACE ${PROJECT_INCLUDE_GEN_DIR})
    add_dependencies(xloop-version xloop-generate-version)
endmacro(gen_project_version VERSION_INPUT_FILE VERSION_INPUT_FILE_TEMPLATE VERSION_OUTPUT_FILE)

# macro to get Git version information
macro(get_repository_version REPOSITORY_VERSION VERSION_HEADER_FILE VERSION_BUILD_TYPE GIT_EXECUTABLE REPOSITORY_DIR)
    # check if generated version header from source package is available
    if(EXISTS ${VERSION_HEADER_FILE})
        # get version information from the generated version header of the source package
        file(READ ${VERSION_HEADER_FILE} GIT_VERSION)
        string(REGEX MATCH "\"(([0-9]+:)?[0-9][A-Za-z0-9.+~-]*)\"" GIT_VERSION ${GIT_VERSION})
        set(GIT_VERSION "${CMAKE_MATCH_1}")
    else(EXISTS ${VERSION_HEADER_FILE})
        # set empty Git version information
        set(GIT_VERSION "")

        # get detailed Git version information from Git repository
        execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags HEAD
                        WORKING_DIRECTORY ${REPOSITORY_DIR}
                        OUTPUT_VARIABLE GIT_VERSION_VERBOSE
                        RESULT_VARIABLE GIT_RETURN_CODE
                        ERROR_QUIET
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        # parse version information from repository if Git command succeeds
        if(GIT_RETURN_CODE EQUAL 0)
            # remove the first letter of the version to satisfy packaging rules
            string(REGEX MATCH "([0-9]+:)?[0-9][A-Za-z0-9.+~-]*" GIT_VERSION ${GIT_VERSION_VERBOSE})
        endif(GIT_RETURN_CODE EQUAL 0)

        # overwrite version from Git if version is unknown
        if(GIT_VERSION STREQUAL "")
            # overwrite version information with unkown version 'v0.0'
            set(GIT_VERSION "0.0")

            # print a message in Release build configuration to warn about the unkown version
            if(${VERSION_BUILD_TYPE} MATCHES "Release")
                message(WARNING "The version information from Git tags in this xloop Git repository is missing! Please fetch all Git tags of this repository for a ${VERSION_BUILD_TYPE} build!")
            endif(${VERSION_BUILD_TYPE} MATCHES "Release")
        endif(GIT_VERSION STREQUAL "")

        # get status of Git repository
        execute_process(COMMAND ${GIT_EXECUTABLE} status --porcelain
                        WORKING_DIRECTORY ${REPOSITORY_DIR}
                        OUTPUT_VARIABLE GIT_STATUS
                        RESULT_VARIABLE GIT_RETURN_CODE
                        ERROR_QUIET
                        OUTPUT_STRIP_TRAILING_WHITESPACE)

        # check if Git repository is dirty
        if(GIT_RETURN_CODE EQUAL 0 AND NOT GIT_STATUS STREQUAL "")
            # the Git repository is dirty, thus extend the version information
            set(GIT_VERSION "${GIT_VERSION}-modified")

            # print a message in Release build configuration to warn about the dirty repository
            if(${VERSION_BUILD_TYPE} MATCHES "Release")
                message(WARNING "This xloop Git repository is dirty! Please commit or revert all changes for a ${VERSION_BUILD_TYPE} build!")
            endif(${VERSION_BUILD_TYPE} MATCHES "Release")
        endif(GIT_RETURN_CODE EQUAL 0 AND NOT GIT_STATUS STREQUAL "")
    endif(EXISTS ${VERSION_HEADER_FILE})

    # return version to caller
    set(${REPOSITORY_VERSION} ${GIT_VERSION})
endmacro(get_repository_version)
