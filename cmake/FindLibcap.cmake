# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# Use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
find_package(PkgConfig QUIET)
pkg_check_modules(PKG_Libcap QUIET libcap)

set(Libcap_COMPILE_OPTIONS ${PKG_Libcap_CFLAGS_OTHER})
set(Libcap_VERSION ${PKG_Libcap_VERSION})

find_path(Libcap_INCLUDE_DIR
          NAMES sys/capability.h
          HINTS ${PKG_Libcap_INCLUDE_DIRS})
find_library(Libcap_LIBRARY
             NAMES cap
             HINTS ${PKG_Libcap_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libcap
                                  FOUND_VAR Libcap_FOUND
                                  REQUIRED_VARS Libcap_LIBRARY
                                                Libcap_INCLUDE_DIR
                                  VERSION_VAR Libcap_VERSION
                                  FAIL_MESSAGE "Library 'cap' is not available! Please install this required library!")

if(Libcap_FOUND AND NOT TARGET Libcap::Libcap)
    add_library(Libcap::Libcap UNKNOWN IMPORTED)
    set_target_properties(Libcap::Libcap PROPERTIES
                          IMPORTED_LOCATION "${Libcap_LIBRARY}"
                          INTERFACE_COMPILE_OPTIONS "${Libcap_COMPILE_OPTIONS}"
                          INTERFACE_INCLUDE_DIRECTORIES "${Libcap_INCLUDE_DIR}")
endif(Libcap_FOUND AND NOT TARGET Libcap::Libcap)

mark_as_advanced(Libcap_LIBRARY Libcap_INCLUDE_DIR)

if(Libcap_FOUND)
    set(Libcap_LIBRARIES ${Libcap_LIBRARY})
    set(Libcap_INCLUDE_DIRS ${Libcap_INCLUDE_DIR})
endif(Libcap_FOUND)

# print found information
message(VERBOSE "Libcap_FOUND: ${Libcap_FOUND}")
message(VERBOSE "Libcap_VERSION: ${Libcap_VERSION}")
message(VERBOSE "Libcap_INCLUDE_DIRS: ${Libcap_INCLUDE_DIRS}")
message(VERBOSE "Libcap_COMPILE_OPTIONS: ${Libcap_COMPILE_OPTIONS}")
message(VERBOSE "Libcap_LIBRARIES: ${Libcap_LIBRARIES}")
