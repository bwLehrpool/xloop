# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2020 Manuel Bentele <development@manuel-bentele.de>
#

# Use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
find_package(PkgConfig QUIET)
pkg_check_modules(PKG_Libncurses QUIET libncurses)

set(Libncurses_COMPILE_OPTIONS ${PKG_Libncurses_CFLAGS_OTHER})
set(Libncurses_VERSION ${PKG_Libncurses_VERSION})

find_path(Libncurses_INCLUDE_DIR
          NAMES ncursesw/ncurses.h
                ncurses/ncurses.h
                ncurses.h
                ncursesw/term.h
                ncurses/term.h
                term.h
          HINTS ${PKG_Libncurses_INCLUDE_DIRS})
find_library(Libncurses_LIBRARY
             NAMES ncurses
             HINTS ${PKG_Libncurses_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libncurses
                                  FOUND_VAR Libncurses_FOUND
                                  REQUIRED_VARS Libncurses_LIBRARY
                                                Libncurses_INCLUDE_DIR
                                  VERSION_VAR Libncurses_VERSION
                                  FAIL_MESSAGE "Library 'ncurses' is not available! Please install this required library!")

if(Libncurses_FOUND AND NOT TARGET Libncurses::Libncurses)
    add_library(Libncurses::Libncurses UNKNOWN IMPORTED)
    set_target_properties(Libncurses::Libncurses PROPERTIES
                          IMPORTED_LOCATION "${Libncurses_LIBRARY}"
                          INTERFACE_COMPILE_OPTIONS "${Libncurses_COMPILE_OPTIONS}"
                          INTERFACE_INCLUDE_DIRECTORIES "${Libncurses_INCLUDE_DIR}")
endif(Libncurses_FOUND AND NOT TARGET Libncurses::Libncurses)

mark_as_advanced(Libncurses_LIBRARY Libncurses_INCLUDE_DIR)

if(Libncurses_FOUND)
    set(Libncurses_LIBRARIES ${Libncurses_LIBRARY})
    set(Libncurses_INCLUDE_DIRS ${Libncurses_INCLUDE_DIR})
endif(Libncurses_FOUND)

# print found information
if(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
    message(VERBOSE "Libncurses_FOUND: ${Libncurses_FOUND}")
    message(VERBOSE "Libncurses_VERSION: ${Libncurses_VERSION}")
    message(VERBOSE "Libncurses_INCLUDE_DIRS: ${Libncurses_INCLUDE_DIRS}")
    message(VERBOSE "Libncurses_COMPILE_OPTIONS: ${Libncurses_COMPILE_OPTIONS}")
    message(VERBOSE "Libncurses_LIBRARIES: ${Libncurses_LIBRARIES}")
endif(${CMAKE_VERSION} VERSION_GREATER "3.15.0")
