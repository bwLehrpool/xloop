cmake_minimum_required(VERSION 3.10)

# include CMake macros
set(PROJECT_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
					  ${PROJECT_MODULES_DIR})

# define root CMake project
project(xloop
        DESCRIPTION "xloop Linux kernel modules and utility"
        LANGUAGES C)

# check for system before all other stuff is configured
if(NOT UNIX OR NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    # abort build of the xloop Linux kernel modules on a system other than Linux, eg. FreeBSD
    message(FATAL_ERROR "Detected non-Linux system: Abort build of the xloop Linux kernel modules and utility")
endif(NOT UNIX OR NOT CMAKE_SYSTEM_NAME MATCHES "Linux")

# set supported build configurations
set(CMAKE_CONFIGURATION_TYPES Debug Release)

# set compilation in debug mode as default configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    message(STATUS "Build type is not set. Defaulting to ${CMAKE_BUILD_TYPE} build!")
endif(NOT CMAKE_BUILD_TYPE)

# include project version and build type related macros
include(Version)
include(Build)

# search for required packages
find_package(Git REQUIRED)
find_package(Libcap REQUIRED)
find_package(Libncurses REQUIRED)
find_package(KernelHeaders REQUIRED)

# set linux kernel modules specific default settings
set(BLK_DEV_XLOOP_MIN_COUNT 8
    CACHE STRING "Number of xloop devices to pre-create at init time")
set(XLOOP_MAJOR 120
    CACHE STRING "Major number for xloop devices")
set(XLOOP_CTRL_MINOR 15
    CACHE STRING "Minor number for the xloop-control device")

# print configured settings
message(STATUS "Path to Linux kernel modules to compile against is " ${KERNEL_BUILD_DIR})
message(STATUS "Path to install Linux kernel modules is " ${KERNEL_INSTALL_DIR})
message(STATUS "Number of xloop devices to pre-create at init time is " ${BLK_DEV_XLOOP_MIN_COUNT})
message(STATUS "Major number for xloop devices is " ${XLOOP_MAJOR})
message(STATUS "Minor number for the xloop-control device is " ${XLOOP_CTRL_MINOR})

# set include directories
set(PROJECT_GEN_DIR ${CMAKE_BINARY_DIR}/generated)
set(PROJECT_INCLUDE_DIR_PREFIX inc)
set(PROJECT_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/${PROJECT_INCLUDE_DIR_PREFIX})
set(PROJECT_INCLUDE_GEN_DIR ${PROJECT_GEN_DIR}/${PROJECT_INCLUDE_DIR_PREFIX})
include_directories(${PROJECT_INCLUDE_DIR})

# generate project version C header file from template
# exposes xloop-generate-version and xloop-version target
set(INCLUDE_VERSION_HEADER ${PROJECT_INCLUDE_DIR}/xloop/version.h)
set(INCLUDE_VERSION_HEADER_TEMPLATE ${PROJECT_INCLUDE_DIR}/xloop/version.h.in)
set(INCLUDE_VERSION_HEADER_GENERATE ${PROJECT_INCLUDE_GEN_DIR}/xloop/version.h)
set(INCLUDE_VERSION_HEADER_GENERATE_PREFIX ${PROJECT_INCLUDE_DIR_PREFIX}/xloop)
gen_project_version(${INCLUDE_VERSION_HEADER} ${INCLUDE_VERSION_HEADER_TEMPLATE} ${INCLUDE_VERSION_HEADER_GENERATE})

# generate project build type C header file from template
# exposes xloop-generate-build and xloop-build target
set(INCLUDE_BUILD_HEADER_TEMPLATE ${PROJECT_INCLUDE_DIR}/xloop/build.h.in)
set(INCLUDE_BUILD_HEADER_GENERATE ${PROJECT_INCLUDE_GEN_DIR}/xloop/build.h)
gen_build_type(${INCLUDE_BUILD_HEADER_TEMPLATE} ${INCLUDE_BUILD_HEADER_GENERATE})

# enable all error warnings in Debug build configuration
set(CMAKE_C_FLAGS_DEBUG "-Wall -Wextra -Wpedantic -Wconversion -Wformat -Wformat-security -Werror=format-security")
set(CMAKE_C_FLAGS_RELEASE "-Wno-error")

# set compilation optimization
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -Og -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")

# define packaging if Release build is enabled
if(CMAKE_BUILD_TYPE MATCHES "Release")
    # get version source package or Git repository
    get_repository_version(REPOSITORY_VERSION ${INCLUDE_VERSION_HEADER} ${CMAKE_BUILD_TYPE})

    # define project version
    if(KernelHeaders_VERSION)
        set(REPOSITORY_VERSION_FULL ${REPOSITORY_VERSION}-${KernelHeaders_VERSION})
    else(KernelHeaders_VERSION)
        set(REPOSITORY_VERSION_FULL ${REPOSITORY_VERSION})
    endif(KernelHeaders_VERSION)

    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
    set(CPACK_MONOLITHIC_INSTALL True)
    set(CPACK_PACKAGE_VERSION ${REPOSITORY_VERSION})
    set(CPACK_PACKAGE_VERSION_FULL ${REPOSITORY_VERSION_FULL})
    set(CPACK_PACKAGE_SECTION admin)
    set(CPACK_PACKAGE_VENDOR "University of Freiburg")
    set(CPACK_PACKAGE_CONTACT "Christian Rößler <christian.roessler@rz.uni-freiburg.de>")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://git.openslx.org/openslx-ng/xloop.git/")
    set(CPACK_PACKAGE_CHECKSUM SHA256)
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${REPOSITORY_VERSION_FULL}_${CMAKE_SYSTEM_PROCESSOR})
    set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_source)
    set(CPACK_STRIP_FILES True)
    set(CPACK_PACKAGE_RELOCATABLE False)
    set(CPACK_SET_DESTDIR True)
    set(CMAKE_INSTALL_PREFIX "/usr")
    set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/COPYING)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

    # set DEB generator specific packaging options
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6")
    if(XLOOP_KERNEL_MODULES)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst "depmod -a\nudevadm control --reload-rules\n")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm "depmod -a\nudevadm control --reload-rules\n")
        set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst
                                               ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm)
    endif(XLOOP_KERNEL_MODULES)

    # set RPM generator specific packaging options
    set(CPACK_RPM_PACKAGE_REQUIRES "glibc")
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/lib"
                                                      "/lib/modules"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}/extra"
                                                      "/lib/udev"
                                                      "/lib/udev/rules.d"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/bash-completion"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/bash-completion/completions"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/man"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/man/man8")
    if(XLOOP_KERNEL_MODULES)
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post "depmod -a\nudevadm control --reload-rules\n")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun "depmod -a\nudevadm control --reload-rules\n")
        set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post)
        set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun)
    endif(XLOOP_KERNEL_MODULES)

    # configure source packaging
    set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
    set(CPACK_SOURCE_INSTALLED_DIRECTORIES "${CMAKE_SOURCE_DIR}" "/"
                                           "${PROJECT_GEN_DIR}" "/")
    set(CPACK_SOURCE_IGNORE_FILES "/build/;/.git/;.gitignore$;.*~;version.h.in$")

    # generate install script for CPack to install generated files
    configure_file(${PROJECT_MODULES_DIR}/InstallVersionFile.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/package/InstallVersionFile.cmake)

    # set CPack install script
    set(CPACK_INSTALL_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/package/InstallVersionFile.cmake)

    # include CPack functionality
    include(CPack)

    # create custom target to build package source
    add_custom_target(source
                      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target package_source
                      DEPENDS xloop-generate-version
                      VERBATIM
                      USES_TERMINAL)
endif(CMAKE_BUILD_TYPE MATCHES "Release")

# add all xloop related projects from the source code directory
add_subdirectory(src)
