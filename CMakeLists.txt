cmake_minimum_required(VERSION 3.10)

# include CMake macros
set (CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(version)

# define root CMake project
project(xloop
        DESCRIPTION "xloop Linux kernel modules and utility"
        LANGUAGES C)

# define project specific settings
set(BLK_DEV_XLOOP_MIN_COUNT 8
               CACHE STRING "Number of xloop devices to pre-create at init time")
set(XLOOP_MAJOR 120
   CACHE STRING "Major number for xloop devices")

# print configured settings
message(STATUS "Number of xloop devices to pre-create at init time is " ${BLK_DEV_XLOOP_MIN_COUNT})
message(STATUS "Major number for xloop devices is " ${XLOOP_MAJOR})

# set supported build configurations
set(CMAKE_CONFIGURATION_TYPES Debug Release)

# set compilation in debug mode as default configuration
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
    message(STATUS "Build type is not set. Defaulting to ${CMAKE_BUILD_TYPE} build!")
endif()

# get versions to define project version
get_kernel_version(LINUX_KERNEL_VERSION)
get_repository_version(REPOSITORY_VERSION)
set(VERSION ${LINUX_KERNEL_VERSION}-${REPOSITORY_VERSION})

# define packaging if Release build is enabled
if(${CMAKE_BUILD_TYPE} MATCHES Release)
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_SOURCE_GENERATOR "TGZ;ZIP")
    set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
    set(CPACK_MONOLITHIC_INSTALL True)
    set(CPACK_SOURCE_IGNORE_FILES "/build/;/.git/;.gitignore$;.*~")
    set(CPACK_PACKAGE_VERSION ${VERSION})
    set(CPACK_PACKAGE_SECTION admin)
    set(CPACK_PACKAGE_VENDOR "University of Freiburg")
    set(CPACK_PACKAGE_CONTACT "Christian Rößler <christian.roessler@rz.uni-freiburg.de>")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://git.openslx.org/openslx-ng/xloop.git/")
    set(CPACK_PACKAGE_CHECKSUM SHA256)
    set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CMAKE_SYSTEM_PROCESSOR})
    set(CPACK_SOURCE_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_source)
    set(CPACK_STRIP_FILES True)
    set(CPACK_PACKAGE_RELOCATABLE False)
    set(CPACK_SET_DESTDIR True)
    set(CMAKE_INSTALL_PREFIX "/usr")
    set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
    # set DEB generator specific packaging options
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc-bin")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst "depmod -a\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm "depmod -a\n")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst
                                           ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm)
    # set RPM generator specific packaging options
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/lib"
                                                      "/lib/modules"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}"
                                                      "/lib/modules/${CMAKE_SYSTEM_VERSION}/extra"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/bash-completion"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/bash-completion/completions"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/man"
                                                      "${CPACK_PACKAGING_INSTALL_PREFIX}/share/man/man8")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post "depmod -a\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun "depmod -a\n")
    set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/post)
    set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE ${CMAKE_CURRENT_BINARY_DIR}/package/rpm/postun)
    # include CPack functionality
    include(CPack)
endif()

# add subprojects
add_subdirectory(kernel)
add_subdirectory(utils)

# print version information
message(STATUS "Configured ${CMAKE_PROJECT_NAME} in version ${VERSION}")
