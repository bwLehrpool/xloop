cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# define packaging
if(NOT CMAKE_BUILD_TYPE MATCHES Debug)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_SOURCE_GENERATOR "TGZ")
    set(CPACK_IGNORE_FILES "*.gitignore")
    set(CPACK_PACKAGE_NAME "xloop")
    set(CPACK_PACKAGE_DESCRIPTION "xloop Kernel modules and utility")
    set(CPACK_PACKAGE_VERSION_MAJOR 0)
    set(CPACK_PACKAGE_VERSION_MINOR 1)
    set(CPACK_PACKAGE_SECTION admin)
    set(CPACK_PACKAGE_VENDOR "University of Freiburg")
    set(CPACK_PACKAGE_CONTACT "Christian Rößler <christian.roessler@rz.uni-freiburg.de>")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://git.openslx.org/openslx-ng/xloop.git/")
    set(CPACK_PACKAGE_CHECKSUM SHA256)
    set(CPACK_STRIP_FILES TRUE)
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst "depmod -a\n")
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm "depmod -a\n")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postinst
                                           ${CMAKE_CURRENT_BINARY_DIR}/package/deb/postrm)
    include(CPack)
endif()

# add subprojects
add_subdirectory(kernel)
add_subdirectory(utils)
