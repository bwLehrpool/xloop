cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils-sys-utils
        LANGUAGES C)

# add xlosetup executable
add_executable(xlosetup ${CMAKE_CURRENT_SOURCE_DIR}/xlosetup.c)
target_link_libraries(xlosetup libcommon libsmartcols xloop-version)
install(TARGETS xlosetup DESTINATION bin
        COMPONENT main)

# install xlosetup man page
# NOTE: installation is done via a directory install with file matching pattern to support CPackRPM's automatic compression of man pages
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
        DESTINATION share/man/man8
        COMPONENT main
        USE_SOURCE_PERMISSIONS
        FILES_MATCHING PATTERN *.8*)
