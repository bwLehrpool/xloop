cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils-sys-utils)

# add xlosetup executable
add_executable(xlosetup ${CMAKE_CURRENT_SOURCE_DIR}/losetup.c)
target_link_libraries(xlosetup LINK_PUBLIC libcommon libsmartcols)
target_include_directories(xlosetup PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../lib ${CMAKE_CURRENT_SOURCE_DIR}/../libsmartcols)
install(TARGETS xlosetup DESTINATION bin)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/losetup.8
        DESTINATION /usr/share/man/man8
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)