cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils-sys-utils)

# add xlosetup executable
add_executable(xlosetup ${CMAKE_CURRENT_SOURCE_DIR}/losetup.c)
target_link_libraries(xlosetup LINK_PUBLIC libcommon libsmartcols)
target_include_directories(xlosetup PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../lib ${CMAKE_CURRENT_SOURCE_DIR}/../libsmartcols)
