cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils
        LANGUAGES C)

# include project and xloop UAPI headers
include_directories(${PROJECT_INCLUDE_GEN_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../kernel)

# add xloop specific compile options
add_definitions(-DCONFIG_BLK_DEV_XLOOP_MIN_COUNT=${BLK_DEV_XLOOP_MIN_COUNT} -DXLOOP_MAJOR=${XLOOP_MAJOR})

add_subdirectory(sys-utils)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/bash-completion/xlosetup
        DESTINATION share/bash-completion/completions
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        COMPONENT main)
