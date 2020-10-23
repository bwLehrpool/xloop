cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils)

# include global headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${PROJECT_INCLUDE_GEN_DIR})

# configure configuration config.h and add it to each source file
add_compile_options(-include ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

# add xloop specific compile options
add_definitions(-DCONFIG_BLK_DEV_XLOOP_MIN_COUNT=${BLK_DEV_XLOOP_MIN_COUNT} -DXLOOP_MAJOR=${XLOOP_MAJOR})

add_subdirectory(lib)
add_subdirectory(libsmartcols)
add_subdirectory(sys-utils)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/bash-completion/xlosetup
        DESTINATION share/bash-completion/completions
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
        COMPONENT main)
