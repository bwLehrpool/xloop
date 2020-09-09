cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils)

# include global headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# add include of config.h to each source file
add_compile_options(-include ${CMAKE_CURRENT_SOURCE_DIR}/config.h)

add_subdirectory(lib)
add_subdirectory(libsmartcols)
add_subdirectory(sys-utils)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/bash-completion/losetup
        DESTINATION /usr/share/bash-completion/completions
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)