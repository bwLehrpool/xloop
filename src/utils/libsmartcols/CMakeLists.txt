cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils-libsmartcols
        LANGUAGES C)

add_library(libsmartcols STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/buffer.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/calculate.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/cell.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/column.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/grouping.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/init.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/iter.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/line.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/print-api.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/print.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/symbols.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/table.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/version.c
                                ${CMAKE_CURRENT_SOURCE_DIR}/src/walk.c)
target_include_directories(libsmartcols PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(libsmartcols LINK_PUBLIC libcommon xloop-version)
