cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test-ioctl_xloop
        LANGUAGES C)

# test ioctl_xloop01
add_executable(ioctl_xloop01 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop01.c)
target_link_libraries(ioctl_xloop01 libltp)
install(TARGETS ioctl_xloop01 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop02
add_executable(ioctl_xloop02 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop02.c)
target_link_libraries(ioctl_xloop02 libltp)
install(TARGETS ioctl_xloop02 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop03
add_executable(ioctl_xloop03 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop03.c)
target_link_libraries(ioctl_xloop03 libltp)
install(TARGETS ioctl_xloop03 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop04
add_executable(ioctl_xloop04 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop04.c)
target_link_libraries(ioctl_xloop04 libltp)
install(TARGETS ioctl_xloop04 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop05
add_executable(ioctl_xloop05 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop05.c)
target_link_libraries(ioctl_xloop05 libltp)
install(TARGETS ioctl_xloop05 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop06
add_executable(ioctl_xloop06 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop06.c)
target_link_libraries(ioctl_xloop06 libltp)
install(TARGETS ioctl_xloop06 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop07
add_executable(ioctl_xloop07 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop07.c)
target_link_libraries(ioctl_xloop07 libltp)
install(TARGETS ioctl_xloop07 DESTINATION bin
        COMPONENT test)
