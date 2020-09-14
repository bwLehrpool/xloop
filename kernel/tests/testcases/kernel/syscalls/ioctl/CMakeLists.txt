cmake_minimum_required(VERSION 3.12)

project(xloop-kernel-test-ioctl_xloop)

# test ioctl_xloop01
add_executable(ioctl_xloop01 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop01.c)
target_link_libraries(ioctl_xloop01 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop01 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop02
add_executable(ioctl_xloop02 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop02.c)
target_link_libraries(ioctl_xloop02 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop02 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop03
add_executable(ioctl_xloop03 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop03.c)
target_link_libraries(ioctl_xloop03 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop03 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop04
add_executable(ioctl_xloop04 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop04.c)
target_link_libraries(ioctl_xloop04 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop04 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop05
add_executable(ioctl_xloop05 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop05.c)
target_link_libraries(ioctl_xloop05 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop05 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop06
add_executable(ioctl_xloop06 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop06.c)
target_link_libraries(ioctl_xloop06 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop06 DESTINATION bin
        COMPONENT test)

# test ioctl_xloop07
add_executable(ioctl_xloop07 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop07.c)
target_link_libraries(ioctl_xloop07 LINK_PUBLIC libltp)
install(TARGETS ioctl_xloop07 DESTINATION bin
        COMPONENT test)
