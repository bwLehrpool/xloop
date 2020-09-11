cmake_minimum_required(VERSION 3.12)

project(xloop-kernel-test-ioctl_xloop)

# test ioctl_xloop01
add_executable(tst_ioctl_xloop01 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop01.c)
target_link_libraries(tst_ioctl_xloop01 LINK_PUBLIC libltp)
install(TARGETS tst_ioctl_xloop01 DESTINATION bin)

# test ioctl_xloop02
add_executable(tst_ioctl_xloop02 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop02.c)
target_link_libraries(tst_ioctl_xloop02 LINK_PUBLIC libltp)

# test ioctl_xloop03
add_executable(tst_ioctl_xloop03 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop03.c)
target_link_libraries(tst_ioctl_xloop03 LINK_PUBLIC libltp)

# test ioctl_xloop04
add_executable(tst_ioctl_xloop04 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop04.c)
target_link_libraries(tst_ioctl_xloop04 LINK_PUBLIC libltp)

# test ioctl_xloop05
add_executable(tst_ioctl_xloop05 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop05.c)
target_link_libraries(tst_ioctl_xloop05 LINK_PUBLIC libltp)

# test ioctl_xloop06
add_executable(tst_ioctl_xloop06 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop06.c)
target_link_libraries(tst_ioctl_xloop06 LINK_PUBLIC libltp)

# test ioctl_xloop07
add_executable(tst_ioctl_xloop07 ${CMAKE_CURRENT_SOURCE_DIR}/ioctl_xloop07.c)
target_link_libraries(tst_ioctl_xloop07 LINK_PUBLIC libltp)