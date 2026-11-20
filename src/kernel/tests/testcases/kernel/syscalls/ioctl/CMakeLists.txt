cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test-ioctl_xloop
        LANGUAGES C)

foreach(test_number RANGE 1 7)
    if(test_number LESS 10)
        set(test_name "ioctl_xloop0${test_number}")
    else()
        set(test_name "ioctl_xloop${test_number}")
    endif()
    add_executable(${test_name} ${test_name}.c)
    install(TARGETS ${test_name} DESTINATION bin COMPONENT test)
endforeach()
