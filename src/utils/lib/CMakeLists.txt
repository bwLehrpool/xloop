cmake_minimum_required(VERSION 3.10)

# set the project name
project(xloop-utils-lib)

add_library(libcommon STATIC ${CMAKE_CURRENT_SOURCE_DIR}/blkdev.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/canonicalize.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/caputils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/color-names.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/colors.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/cpuset.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/crc32.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/crc32c.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/encode.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/env.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/exec_shell.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/fileutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/idcache.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/ismounted.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/langinfo.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/linux_version.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/loopdev.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/mangle.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/match.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/mbsalign.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/mbsedit.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/md5.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/monotonic.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/pager.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/path.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/plymouth-ctrl.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/procutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/pty-session.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/pwdutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/randutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/setproctitle.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/sha1.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/signames.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/strutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/strv.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/sysfs.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/timer.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/timeutils.c
                             ${CMAKE_CURRENT_SOURCE_DIR}/ttyutils.c)
