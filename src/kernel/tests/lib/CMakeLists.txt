cmake_minimum_required(VERSION 3.10)

project(xloop-kernel-test-lib
        LANGUAGES C)

add_library(libltp STATIC ${CMAKE_CURRENT_SOURCE_DIR}/cloner.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/get_path.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/parse_opts.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/random_range.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/safe_file_ops.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/safe_macros.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/safe_net.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/safe_pthread.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/safe_stdio.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/self_exec.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tlibio.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_af_alg.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_ansi_color.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_assert.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_buffers.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_capability.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_cgroup.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_checkpoint.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_checksum.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_clocks.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_cmd.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_coredump.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_cpu.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_crypto.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_device.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_dir_is_empty.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fill_file.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fill_fs.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fs_has_free.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fs_link_count.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fs_setup.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_fs_type.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_get_bad_addr.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_hugepage.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_ioctl.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_kconfig.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_kernel.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_kvercmp.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_lockdown.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_memutils.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_mkfs.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_module.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_net.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_parse_opts.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_path_has_mnt_flags.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_pid.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_process_state.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_res.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_resource.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_safe_macros.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_safe_sysv_ipc.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_safe_timerfd.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_sig.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_sig_proc.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_status.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_supported_fs_types.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_sys_conf.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_taint.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_test.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_timer.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_timer_test.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_tmpdir.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_virt.c
                          ${CMAKE_CURRENT_SOURCE_DIR}/tst_wallclock.c)
target_include_directories(libltp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(libltp PUBLIC "-Wno-deprecated-declarations")
target_link_libraries(libltp LINK_PUBLIC xloop-version)
