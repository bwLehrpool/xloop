The master branch supports 4.19.x kernels.

Building the modules:

```shell
$ make CONFIG_BLK_DEV_LOOP=m CONFIG_BLK_DEV_LOOP_FILE_FMT_QCOW=m CONFIG_BLK_DEV_LOOP_FILE_FMT_RAW=m
```

Results in:
* xloop.ko
* loop_file_fmt_raw.ko
* loop_file_fmt_qcow.ko

Clean:
```shell
$ make clean
```
