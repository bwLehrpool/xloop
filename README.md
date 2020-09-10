# xloop - eXtended loop device

The eXtended loop (xloop) device provides a subsystem for the Linux kernel to register custom file format drivers. Those file format drivers enable the possibility to write and read file formats in the kernel space rather than in the user space.

This repository contains the source code for the xloop Linux kernel modules

  - **xloop**: eXtended loop device with file format subsystem
  - **xloop_file_format_raw**: file format subsystem driver for RAW files
  - **xloop_file_format_qcow**: file format subsystem driver for QCOW files

and the user space utility **xlosetup** to configure xloop devices.


## Build

### Preparation
Before a build takes place, you should create a `build` directory inside the root folder of the repository. After that, change your working directory to that new directory as follows:

```shell
mkdir build
cd build
```


### Configuration
A build of the xloop Linux kernel modules and the xlosetup utiliy can be configured and customized by the following configuration variables (CMake cache entries):

| Variable                  | Type   | Values                                  | Default value           | Description                                         |
|:--------------------------|:-------|:----------------------------------------|:------------------------|-----------------------------------------------------|
| `CMAKE_BUILD_TYPE`        | STRING | {`Debug`, `Release`}                    | `Debug`                 | Build configuration of the xloop project.           |
| `KERNEL_DIR`              | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r` | Path to Linux kernel modules to compile against.    |
| `XLOOP_MAJOR`             | NUMBER | {`0` .. `255`}                          | `120`                   | Major number for xloop devices.                     |
| `XLOOP_CTRL_MINOR`        | NUMBER | {`0` .. `255`}                          | `15`                    | Minor number for the xloop-control device.          |
| `BLK_DEV_XLOOP_MIN_COUNT` | NUMBER | {`0` .. `255`}                          | `8`                     | Number of xloop devices to pre-create at init time. |

A value from the range of appropriate values can be assigend to each configuration variable by executing CMake once with the following command pattern:

```shell
cmake -D<VARIABLE>=<VALUE> [-D ...] ../.
```


### Debug
In the `Debug` build configuration, all Linux kernel modules and the utility can be built by calling `make`:

```shell
make
```

Optionally, the output files can be installed with superuser permissions on the local system using the Makefile target `install`:

```shell
sudo make install
```


### Packages
In the `Release` build configuration, installation packages can be built by calling the make target `package`:

```shell
make package
```

This target creates a Debian installation package (\*.deb) and a compressed archive (\*.tar.gz) containing the built xloop Linux kernel modules and the xlosetup utility executable as well as its man page and bash-completion support.


### Sources
In the `Release` build configuration, sources can be built by calling the make target `package_source`:

```shell
make package_source
```

This target creates compressed archives (\*_sources.tar.gz and \*_sources.zip) containing the source code of this repository for code distribution purposes.
