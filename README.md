# xloop - eXtended loop device

The eXtended loop (xloop) device provides a subsystem for the Linux kernel to register custom file format drivers. Those file format drivers enable the possibility to write and read file formats in the kernel space rather than in the user space.

This repository contains the source code for the xloop Linux kernel modules

  - **xloop**: eXtended loop device with file format subsystem
  - **xloop_file_format_raw**: file format subsystem driver for RAW files
  - **xloop_file_format_qcow**: file format subsystem driver for QCOW files

and the user space utility **xlosetup** to configure xloop devices. The xloop Linux kernel modules can be built for the following Linux kernel versions and Linux distributions:

  - Archlinux with **Linux kernel 5.9.x** or **5.4.x**
  - Ubuntu 20.04 with **Linux kernel 5.4.x**
  - CentOS 8 with **Linux kernel 4.18.x**


## Build

### Preliminaries
A build of the xloop Linux kernel modules and the xlosetup utility requires the installation of the following build tools and libraries under your supported Linux distribution.

#### Archlinux with Linux kernel 5.9.x or 5.4.x
```shell
pacman -S git \
          make \
          cmake \
          gcc \
          linux-headers \  # or linux-lts-headers
          libcap \
          ncurses \
          dpkg \
          rpm-tools
```

#### Ubuntu 20.04 with Linux kernel 5.4.x
```shell
apt-get install git \
                make \
                cmake \
                gcc \
                g++ \
                linux-headers-generic \
                libcap-dev \
                libncurses-dev \
                rpm
```

#### CentOS 8 with Linux kernel 4.18.x
```shell
yum install git \
            make \
            cmake \
            gcc \
            gcc-c++ \
            kernel-devel \
            elfutils-libelf-devel \
            libcap-devel \
            ncurses-devel \
            rpm-build
```


### Preparation
Before a build takes place, you should create a `build` directory inside the root folder of the repository. After that, change your working directory to that new directory as follows:

```shell
mkdir build
cd build
```


### Configuration
A build of the xloop Linux kernel modules and the xlosetup utility can be configured and customized by the following configuration variables (CMake cache entries):

| Variable                  | Type   | Values                                  | Default value                 | Description                                         |
|:--------------------------|:-------|:----------------------------------------|:------------------------------|-----------------------------------------------------|
| `CMAKE_BUILD_TYPE`        | STRING | {`Debug`, `Release`}                    | `Debug`                       | Build configuration of the xloop project.           |
| `KERNEL_BUILD_DIR`        | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r`/build | Path to Linux kernel modules to compile against.    |
| `KERNEL_INSTALL_DIR`      | PATH   | {`a` .. `z`, `A` .. `Z`, `/`, `_`, `-`} | /lib/modules/`uname -r`/extra | Path to install Linux kernel modules.               |
| `XLOOP_MAJOR`             | NUMBER | {`0` .. `255`}                          | `120`                         | Major number for xloop devices.                     |
| `XLOOP_CTRL_MINOR`        | NUMBER | {`0` .. `255`}                          | `15`                          | Minor number for the xloop-control device.          |
| `BLK_DEV_XLOOP_MIN_COUNT` | NUMBER | {`0` .. `255`}                          | `8`                           | Number of xloop devices to pre-create at init time. |

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
sudo depmod -a
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


## Debugging
Debugging of the Linux kernel modules and the user space utility requires this project to be built in the `Debug` configuration.

### Linux kernel modules
The Linux kernel modules **xloop**, **xloop_file_fmt_raw** and **xloop_file_fmt_qcow** support the Linux kernel's dynamic debug feature if the Linux kernel is built with the enabled kernel configuration `CONFIG_DYNAMIC_DEBUG`. The dynamic debug feature allows the printing of customizable debug messages into the Linux kernel's message buffer.

Dynamic debug for the modules can be either enabled at module initialization or during operation. At module initialization, dynamic debug can be enabled by modprobe using the "fake" module parameter `dyndbg`:

```shell
modprobe xloop dyndbg=+pflmt
modprobe xloop_file_fmt_raw dyndbg=+pflmt
modprobe xloop_file_fmt_qcow dyndbg=+pflmt
```

The module parameter `dyndbg` customizes the debug messages written into the Linux kernel's message buffer. The specific value `+pflmt` enables all debug messages in the source code and includes function name (`f`), line number (`l`), module name (`m`) and thread ID (`t`) for each executed debug statement from the source code.

During operation, debug messages from debug statements in the code can be customized and enabled dynamically as well using the debugfs control file `<DEBUG_FS>/dynamic_debug/control` where `DEBUG_FS` is the mount point of a mounted DebugFS, eg. `/sys/kernel/debug`:

```shell
echo "module xloop +pflmt" > <DEBUG_FS>/dynamic_debug/control
echo "module xloop_file_fmt_raw +pflmt" > <DEBUG_FS>/dynamic_debug/control
echo "module xloop_file_fmt_qcow +pflmt" > <DEBUG_FS>/dynamic_debug/control
```

More information regarding the Linux kernel's dynamic debug feature can be found in the (https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html)[Linux kernel documentation].


### User space utility
Built-in debug messages from the user space utility **xlosetup** can be enabled by setting the following environment variables before any execution of xlosetup:

```shell
export XLOOPDEV_DEBUG=all
export LIBSMARTCOLS_DEBUG=all
```
