Perfuser modules
================

Receive a signal when a perf sample is generated. This is the kernel
module component.

Building
--------

You will need to have your kernel headers available (or access to your full
kernel source tree), and do:

    make
    sudo make modules_install
    sudo depmod -a

The above commands will build the modules against your current kernel. If you
need to build the modules against a custom kernel, do:

    make KERNELDIR=/path/to/custom/kernel
    sudo make KERNELDIR=/path/to/custom/kernel modules_install
    sudo depmod -a kernel_version


### Required kernel config options

Make sure your target kernel has the following config options enabled:

  - `CONFIG_MODULES`: loadable module support
  - `CONFIG_KALLSYMS`: see files in [`wrapper`](wrapper); this is
     necessary until the few required missing symbols are exported to GPL
     modules from mainline
  - `CONFIG_PERF_EVENT`: kernel performance counter 


Usage
-----

The API is a set of ioctl() on /proc/perfuser file. However, since this
is a prototype, the API may change at any time. For usage examples, look
at the project `perfuser`.

