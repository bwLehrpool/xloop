# SPDX-License-Identifier: GPL-2.0
include $(PWD)/Kbuild

ifndef KDIR
	KDIR = /lib/modules/$(shell uname -r)/build
endif

all:
	make -C "$(KDIR)" "M=$(PWD)" modules

clean:
	make -C "$(KDIR)" "M=$(PWD)" clean
