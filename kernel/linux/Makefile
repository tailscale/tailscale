# SPDX-License-Identifier: GPL-2.0
#
# Build tswg.ko out of tree.
#
#   make                      # against the running kernel
#   make KDIR=/path/to/build  # against another kernel's build dir
#   make TSWG_DEBUG=y         # enable DEBUG and the built-in selftests

KDIR ?= /lib/modules/$(shell uname -r)/build
SRC := $(CURDIR)/src

all: module

module:
	$(MAKE) -C $(KDIR) M=$(SRC) TSWG_DEBUG=$(TSWG_DEBUG) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC) clean

.PHONY: all module clean
