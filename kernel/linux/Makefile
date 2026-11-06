# SPDX-License-Identifier: GPL-2.0
#
# Build tswg.ko out of tree.
#
#   make                      # against the running kernel
#   make KDIR=/path/to/build  # against another kernel's build dir
#   make TSWG_DEBUG=y         # enable DEBUG and the built-in selftests

KDIR ?= /lib/modules/$(shell uname -r)/build
SRC := $(CURDIR)/src
AUTOCONF := $(SRC)/compat/generated/autoconf.h

all: module

# The probes are cheap, so always rerun them; probe.sh leaves the header
# untouched (and so doesn't trigger a rebuild) when the results don't change.
probe:
	scripts/probe.sh $(KDIR) $(AUTOCONF)

module: probe
	$(MAKE) -C $(KDIR) M=$(SRC) TSWG_DEBUG=$(TSWG_DEBUG) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC) clean
	rm -rf $(SRC)/compat/generated

.PHONY: all probe module clean
