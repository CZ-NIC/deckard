# Defaults
TESTS ?= sets/resolver
DAEMON ?= kresd
TEMPLATE ?= kresd.j2
CONFIG ?= config

LIBEXT := .so
PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	LIBEXT := .dylib
endif

# Dependencies
include platform.mk
$(eval $(call find_lib,socket_wrapper))
libcwrap := $(strip $(socket_wrapper_LIBS))
libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime):$(libcwrap)"
else
	preload_syms := LD_PRELOAD="$(libfaketime):$(libcwrap)"
endif

# Targets
ifeq ($(HAS_socket_wrapper), yes)
all: depend
	$(preload_syms) ./deckard.py $(TESTS) $(DAEMON) $(TEMPLATE) $(CONFIG) $(ADDITIONAL)
depend: $(libfaketime) $(libcwrap)
else
$(error missing required socket_wrapper)
endif

# Synchronize submodules
$(libfaketime_DIR)/Makefile:
	@git submodule update --init
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="-O2 -g" $(MAKE) -C $(libfaketime_DIR)

.PHONY: depend all
