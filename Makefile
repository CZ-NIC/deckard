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
libcwrap_DIR := contrib/libswrap
libcwrap_cmake_DIR := $(libcwrap_DIR)/obj
libcwrap=$(abspath $(libcwrap_cmake_DIR))/src/libsocket_wrapper$(LIBEXT).0
libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime):$(libcwrap)"
else
	preload_syms := LD_PRELOAD="$(libfaketime):$(libcwrap)"
endif

all: depend
	$(preload_syms) ./deckard.py $(TESTS) $(DAEMON) $(TEMPLATE) $(CONFIG) $(ADDITIONAL)
depend: $(libfaketime) $(libcwrap)

# Synchronize submodules
$(libfaketime_DIR)/Makefile:
	@git submodule update --init
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="-O2 -g" $(MAKE) -C $(libfaketime_DIR)
$(libcwrap_DIR):
	@git submodule update --init
$(libcwrap_cmake_DIR):$(libcwrap_DIR)
	mkdir $(libcwrap_cmake_DIR)
$(libcwrap_cmake_DIR)/Makefile: $(libcwrap_cmake_DIR)
	@cd $(libcwrap_cmake_DIR); cmake ..
$(libcwrap): $(libcwrap_cmake_DIR)/Makefile
	@CFLAGS="-O2 -g" $(MAKE) -C $(libcwrap_cmake_DIR)


.PHONY: depend all
