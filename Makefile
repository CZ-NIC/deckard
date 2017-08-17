# Defaults
TESTS ?= sets/resolver
DAEMON ?= kresd
TEMPLATE ?= template/kresd.j2
CONFIG ?= config

PYTHON ?= python3
LIBEXT := .so
PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	LIBEXT := .dylib
endif

# Find all sub-targets
TARGETS := $(TESTS)
ifeq (,$(findstring .rpl,$(TESTS)))
TARGETS := $(wildcard $(TESTS)/*.rpl)
endif
SOURCES := $(TARGETS)
TARGETS := $(sort $(patsubst %.rpl,%.out,$(SOURCES)))

# Dependencies
include platform.mk
libcwrap_DIR := contrib/libswrap
libcwrap_cmake_DIR := $(libcwrap_DIR)/obj
libcwrap=$(abspath $(libcwrap_cmake_DIR))/src/libsocket_wrapper$(LIBEXT).0
ifeq ($(PLATFORM),Darwin)
	libcwrap=$(abspath $(libcwrap_cmake_DIR))/src/libsocket_wrapper.0$(LIBEXT)
endif
libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	preload_syms := DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH) DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime):$(libcwrap)"
else
	preload_syms := LD_PRELOAD="$(libfaketime):$(libcwrap)"
endif

# Targets
all: $(TARGETS)
depend: $(libfaketime) $(libcwrap)

# Generic rule to run test
$(SOURCES): depend
%.out: %.rpl
	@$(preload_syms) $(PYTHON) $(abspath ./deckard.py) $< one $(DAEMON) $(TEMPLATE) $(CONFIG) -- $(ADDITIONAL)

# Synchronize submodules
submodules: .gitmodules
	@git submodule update --init
# indirection through submodules target is necessary
# to prevent make from running "git submodule" commands in parallel
$(libfaketime_DIR)/Makefile $(libcwrap_DIR)/CMakeLists.txt: submodules
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="-O0 -g" $(MAKE) -s -C $(libfaketime_DIR)
$(libcwrap_cmake_DIR):$(libcwrap_DIR)/CMakeLists.txt
	@mkdir -p $(libcwrap_cmake_DIR)
$(libcwrap_cmake_DIR)/Makefile: $(libcwrap_cmake_DIR)
	@cd $(libcwrap_cmake_DIR); cmake ..
$(libcwrap): $(libcwrap_cmake_DIR)/Makefile
	@CFLAGS="-O0 -g" $(MAKE) -s -C $(libcwrap_cmake_DIR)


.PHONY: submodules depend all

check:
	@echo Running unittests using pytest
	${PYTHON} -m pytest
