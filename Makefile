# Defaults
PYTHON ?= python3
LIBEXT := .so
PLATFORM := $(shell uname -s)
ifeq ($(PLATFORM),Darwin)
	LIBEXT := .dylib
endif

# Dependencies
include platform.mk
libfaketime_DIR := contrib/libfaketime
libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime$(LIBEXT).1

# Platform-specific targets
ifeq ($(PLATFORM),Darwin)
	libfaketime := $(abspath $(libfaketime_DIR))/src/libfaketime.1$(LIBEXT)
	preload_syms := DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH) DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(libfaketime)"
else
	preload_syms := LD_PRELOAD="$(libfaketime)"
endif


# Targets
all:
	@echo "Deckard is now run using *run.sh scripts in its root directory."
	@echo "To build the dependencies (libfaketime and libcwrap) run 'make depend'."
	exit 1
depend: $(libfaketime) $(libcwrap)
	@echo "export DONT_FAKE_MONOTONIC=1" > env.sh
	@echo "export $(preload_syms)" >> env.sh

# Synchronize submodules
submodules: .gitmodules
	@git submodule update --init
# indirection through submodules target is necessary
# to prevent make from running "git submodule" commands in parallel
$(libfaketime_DIR)/Makefile $(libcwrap_DIR)/CMakeLists.txt: submodules
$(libfaketime): $(libfaketime_DIR)/Makefile
	@CFLAGS="-O0 -g" $(MAKE) -s -C $(libfaketime_DIR)


.PHONY: submodules depend all

check:
	@echo Running unittests using pytest
	${PYTHON} -m pytest
