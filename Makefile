# Defaults
TESTS ?= sets/resolver
DAEMON ?= kresd
TEMPLATE ?= template/kresd.j2
CONFIG ?= config
ADDITIONAL ?= -f 1
OPTS ?=

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
TARGETS := $(sort $(patsubst %.rpl,%.out-qmin,$(SOURCES))) $(sort $(patsubst %.rpl,%.out-noqmin,$(SOURCES)))

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

# Test coverage measurement
# User has to provide own coverage_env.sh to generate environment variables for daemon under test
ifdef COVERAGE
ifndef COVERAGE_ENV_SCRIPT
$(error COVERAGE requires COVERAGE_ENV_SCRIPT with path to scripts/coverage_env.sh for given daemon)
endif
ifndef DAEMONSRCDIR
$(error COVERAGE requires DAEMONSRCDIR pointing to source directory of daemon under test)
endif
ifndef COVERAGE_STATSDIR
$(error COVERAGE requires COVERAGE_STATSDIR pointing to output directory)
endif
define set_coverage_env
$(shell "$(COVERAGE_ENV_SCRIPT)" "$(DAEMONSRCDIR)" "$(COVERAGE_STATSDIR)" "$(1)")
endef
endif


# Targets
all: $(TARGETS)
depend: $(libfaketime) $(libcwrap)

# Generic rule to run test
$(SOURCES): depend
%.out-qmin: %.rpl
	@test "$${QMIN:-true}" = "true" || exit 0 && \
	$(call set_coverage_env,$@) $(preload_syms) $(PYTHON) $(abspath ./deckard.py) --qmin true $(OPTS) $< one $(DAEMON) $(TEMPLATE) $(CONFIG) -- $(ADDITIONAL)

%.out-noqmin: %.rpl
	@test "$${QMIN:-false}" = "false" || exit 0 && \
	$(call set_coverage_env,$@) $(preload_syms) $(PYTHON) $(abspath ./deckard.py) --qmin false $(OPTS) $< one $(DAEMON) $(TEMPLATE) $(CONFIG) -- $(ADDITIONAL)

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
