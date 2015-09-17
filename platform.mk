# Evaluate library
define have_lib
ifeq ($$(strip $$($(1)_LIBS)),)
	HAS_$(1) := no
else
	HAS_$(1) := yes
endif
endef

# Find library (pkg-config)
define find_lib
	$(call find_alt,$(1),$(1),$(2))
endef

# Find library alternative (pkg-config)
define find_alt
	ifeq ($$(strip $$($(1)_LIBS)),)
		ifneq ($(strip $(3)),)
			$(1)_VER := $(shell pkg-config --atleast-version=$(3) $(2) && echo $(3))
		endif
		ifeq ($(strip $(3)),$$($(1)_VER))
			$(1)_CFLAGS := $(shell pkg-config --cflags $(2) --silence-errors)
			$(1)_LIBS := $(shell pkg-config --libs $(2)  --silence-errors)
		endif
	endif
	$(call have_lib,$(1),$(3))
endef
