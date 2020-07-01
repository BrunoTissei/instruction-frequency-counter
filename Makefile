ifdef PIN_ROOT

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

all:
	make TARGET=intel64 obj-intel64/instruction_freq.so

else

all:
	@echo "Example: make PIN_ROOT=/path/to/pinroot"

clean:
	rm obj-intel64/*

endif
