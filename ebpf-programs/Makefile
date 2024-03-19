# Description: Makefile for ebpf-programs

SUBDIRS := $(shell find . -mindepth 2 -type f -name 'Makefile' -exec dirname {} \;)

# remove duplicates and sort
SUBDIRS := $(sort $(SUBDIRS))
SUBDIRS := $(filter-out ./,$(SUBDIRS))

.PHONY: all clean

.SILENT: all $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "Building $@..."
	$(MAKE) -C $@ all

# TODO TEST - I don't know if this will work
load_module:
	@echo "Loading module..."
	$(MAKE) -C ../tracing-tools/xdp-introspection/kperf_ all
	sudo $(MAKE) -C ../tracing-tools/xdp-introspection/kperf_ load

clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
        $(MAKE) -C $$dir clean; \
    done