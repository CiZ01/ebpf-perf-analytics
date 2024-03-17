# Description: Makefile for ebpf-programs

SUBDIRS := $(shell find . -mindepth 2 -type f -name 'Makefile' -exec dirname {} \;)

# remove duplicates and sort
SUBDIRS := $(sort $(SUBDIRS))
SUBDIRS := $(filter-out ./,$(SUBDIRS))

.PHONY: all $(SUBDIRS) clean

.SILENT: all

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "Building $@..."
	$(MAKE) -C $@ all

clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
        $(MAKE) -C $$dir clean; \
    done