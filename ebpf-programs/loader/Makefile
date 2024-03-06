TARGET := loader-stats
KHEADER:= ../../tracing-tools/xdp-introspection/kperf_

.PHONY: all build clean
.SILENT: all build clean

all: build

build:
	@echo "Compiling $(TARGET)"
	gcc -g -Wall -O2 -I$(KHEADER) $(TARGET).c -o $(TARGET).o -lbpf

install:
	@echo "Installing $(TARGET)"
	install -m 755 $(TARGET).o /usr/bin/$(TARGET)

clean:
	rm -f $(TARGET).o