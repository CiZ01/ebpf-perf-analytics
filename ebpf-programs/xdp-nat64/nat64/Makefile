CC := gcc
CLANG := clang

XDP_PROG_NAME := xdp_router
XDP_KERN_PROG := $(XDP_PROG_NAME)_kern.o
XDP_USER_PROG := $(XDP_PROG_NAME)_user.o

KHEADER :=  ../../../tracing-tools/xdp-introspection/kperf_
COMMON_DIR := ../../common

.PHONY: all clean

.SILENT: build_u build_k

all: build_u build_k

run: 
	./$(XDP_USER_PROG).o

build_k: $(XDP_PROG_NAME)_kern.c
	@echo "Building XDP program"
	$(CLANG) \
	-O2 \
	-g \
	-Wno-compare-distinct-pointer-types \
	-I$(KHEADER) \
	-target bpf \
	-c $< \
	-o $(XDP_KERN_PROG)

build_u: $(XDP_PROG_NAME)_user.c
	@echo "Building user program"
	$(CC) -g -Wall -O2 $< -o $(XDP_USER_PROG) -lbpf

clean:
	rm -f $(XDP_KERN_PROG) $(XDP_USER_PROG)
