CC := gcc
CLANG := clang

XDP_PROG_NAME := xdp_router
XDP_KERN_PROG := $(XDP_PROG_NAME)_kern.o
XDP_USER_PROG := $(XDP_PROG_NAME)_user

.PHONY: all clean

all: build_u build_k

run: 
	./xdp_router_user

build_k: $(XDP_PROG_NAME)_kern.c
	$(CLANG) \
	-O2 \
	-g \
	-Wno-compare-distinct-pointer-types \
	-target bpf \
	-c $< \
	-o $(XDP_KERN_PROG)

build_u: $(XDP_PROG_NAME)_user.c
	$(CC) -g -Wall -O2 common/common_params.c $< -o $(XDP_USER_PROG) -lxdp -lbpf

clean:
	rm -f $(XDP_KERN_PROG) $(XDP_USER_PROG)
