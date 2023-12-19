CC := gcc
CLANG := clang

XDP_PROG_NAME := xdp_router
XDP_KERN_PROG := $(XDP_PROG_NAME)_kern.o
XDP_USER_PROG := $(XDP_PROG_NAME)_user

.PHONY: all clean

all: $(XDP_USER_PROG) $(XDP_KERN_PROG)

$(XDP_KERN_PROG): $(XDP_PROG_NAME)_kern.c
	$(CLANG) \
	-O2 \
	-g \
	-target bpf \
	-lbpf \
	-lbxdp \
	-c $< \
	-o $@

$(XDP_USER_PROG): $(XDP_PROG_NAME)_user.c
	$(CC) $< -o $@ -lxdp -lbpf

clean:
	rm -f $(XDP_KERN_PROG) $(XDP_USER_PROG)