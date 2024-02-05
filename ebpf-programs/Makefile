XDP_PASS=./xdp-pass/xdp_pass_kern
XDP_DROP=./xdp-pass/xdp_drop_kern

CC=clang
CFLAGS= -Wall -O2 -g -target bpf
LOADER=./loader/loader

all: xdp-pass xdp-drop

xdp-pass:
	$(CC) $(CFLAGS) -c $(XDP_PASS).c -o $(XDP_PASS).o 

xdp-drop:
	$(CC) $(CFLAGS) -c $@.c -o $@.o

load:
	$(LOADER) $(xdp) $(if) $(sec)

clean:
	rm -f $(XDP_PASS).o $(XDP_DROP).o

