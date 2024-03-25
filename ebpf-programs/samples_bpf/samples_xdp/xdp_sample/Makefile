TARGET := xdp_sample
IHASHTABLE := /usr/src/ofa_kernel/x86_64/6.7.9-1.el9.elrepo.x86_64/include/linux/hashtable.h

.PHONY: all clean
.SILENT: $(TARGET)_user $(TARGET).bpf

all: $(TARGET)_user $(TARGET).bpf 

$(TARGET)_user:
	@echo "[INFO]: Compiling $(TARGET)_user"
	gcc -Wall -g -O2 -I$(IHASHTABLE) $(TARGET)_user.c -o $(TARGET) -lbpf

$(TARGET).bpf: 
	@echo "[INFO]: Compiling $(TARGET).bpf"
	clang -g -Wno-compare-distinct-pointer-types -O2 -target bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o

clean:
	rm -f *.o
	rm -f $(TARGET)