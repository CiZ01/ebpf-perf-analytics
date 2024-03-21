TARGET := xdp_tx_iptunnel

KHEADER:= /usr/local/include/mykperf/mykperf_module.h

.PHONY: all clean
.SILENT: $(TARGET)_kern $(TARGET)_kern_trace $(TARGET)_user
all: $(TARGET)_kern $(TARGET)_kern_trace $(TARGET)_user

#----------------------- KERNEL SPACE -------------------------------
$(TARGET)_kern: 
	@echo "Using $(KHEADER)"
	@echo "[INFO]: Compiling $(TARGET)_kern"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET)_kern.c -o $(TARGET)_kern.o

$(TARGET)_kern_trace:
	@echo "[INFO]: Compiling $(TARGET)_kern_trace"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET)_kern.c -o $(TARGET)_kern__trace.o -DTRACE=1

#----------------------- USER SPACE -------------------------------
# this is the user space program that will be used to load the eBPF program
# it's provide by linux/sample/bpf, I will then only use my loader-stats to retrieve stats.
$(TARGET)_user:
	@echo "[INFO]: Compiling $(TARGET)_user"
	gcc -Wall -g -O2 $(TARGET)_user.c -o $(TARGET)_user.o -lbpf


clean:
	rm -f *.o