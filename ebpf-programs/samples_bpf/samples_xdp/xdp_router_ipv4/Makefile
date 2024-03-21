TARGET := xdp_router_ipv4

KHEADER:= /usr/local/include/mykperf/mykperf_module.h

.PHONY: all clean
.SILENT: $(TARGET)_kern $(TARGET)_user
all: $(TARGET)_kern $(TARGET)_skel $(TARGET)_user

#----------------------- KERNEL SPACE -------------------------------
$(TARGET)_kern: 
	@echo "Using $(KHEADER)"
	@echo "[INFO]: Compiling $(TARGET)_kern"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET).bpf.c -o $(TARGET).o -DTRACE=1
# ---------------------- GEN SKEL --------------------------------------
$(TARGET)_skel:
	@echo "Generating Skel for $(TARGET)"
	bpftool gen skeleton $(TARGET).o > $(TARGET).skel.h

#----------------------- USER SPACE -------------------------------
# this is the user space program that will be used to load the eBPF program
# it's provide by linux/sample/bpf, I will then only use my loader-stats to retrieve stats.
$(TARGET)_user:
	@echo "[INFO]: Compiling $(TARGET)_user"
	gcc -Wall -g -O2 $(TARGET)_user.c -o $(TARGET) -lbpf


clean:
	rm -f *.o
	rm -f $(TARGET)