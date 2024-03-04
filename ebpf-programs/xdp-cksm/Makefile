TARGET := xdp_cksm_kern
TARGET_USER := xdp_cksm_user

.SILENT: all

build: $(TARGET) $(TARGET)_skel $(TARGET_USER)

build_trace: $(TARGET)_trace $(TARGET)_trace_skel $(TARGET_USER)_trace $(TARGET_USER)_rb $(TARGET_USER)_percpu

all: build build_trace


# --------------------- KERNEL SPACE -------------------------------
$(TARGET): 
	@echo "[INFO]: Compiling $(TARGET)"
	clang -g -Wno-compare-distinct-pointer-types -O2 -target bpf -c $(TARGET).c -o $(TARGET).o

$(TARGET)_trace:
	@echo "[INFO]: Compiling $(TARGET)_trace"
	clang -g -Wno-compare-distinct-pointer-types -O2 -target bpf -c $(TARGET).c -o $(TARGET)_trace.o -DTRACE=1

# --------------------- GEN SKELETON -------------------------------
$(TARGET)_skel:
	@echo "[INFO]: Generating $(TARGET)_skel"
	bpftool gen skeleton $(TARGET).o > $(TARGET)_skel.h

$(TARGET)_trace_skel:
	@echo "[INFO]: Generating $(TARGET)_trace_skel"
	bpftool gen skeleton $(TARGET)_trace.o > $(TARGET)_trace_skel.h

# --------------------- USER SPACE -------------------------------
$(TARGET_USER):
	@echo "[INFO]: Compiling $(TARGET_USER)"
	gcc -Wall -g -O2 $(TARGET_USER).c -o $(TARGET_USER).o -lbpf  

$(TARGET_USER)_trace:
	@echo "[INFO]: Compiling $(TARGET_USER)"
	gcc -Wall -g -O2 $(TARGET_USER).c -o $(TARGET_USER)_trace.o -lbpf -DTRACE=1

# --------------------- RING BUFFER -------------------------------
$(TARGET_USER)_rb:
	@echo "[INFO]: Compiling $(TARGET_USER)_rb"
	gcc -Wall -g -O2 $(TARGET_USER)_rb.c -o $(TARGET_USER)_rb.o -lbpf -DTRACE=1

# --------------------- PERCPU ARRAY -------------------------------
$(TARGET_USER)_percpu:
	@echo "[INFO]: Compiling $(TARGET_USER)_percpu"
	gcc -Wall -g -O2 $(TARGET_USER)_percpu.c -o $(TARGET_USER)_percpu.o -lbpf -DTRACE=1

# --------------------- CLEAN -------------------------------
clean:
	rm -f $(TARGET).o \
		  $(TARGET)_trace.o \
		  \
		  $(TARGET)_skel.h \
		  $(TARGET)_trace_skel.h \
		  \
		  $(TARGET_USER).o  \
		  $(TARGET_USER)_trace.o \
