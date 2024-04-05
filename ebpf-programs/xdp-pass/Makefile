TARGET := xdp_pass_kern
TARGET_USER := xdp_pass_user
TARGET_TEST := xdp_pass_test
KHEADER:= ../../tracing-tools/xdp-introspection/kperf_


.SILENT: all
.PHONY: all build build_trace

all: build build_trace

build: $(TARGET) #$(TARGET)_skel $(TARGET_USER) $(TARGET_TEST)_run

build_trace: $(TARGET)_trace #$(TARGET_TEST)_trace_run



# --------------------- KERNEL SPACE -------------------------------
$(TARGET): 
	@echo "[INFO]: Compiling $(TARGET)"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET).c -o $(TARGET).o

$(TARGET)_trace:
	@echo "[INFO]: Compiling $(TARGET)_trace"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET).c -o $(TARGET)_trace.o -DTRACE=1

$(TARGET)_trace_rb:
	@echo "[INFO]: Compiling $(TARGET)_trace_rb"
	clang -g -Wno-compare-distinct-pointer-types -O2 -I$(KHEADER) -target bpf -c $(TARGET)_rb.c -o $(TARGET)_trace_rb.o -DTRACE=1

# --------------------- GEN SKELETON -------------------------------
$(TARGET)_skel:
	@echo "[INFO]: Generating $(TARGET)_skel"
	bpftool gen skeleton $(TARGET).o > $(TARGET)_skel.h

$(TARGET)_trace_skel:
	@echo "[INFO]: Generating $(TARGET)_trace_skel"
	bpftool gen skeleton $(TARGET)_trace.o > $(TARGET)_trace_skel.h

$(TARGET)_trace_rb_skel:
	@echo "[INFO]: Generating $(TARGET)_trace_skel"
	bpftool gen skeleton $(TARGET)_trace_rb.o > $(TARGET)_trace_rb_skel.h

# --------------------- USER SPACE -------------------------------
$(TARGET_USER):
	@echo "[INFO]: Compiling $(TARGET_USER)"
	gcc -Wall -g -O2 $(TARGET_USER).c -o $(TARGET_USER).o -lbpf  

$(TARGET_USER)_trace: #array
	@echo "[INFO]: Compiling $(TARGET_USER)"
	gcc -Wall -g -O2 -I$(KHEADER) $(TARGET_USER)_array.c -o $(TARGET_USER)_trace_array.o -lbpf -DTRACE=1

$(TARGET_USER)_trace_rb:
	@echo "[INFO]: Compiling $(TARGET_USER)"
	gcc -Wall -g -O2 -I$(KHEADER) $(TARGET_USER)_RB.c -o $(TARGET_USER)_trace_rb.o -lbpf -DTRACE=1
# ------------------- USER SPACE PROG RUN ----------------------------
$(TARGET_TEST)_run:
	@echo "[INFO]: Compiling $(TARGET_TEST)"
	gcc -Wall -g -O2 $(TARGET_TEST)_run.c -o $(TARGET_TEST)_run.o -L../libbpf/src -l:libbpf.a -lelf -lz

$(TARGET_TEST)_trace_run:
	@echo "[INFO]: Compiling $(TARGET_TEST)"
	gcc -Wall -g -O2 $(TARGET_TEST)_run.c -o $(TARGET_TEST)_trace_run.o -DTRACE=1 -L../libbpf/src -l:libbpf.a -lelf -lz
	

clean:
	rm -f $(TARGET).o \
		  $(TARGET)_trace.o \
		  \
		  $(TARGET)_skel.h \
		  $(TARGET)_trace_skel.h \
		  \
		  $(TARGET_USER).o  \
		  $(TARGET_USER)_trace.o \
		  \
		  $(TARGET_TEST)_run.o \ 
		  $(TARGET_TEST)_trace_run.o
