TARGET := xdp_cid_kern
TARGET_USER := xdp_cid_user
TARGET_TEST := xdp_cid_test

.SILENT: all

build: $(TARGET) $(TARGET)_skel $(TARGET_USER) $(TARGET_TEST)_run

build_trace: $(TARGET)_trace $(TARGET)_trace_skel $(TARGET_USER)_trace $(TARGET_TEST)_trace_run

all: build build_trace


# --------------------- KERNEL SPACE -------------------------------
$(TARGET): 
	@echo "[INFO]: Compiling $(TARGET)"
	clang -g -Wall -O2 -target bpf -c $(TARGET).c -o $(TARGET).o

$(TARGET)_trace:
	@echo "[INFO]: Compiling $(TARGET)_trace"
	clang -g -Wall -O2 -target bpf -c $(TARGET).c -o $(TARGET)_trace.o -DTRACE=1

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
# ------------------- USER SPACE PROG RUN ----------------------------
$(TARGET_TEST)_run:
	@echo "[INFO]: Compiling $(TARGET_TEST)"
	gcc -Wall -g -O2 xdp_cid_test_run.c -o xdp_cid_test_run.o -L../libbpf/src -l:libbpf.a -lelf -lz

$(TARGET_TEST)_trace_run:
	@echo "[INFO]: Compiling $(TARGET_TEST)"
	gcc -Wall -g -O2 xdp_cid_test_run.c -o xdp_cid_test_trace_run.o -L../libbpf/src -l:libbpf.a -lelf -lz -DTRACE=1
	

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
