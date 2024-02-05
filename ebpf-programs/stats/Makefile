TARGET := stats

all: $(TARGET)

$(TARGET): 
	gcc -g -Wall -O2 $(TARGET).c -o $@.o -lxdp -lbpf 
	gcc -g -Wall -O2 $(TARGET)_bpf.c -o $@_bpf.o -lbpf
