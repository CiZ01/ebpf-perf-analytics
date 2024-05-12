TARGET=fentry
KHEADERS=../../../inxpect/kperf_

all: $(TARGET).bpf.o $(TARGET)_skel $(TARGET)



$(TARGET).bpf.o: $(TARGET).bpf.c
	clang -g -O2 -target bpf -I $(KHEADERS) -c $(TARGET).bpf.c -o $(TARGET).bpf.o

$(TARGET)_skel: 
	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET).skel.h

$(TARGET): 
	gcc -Wall -g -O2 $(TARGET).c -o $(TARGET).o -lbpf

clean:
	rm -f $(TARGET).bpf.o $(TARGET)_skel.h $(TARGET).o
