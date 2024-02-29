TARGET=fentry

all: $(TARGET).bpf.o $(TARGET)_skel $(TARGET)



$(TARGET).bpf.o: $(TARGET).bpf.c
	clang -g -O2 -target bpf -c $(TARGET).bpf.c -o $(TARGET).bpf.o

$(TARGET)_skel: 
	bpftool gen skeleton $(TARGET).bpf.o > $(TARGET)_skel.h

$(TARGET): 
	gcc -Wall -g -O2 $(TARGET).c -o $(TARGET).o -lbpf

clean:
	rm -f $(TARGET).bpf.o $(TARGET)_skel.h
