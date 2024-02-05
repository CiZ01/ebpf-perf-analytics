TARGET := loader

build:
	gcc -g -Wall -O2 ../common/common_params.c $(TARGET).c -o $(TARGET) -lxdp -lbpf

clean:
	rm -f $(TARGET)