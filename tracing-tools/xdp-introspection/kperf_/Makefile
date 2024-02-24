obj-m += mykperf_module.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod mykperf_module.ko

unload:
	sudo rmmod mykperf_module.ko

reload:
	sudo rmmod mykperf_module.ko
	sudo insmod mykperf_module.ko