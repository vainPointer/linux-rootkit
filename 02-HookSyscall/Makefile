obj-m += hooksyscall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -c
	sudo insmod example.ko
	sudo rmmod example.ko
	dmesg
