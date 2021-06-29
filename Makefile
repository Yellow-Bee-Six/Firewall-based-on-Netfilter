target = firewall
user = start
obj-m := $(target).o  
#generate the path  
	CURRENT_PATH:=$(shell pwd)  
#the current kernel version number  
	LINUX_KERNEL:=$(shell uname -r)  
#the absolute path  
LINUX_KERNEL_PATH:=/usr/src/linux-headers-$(LINUX_KERNEL) 
#complie object  
all:  
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)
	gcc $(user).c -o $(user).o
#clean  
clean:  
	rm -rf *.a *.symvers *.order *.ko *.mod *.mod.c *.mod.o *.o

install:
	insmod $(target).ko

uninstall:
	rmmod $(target).ko