obj-m = psi.o
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	#sudo insmod psi.ko
	#make clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

remove:
	sudo rmmod psi.ko
