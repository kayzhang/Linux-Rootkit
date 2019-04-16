ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: all build clean

all: sneaky_process build

sneaky_process: sneaky_process.c
	gcc -o sneaky_process sneaky_process.c

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

clean:
	rm -rf sneaky_process *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c 
else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    sneaky_mod.o  

endif
