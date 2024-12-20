obj-m := rootkit.o
rootkit-objs := src/rootkit.o src/hooks.o src/packet_handler.o src/rule.o src/packet.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean