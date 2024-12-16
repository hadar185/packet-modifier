obj-m := packet_modifier.o
packet_modifier-objs := src/packet_modifier.o src/rule.o src/packet.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean