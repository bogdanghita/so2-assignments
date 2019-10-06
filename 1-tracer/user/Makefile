CFLAGS = -Wall -g -m32 -static

.PHONY: all clean

all: tracer_ioctl_test

clean:
	-rm -f *~ *.o tracer_ioctl_test

copy-to-vm:
	cp tracer_ioctl_test ../../qemu-so2/fsimg/root/modules
