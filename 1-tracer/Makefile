KDIR = /usr/src/linux-so2

build:
	make -C $(KDIR) M=`pwd`

clean:
	make -C $(KDIR) M=`pwd` clean
	-rm -f *~ Module.symvers

copy-to-vm:
	cp tracer.ko 1-tracer/tracer_test 1-tracer/_checker 1-tracer/_helper/tracer_helper.ko ../qemu-so2/fsimg/root/modules

checkpatch:
	../linux-4.9.11/scripts/checkpatch.pl --no-tree --terse -f ./tracer.c