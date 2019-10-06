KDIR = /usr/src/linux-so2

QEMU_PATH = ../../qemu-so2/
CHECKER_PATH = ../checker/
CHECKER_FILES = $(CHECKER_PATH)_checker $(CHECKER_PATH)test $(CHECKER_PATH)solutie.ko
UTIL_FILES = insertmodule.sh removemodule.sh makenodes.sh

kbuild:
	make -C $(KDIR) M=`pwd`

clean:
	make -C $(KDIR) M=`pwd` clean
	-rm -f *~ Module.symvers Module.markers modules.order

copy-to-vm:
	cp uart16550.ko $(CHECKER_FILES) $(UTIL_FILES) $(QEMU_PATH)fsimg/root