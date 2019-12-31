obj-m += kmod/rsyscall.o

all: rsyscall.ko librsyscall.so

rsyscall.ko: kmod/rsyscall.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp kmod/rsyscall.ko .

librsyscall.so: librsyscall/librsyscall.c
	gcc -shared $< -o $@ -fPIC -Wall -Wextra

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
