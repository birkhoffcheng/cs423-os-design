EXTRA_CFLAGS +=
APP_EXTRA_FLAGS:= -O2 -ansi -pedantic
KERNEL_SRC:= /lib/modules/$(shell uname -r)/build
SUBDIR= $(PWD)
GCC:=gcc
RM:=rm

.PHONY : clean

all: clean modules app work monitor

obj-m:= mp3.o

modules:
	$(MAKE) -C $(KERNEL_SRC) M=$(SUBDIR) modules

app: userapp.c userapp.h
	$(GCC) -o userapp userapp.c

monitor: monitor.c
	$(GCC) -o monitor monitor.c

work: work.c
	$(GCC) -o work work.c

clean:
	$(RM) -f userapp *~ *.ko *.o *.mod.c Module.symvers modules.order

