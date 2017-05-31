CC=gcc
CFLAGS=-O2 -g -Wall -DIBV_CONFIG_DIR=\"/etc/libibverbs.d\" -DHAVE_CONFIG_H -DCONF_debug_memory=0 -D_KERNEL
INCLUDES=-I./include -I./ -I../../../ -I../../../arch/common -I../../../include/glibc-compat -I../../../include/api -I../../../bsd/sys -I../../../bsd -I../../../bsd/include -I../../../include -I../../../bsd/sys/ofed/include -I../../../bsd/sys/ofed/drivers/hw -I../../../build/release.x64/gen/include -I../../../include/api/x64/ -I../../../arch/x64/ -I../../../external/x64/misc.bin/usr/include/boost -I../../../bsd/x64 -I../../../build/debug.x64/gen/include

LFLAGS=-L./

CPP_SRCS=cmd.cc
CPP_O=cmd.o

MAIN_SRCS=compat-1_0.c device.c enum_strs.c init.c marshall.c memory.c sysfs.c verbs.c
MAIN=libibverbs.so.1.0.0

DEVINFO_SRCS=devinfo.c
DEVINFO=ibv_devinfo.so

module: $(MAIN) $(DEVINFO) $(CPP_O)

$(CPP_O): $(CPP_SRC)
	$(CC) -DOSV_CLI $(CFLAGS) -fPIC -c -std=gnu++11 $(INCLUDES) $(CPP_SRCS)

$(MAIN): $(MAIN_SRCS) $(CPP_O)
	$(CC) -DOSV_CLI $(CFLAGS) -std=gnu99 $(INCLUDES) -fPIC -shared -o $@ $(MAIN_SRCS) $(CPP_O) -ldl -pthread
	ln -s -f ./libibverbs.so.1.0.0 ./libibverbs.so
	ln -s -f ./libibverbs.so.1.0.0 ./libibverbs.so.1

$(DEVINFO): $(DEVINFO_SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) -std=gnu99 $(INCLUDES) -fPIC -shared -o $@ $(DEVINFO_SRCS) $(LFLAGS) -pthread -libverbs -ldl

clean:
	rm -f $(MAIN) $(DEVINFO) $(CPP_O) ./libibverbs.so

install:
	cp ./libibverbs.so.1.0.0 /usr/lib/libibverbs.so.1.0.0
	ln -s -f /usr/lib/libibverbs.so.1.0.0 /usr/lib/libibverbs.so.1
	ln -s -f /usr/lib/libibverbs.so.1.0.0 /usr/lib/libibverbs.so
	cp ./ibv_devinfo.so /usr/bin/ibv_devinfo.so
	mkdir -p /usr/include/infiniband
	cp ./include/infiniband/* /usr/include/infiniband

uninstall:
	rm -f /usr/lib/$(MAIN) /usr/lib/libibverbs.so.1 /usr/lib/libibverbs.so /usr/bin/$(DEVINFO)

.PHONY: module clean install uninstall
