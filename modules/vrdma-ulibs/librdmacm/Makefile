CC=gcc
CFLAGS=-O2 -g -Wall -DHAVE_CONFIG_H -DCONF_debug_memory=0

INCLUDES=-I./include -I./ -I../libibverbs/include -I../../../ -I../../../arch/common -I../../../include/glibc-compat -I../../../include/api -I../../../bsd/sys -I../../../bsd -I../../../bsd/include -I../../../include -I../../../bsd/sys/ofed/include -I../../../bsd/sys/ofed/drivers/hw -I../../../build/release.x64/gen/include -I../../../include/api/x64/ -I../../../arch/x64/ -I../../../external/x64/misc.bin/usr/include/boost -I../../../bsd/x64 -I../../../build/debug.x64/gen/include

CPP_SRCS=cma.cc
CPP_O=cma.o

SRCS=rsocket.c indexer.c
MAIN=librdmacm.so.1.0.0

module: $(MAIN) $(CPP_O)

$(CPP_O): $(CPP_SRC)
	$(CC) -DOSV_CLI $(CFLAGS) -fPIC -c -std=gnu++11 $(INCLUDES) $(CPP_SRCS)

$(MAIN): $(SRCS) $(CPP_O)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -std=gnu99 -fPIC -shared -o $@ $(SRCS) $(LFLAGS) $(LIBS)
	ln -s -f ./librdmacm.so.1.0.0 ./librdmacm.so

clean:
	rm -f $(MAIN) librdmacm.so.1 librdmacm.so
install:
	cp ./librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1.0.0
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so
	mkdir -p /usr/include/rdma
	cp ./include/rdma/* /usr/include/rdma
uninstall:
	rm -f /usr/lib/$(MAIN) /usr/lib/librdmacm.so.1 /usr/lib/librdmacm.so

.PHONY: module clean install uninstall
