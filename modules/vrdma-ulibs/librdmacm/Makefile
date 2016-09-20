CC=gcc
CFLAGS=-O2 -g -Wall -std=gnu99 -DHAVE_CONFIG_H

INCLUDES=-I./include -I./ -I../../include/api/ -I../../include/api/x64/ -I../../include/glibc-compat/ -I../../bsd/sys/ -I../../../osv/build/release.x64/gen/include -I../../bsd/x64/ -I../../ -I../../include/
#	../../bsd/sys/ \ # sys/mman.h (minherit)
#	../../../osv/build/release.x64/gen/include \ # bits/alltypes.h
#	../../bsd/x64/ # machine/endian.h
#	../../include/api/ # netinet/__in.h
#	../../include/api/x64/ # bits/posix.h
#	../../include/glibc-compat/ # sys/cdef.h
#	./../ # _sockaddr_storage.h

SRCS=cma.c
MAIN=librdmacm.so.1.0.0


module: $(MAIN)

$(MAIN): $(SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $(SRCS) $(LFLAGS) $(LIBS)

clean:
	rm -f $(MAIN)
install:
	cp ./librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1.0.0
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so
	mkdir -p /usr/include/rdma
	cp ./include/rdma/* /usr/include/rdma
uninstall:
	rm -f /usr/lib/$(MAIN) /usr/lib/libibverbs.so.1 /usr/lib/libibverbs.so

.PHONY: module clean install uninstall
