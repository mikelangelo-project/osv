CC=gcc
CFLAGS=-O2 -g -Wall -std=gnu99 -DHAVE_CONFIG_H
INCLUDES=-I./include -I./ -I../../include/glibc-compat/ -I../../bsd/sys/ -I../../../osv/build/release.x64/gen/include -I../../bsd/x64/ -I../../include/api/ -I../../include/api/x64/ -I../../
#	../../bsd/sys/ \ # sys/mman.h (minherit)
#	../../../osv/build/release.x64/gen/include \ # bits/alltypes.h
#	../../bsd/x64/ # machine/endian.h
#	../../include/api/ # netinet/__in.h
#	../../include/api/x64/ # bits/posix.h
#	../../include/glibc-compat/ # sys/cdef.h
#	./../ # _sockaddr_storage.h

SRCS=buf.c cq.c dbrec.c mlx4.c qp.c srq.c verbs.c
MAIN=libmlx4-rdmav2.so


module: $(MAIN)

$(MAIN): $(SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $(SRCS) $(LFLAGS) $(LIBS)

clean:
	rm -f $(MAIN)
install:
	cp libmlx4-rdmav2.so /usr/lib/libmlx4-rdmav2.so
	ln -s -f /usr/lib/libmlx4-rdmav2.so /usr/lib/libmlx4.so
	mkdir -p /usr/etc/libibverbs.d
	cp mlx4.driver /usr/etc/libibverbs.d
	chmod 644 /usr/etc/libibverbs.d/mlx4.driver

uninstall:
	rm -f /usr/etc/libibverbs.d/mlx4.driver /usr/lib/libmlx4-rdmav2.so /usr/lib/libmlx4.so

.PHONY: module clean install uninstall
