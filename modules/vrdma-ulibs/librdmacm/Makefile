CC=gcc
CFLAGS=-O2 -g -Wall -std=gnu99 -DHAVE_CONFIG_H

INCLUDES=-I./include -I./ -I../libibverbs/include

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
	rm -f /usr/lib/$(MAIN) /usr/lib/librdmacm.so.1 /usr/lib/librdmacm.so

.PHONY: module clean install uninstall
