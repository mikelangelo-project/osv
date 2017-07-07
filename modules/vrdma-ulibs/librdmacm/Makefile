CC=gcc
CFLAGS=-O2 -g -Wall -std=gnu99 -DHAVE_CONFIG_H

INCLUDES=-I./include -I./ -I../libibverbs/include

SRCS=cma.c
MAIN=librdmacm.so.1.0.0

RSPRELOAD_SRC=rsocket.c indexer.c
RSPRELOAD_SO=librspreload.so.1.0.0


module: $(MAIN) $(RSPRELOAD_SO)

$(MAIN): $(SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $(SRCS) $(LFLAGS) $(LIBS)
	ln -s -f ./librdmacm.so.1.0.0 ./librdmacm.so

$(RSPRELOAD_SO): $(RSPRELOAD_SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $(RSPRELOAD_SRC) $(LFLAGS) -pthread -libverbs -ldl
	ln -s -f ./librspreload.so.1.0.0 ./librspreload.so
	ln -s -f ./librspreload.so.1.0.0 ./librspreload.so.1

clean:
	rm -f $(MAIN) librdmacm.so.1 librdmacm.so $(RSPRELOAD_SO) librspreload.so.1 librspreload.so
install:
	cp ./librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1.0.0
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so.1
	ln -s -f /usr/lib/librdmacm.so.1.0.0 /usr/lib/librdmacm.so
	cp ./librspreload.so.1.0.0 /usr/lib/librspreload.so.1.0.0
	ln -s -f /usr/lib/librspreload.so.1.0.0 /usr/lib/librspreload.so.1
	ln -s -f /usr/lib/librspreload.so.1.0.0 /usr/lib/librspreload.so
	mkdir -p /usr/include/rdma
	cp ./include/rdma/* /usr/include/rdma
uninstall:
	rm -f /usr/lib/$(MAIN) /usr/lib/librdmacm.so.1 /usr/lib/librdmacm.so /usr/lib/$(RSOCKET_SO) /usr/lib/librspreload.so.1 /usr/lib/librspreload.so

.PHONY: module clean install uninstall
