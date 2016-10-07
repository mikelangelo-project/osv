CC=gcc
CFLAGS=-O2 -g -Wall -DIBV_CONFIG_DIR=\"/etc/libibverbs.d\" -std=gnu99 -DHAVE_CONFIG_H
INCLUDES=-I./include -I./ -I../../include/glibc-compat/ -I../../bsd/sys/ -I../../../osv/build/release.x64/gen/include -I../../bsd/x64/ -I../../include/api/ -I../../include/api/x64/ -I../../

LINK=-L./

MAIN_SRCS=cmd.c compat-1_0.c device.c devinfo.c enum_strs.c init.c marshall.c memory.c sysfs.c verbs.c
MAIN=libibverbs.so.1.0.0
DEVINFO_SRCS=devinfo.c
DEVINFO=ibv_devinfo.so

module: $(MAIN) $(DEVINFO)

$(MAIN): $(SRCS)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $(MAIN_SRCS) $(LFLAGS) $(LIBS) -ldl -pthread
	ln -s -f ./libibverbs.so.1.0.0 ./libibverbs.so

$(DEVINFO): $(DEVINFO_SRC)
	$(CC) -DOSV_CLI $(CFLAGS) $(INCLUDES) $(LINK) -fPIC -shared -o $@ $(DEVINFO_SRCS) $(LFLAGS) $(LIBS) -pthread -libverbs -ldl

clean:
	rm -f $(MAIN) $(DEVINFO) ./libibverbs.so

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
