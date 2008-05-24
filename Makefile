all: susanin libscvpcli.so rehash

GLIB_INCLUDES := $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS := $(shell pkg-config --libs glib-2.0)
override CFLAGS+=-g -D_GNU_SOURCE -Wall $(GLIB_INCLUDES) -Icommon -Isusanin -Ilibrary -Iclient -fPIC -fvisibility=hidden \
 -I/home/user/Desktop/workspace/libtasn1-3.4/lib -I/usr/local/ssl/include

susanin: common/scvp_defs.o common/scvp_proto.o common/channel.o common/cache.o \
	susanin/crypto_openssl.o susanin/logger.o susanin/config.o susanin/ocsp_verify.o \
	susanin/path_checker.o susanin/connection.o susanin/susanin.o susanin/update_chain.o
	$(CC) -o susanin/$@ $^ $(LDFLAGS) $(GLIB_LIBS) -lcrypto -lssl -lrt -lpthread -ldl -lcurl -ltasn1

libscvpcli.so: common/scvp_defs.o common/scvp_proto.o common/channel.o common/cache.o library/scvp_cli.o
	$(CC) -o library/libscvpcli.so.1 $^ -shared $(LDFLAGS) $(GLIB_LIBS) -lcrypto -ltasn1 -Wl,-soname,libscvpcli.so.1
	ln -sf libscvpcli.so.1 library/libscvpcli.so

rehash: common/scvp_defs.o common/cache.o rehash/rehash.o
	$(CC) -o rehash/$@ $^ $(LDFLAGS) $(GLIB_LIBS) -lcrypto

path_test: client/path_test.o
	$(CC) -o client/$@ $^ $(LDFLAGS) $(GLIB_LIBS) -Llibrary -lscvpcli -lcrypto -lpthread

clean:
	rm -f */*.o */*.*~ susanin/susanin library/libscvpcli.so.1 library/libscvpcli.so rehash/rehash client/path_test

install_susanin:
	install -d $(DESTDIR)/usr/sbin
	install -m 0755 susanin/susanin $(DESTDIR)/usr/sbin

install_rehash:
	install -d $(DESTDIR)/usr/sbin
	install -m 0755 rehash/rehash $(DESTDIR)/usr/sbin

install_scvpcli:
	install -d $(DESTDIR)/usr/lib
	install -m 0755 library/libscvpcli.so.1 $(DESTDIR)/usr/lib
	cp -d library/libscvpcli.so $(DESTDIR)/usr/lib
	install -d $(DESTDIR)/usr/include
	install -m 0644 library/scvp_cli.h $(DESTDIR)/usr/include

.PHONY: all clean susanin libscvpcli.so rehash path_test install_susanin install_rehash install_scvpcli
