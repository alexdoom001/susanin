TARGET := susanin

COMMON_DIR = ../common
SOURCES	:= $(COMMON_DIR)/scvp_proto.c $(COMMON_DIR)/channel.c $(COMMON_DIR)/cache.c crypto_openssl.o logger.o config.o ocsp_verify.o \
 path_checker.o connection.o susanin.o

CFLAGS  := -g0 -O3 -Wall -D_GNU_SOURCE
LDFLAGS +=

GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS := $(shell pkg-config --libs glib-2.0)

LIBTASN1_CFLAGS :=
LIBTASN1_LDFLAGS := -ltasn1

OPENSSL_CFLAGS :=
OPENSSL_LDFLAGS := -lcrypto

SUSANIN_CFLAGS := -I$(COMMON_DIR) $(GLIB_CFLAGS) $(LIBTASN1_CFLAGS) $(OPENSSL_CFLAGS)
SUSANIN_LDFLAGS := $(GLIB_LDFLAGS) $(LIBTASN1_LDFLAGS) $(OPENSSL_LDFLAGS) -lrt -lpthread -ldl -lcurl

COMMON_SOURCES := $(patsubst $(COMMON_DIR)/%.c,%.o,$(SOURCES)) 
OBJS := $(COMMON_SOURCES:.c=.o)

.PHONY: all clean

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(SUSANIN_LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(SUSANIN_CFLAGS) -o $@ $<
	
%.o: $(COMMON_DIR)/%.c
	$(CC) -c $(CFLAGS) $(SUSANIN_CFLAGS) -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS)
