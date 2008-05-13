TARGET := libscvpcli.so

COMMON_DIR = ../common
SOURCES	:= $(COMMON_DIR)/scvp_proto.c $(COMMON_DIR)/channel.c $(COMMON_DIR)/cache.c scvp_cli.c

CFLAGS  := -g0 -O3 -Wall -D_GNU_SOURCE
LDFLAGS +=

GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS := $(shell pkg-config --libs glib-2.0)

LIBTASN1_CFLAGS :=
LIBTASN1_LDFLAGS :=

OPENSSL_CFLAGS :=
OPENSSL_LDFLAGS :=

LIB_CFLAGS := -I$(COMMON_DIR) $(GLIB_CFLAGS) $(LIBTASN1_CFLAGS) $(OPENSSL_CFLAGS) -fPIC
LIB_LDFLAGS := -shared $(GLIB_LDFLAGS) $(LIBTASN1_LDFLAGS) $(OPENSSL_LDFLAGS)

COMMON_SOURCES := $(patsubst $(COMMON_DIR)/%.c,%.o,$(SOURCES)) 
OBJS := $(COMMON_SOURCES:.c=.o)

.PHONY: all clean

$(TARGET): $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(LIB_LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(LIB_CFLAGS) -o $@ $<
	
%.o: $(COMMON_DIR)/%.c
	$(CC) -c $(CFLAGS) $(LIB_CFLAGS) -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS)
