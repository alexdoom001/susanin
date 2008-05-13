TARGET := path_test

LIBDIR = ../library
SOURCES	:= path_test.cpp

CFLAGS  := -g0 -O3 -Wall
LDFLAGS +=

GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
GLIB_LDFLAGS := $(shell pkg-config --libs glib-2.0)

LIBTASN1_CFLAGS :=
LIBTASN1_LDFLAGS := -ltasn1

OPENSSL_CFLAGS :=
OPENSSL_LDFLAGS := -lcrypto

CLIENT_CFLAGS := -I$(LIBDIR) $(GLIB_CFLAGS) $(OPENSSL_CFLAGS)
CLIENT_LDFLAGS := $(GLIB_LDFLAGS) $(OPENSSL_LDFLAGS) -L$(LIBDIR) -lscvpcli $(LIBTASN1_LDFLAGS) -lrt -lpthread

OBJS  := $(SOURCES:.cpp=.o)

.PHONY: all clean

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS) $(CLIENT_LDFLAGS)

%.o: %.cpp
	$(CXX) -c $(CFLAGS) $(CLIENT_CFLAGS) -o $@ $<
	
clean:
	$(RM) $(TARGET) $(OBJS)
