CC ?= cc
CFLAGS = -Wall -Wextra -O2 -fPIC
LDFLAGS = -shared

# libfido2 from Homebrew (also provides OpenSSL headers via its dependency)
FIDO2_PREFIX := $(shell brew --prefix libfido2 2>/dev/null || echo /opt/homebrew/opt/libfido2)
OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null || echo /opt/homebrew/opt/openssl)
CFLAGS += -I$(FIDO2_PREFIX)/include -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(FIDO2_PREFIX)/lib -lfido2 -L$(OPENSSL_PREFIX)/lib -lcrypto

# Output
LIB = libyubikey-sk.dylib
SRC = sk-yubikey.c
OBJ = $(SRC:.c=.o)

# Install path
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib

.PHONY: all clean install uninstall

all: $(LIB)

$(LIB): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c sk-api.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIB)

install: $(LIB)
	install -d $(LIBDIR)
	install -m 755 $(LIB) $(LIBDIR)/$(LIB)

uninstall:
	rm -f $(LIBDIR)/$(LIB)

# Debug build
debug: CFLAGS += -DDEBUG -g -O0
debug: clean all
