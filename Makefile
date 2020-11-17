DESCRIPTION = Linux Firewall Configurator
URL = https://github.com/ikle/firewall

LIBVER	= 0
LIBREV	= 0.1

DEPENDS	= glib-2.0 libcrypto libiptc

LDFLAGS	+= -Wl,--as-needed
LDFLAGS	+= -lpcap

include make-core.mk
