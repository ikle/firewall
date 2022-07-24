DESCRIPTION = Linux Firewall Configurator
URL = https://github.com/ikle/firewall

LIBVER	= 0
LIBREV	= 0.4

DEPENDS	= glib-2.0 libcrypto libipset libiptc

LDFLAGS	+= -Wl,--as-needed
LDFLAGS	+= -lpcap

include make-core.mk
