AM_CFLAGS = @EXTRA_CFLAGS@

SUBDIRS =

if INTERNAL_LIBUSTR
SUBDIRS += ustr
endif

SUBDIRS += wdns examples

include_HEADERS = wdns.h

EXTRA_DIST = \
	LICENSE \
	pywdns/Makefile \
	pywdns/README \
	pywdns/wdns.c \
	pywdns/wdns.pxi \
	pywdns/wdns.pyx \
	pywdns/setup.py
