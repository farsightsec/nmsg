AM_CFLAGS = @EXTRA_CFLAGS@

SUBDIRS =

if INTERNAL_LIBUSTR
SUBDIRS += ustr
endif

SUBDIRS += wdns examples

include_HEADERS = wdns.h

pywdns/wdns_constants.py: wdns/constants.h pywdns/gen_pywdns_constants
	pywdns/gen_pywdns_constants

EXTRA_DIST = \
	LICENSE \
	pywdns/Makefile \
	pywdns/README \
	pywdns/wdns.c \
	pywdns/wdns.pxi \
	pywdns/wdns.pyx \
	pywdns/wdns_constants.py \
	pywdns/setup.py
