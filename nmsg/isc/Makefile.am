AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

NMSGPB_LIBTOOL_FLAGS = -module -avoid-version

SUFFIXES = .proto .pb-c.c

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

moduledir = $(libdir)/nmsg

pbnmsgiscincludedir = $(pkgincludedir)/isc

nobase_pbnmsgiscinclude_HEADERS = \
	email.pb-c.h \
	http.pb-c.h \
	ipconn.pb-c.h \
	linkpair.pb-c.h \
	logline.pb-c.h \
	ncap.pb-c.h \
	nmsgpb_isc_email.h \
	nmsgpb_isc_http.h \
	nmsgpb_isc_ipconn.h \
	nmsgpb_isc_linkpair.h \
	nmsgpb_isc_logline.h \
	nmsgpb_isc_ncap.h

EXTRA_DIST = \
	email.pb-c.c \
	email.proto \
	http.pb-c.c \
	http.proto \
	ipconn.pb-c.c \
	ipconn.proto \
	linkpair.pb-c.c \
	linkpair.proto \
	logline.pb-c.c \
	logline.proto \
	ncap.pb-c.c \
	ncap.proto \
	nmsgpb_isc_email.c \
	nmsgpb_isc_http.c \
	nmsgpb_isc_ipconn.c \
	nmsgpb_isc_linkpair.c \
	nmsgpb_isc_logline.c \
	nmsgpb_isc_ncap.c

module_LTLIBRARIES = nmsgpb_isc.la
#nmsgpb_isc_email.la \
#nmsgpb_isc_http.la \
#nmsgpb_isc_ipconn.la \
#nmsgpb_isc_linkpair.la \
#nmsgpb_isc_logline.la \
#nmsgpb_isc_ncap.la

#nmsgpb_isc_email_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_email_la_SOURCES = nmsgpb_isc_email.c

#nmsgpb_isc_http_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_http_la_SOURCES = nmsgpb_isc_http.c

#nmsgpb_isc_ipconn_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_ipconn_la_SOURCES = nmsgpb_isc_ipconn.c

#nmsgpb_isc_linkpair_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_linkpair_la_SOURCES = nmsgpb_isc_linkpair.c

#nmsgpb_isc_logline_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_logline_la_SOURCES = nmsgpb_isc_logline.c

#nmsgpb_isc_ncap_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
#nmsgpb_isc_ncap_la_SOURCES = nmsgpb_isc_ncap.c

nmsgpb_isc_la_LDFLAGS = $(NMSGPB_LIBTOOL_FLAGS)
nmsgpb_isc_la_SOURCES = nmsgpb_isc.c
