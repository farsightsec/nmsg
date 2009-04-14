AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

moduledir = $(libdir)/nmsg

pbnmsgiscincludedir = $(pkgincludedir)/isc

nobase_pbnmsgiscinclude_HEADERS = \
	email.pb-c.h \
	http.pb-c.h \
	ipconn.pb-c.h \
	linkpair.pb-c.h \
	nmsgpb_isc_email.h \
	nmsgpb_isc_http.h \
	nmsgpb_isc_ipconn.h \
	nmsgpb_isc_linkpair.h

EXTRA_DIST = \
	email.pb-c.c \
	email.proto \
	http.pb-c.c \
	http.proto \
	ipconn.pb-c.c \
	ipconn.proto \
	linkpair.pb-c.c \
	linkpair.proto \
	ncap.pb-c.c \
	ncap.proto

module_LTLIBRARIES = \
	nmsgpb_isc_email.la \
	nmsgpb_isc_linkpair.la \
	nmsgpb_isc_http.la \
	nmsgpb_isc_ipconn.la \
	nmsgpb_isc_ncap.la

nmsgpb_isc_email_la_LDFLAGS = -module -avoid-version
nmsgpb_isc_email_la_SOURCES = \
	nmsgpb_isc_email.c \
	nmsgpb_isc_email.h \
	email.pb-c.h

nmsgpb_isc_linkpair_la_LDFLAGS = -module -avoid-version
nmsgpb_isc_linkpair_la_SOURCES = \
	nmsgpb_isc_linkpair.c \
	nmsgpb_isc_linkpair.h \
	linkpair.pb-c.h

nmsgpb_isc_http_la_LDFLAGS = -module -avoid-version
nmsgpb_isc_http_la_SOURCES = \
	nmsgpb_isc_http.c \
	nmsgpb_isc_http.h \
	http.pb-c.h

nmsgpb_isc_ipconn_la_LDFLAGS = -module -avoid-version
nmsgpb_isc_ipconn_la_SOURCES = \
	nmsgpb_isc_ipconn.c \
	nmsgpb_isc_ipconn.h \
	ipconn.pb-c.h

nmsgpb_isc_ncap_la_LDFLAGS = -module -avoid-version
nmsgpb_isc_ncap_la_SOURCES = \
	nmsgpb_isc_ncap.c \
	nmsgpb_isc_ncap.h \
	ncap.pb-c.h
