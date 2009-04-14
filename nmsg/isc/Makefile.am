AM_CFLAGS = @EXTRA_CFLAGS@

moduledir = $(libdir)/nmsg

pbnmsgiscincludedir = $(pkgincludedir)/isc

nobase_pbnmsgiscinclude_HEADERS = \
	email.pb-c.h \
	http.pb-c.h \
	ipconn.pb-c.h \
	linkpair.pb-c.h \
	pbnmsg_isc_email.h \
	pbnmsg_isc_http.h \
	pbnmsg_isc_ipconn.h \
	pbnmsg_isc_linkpair.h

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
	pbnmsg_isc_email.la \
	pbnmsg_isc_linkpair.la \
	pbnmsg_isc_http.la \
	pbnmsg_isc_ipconn.la \
	pbnmsg_isc_ncap.la

INCLUDES = -I$(top_srcdir)/nmsg

pbnmsg_isc_email_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_email_la_SOURCES = \
	pbnmsg_isc_email.c \
	pbnmsg_isc_email.h \
	email.pb-c.h

pbnmsg_isc_linkpair_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_linkpair_la_SOURCES = \
	pbnmsg_isc_linkpair.c \
	pbnmsg_isc_linkpair.h \
	linkpair.pb-c.h

pbnmsg_isc_http_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_http_la_SOURCES = \
	pbnmsg_isc_http.c \
	pbnmsg_isc_http.h \
	http.pb-c.h

pbnmsg_isc_ipconn_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_ipconn_la_SOURCES = \
	pbnmsg_isc_ipconn.c \
	pbnmsg_isc_ipconn.h \
	ipconn.pb-c.h

pbnmsg_isc_ncap_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_ncap_la_SOURCES = \
	pbnmsg_isc_ncap.c \
	pbnmsg_isc_ncap.h \
	ncap.pb-c.h
