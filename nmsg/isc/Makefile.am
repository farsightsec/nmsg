AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

MSG_LIBTOOL_FLAGS = -module -avoid-version

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

.proto.pb-c.h:
	protoc-c --c_out="`dirname $@`" $<

moduledir = $(libdir)/nmsg
protodir = $(pkgdatadir)/isc

pbnmsgiscincludedir = $(pkgincludedir)/isc

nobase_pbnmsgiscinclude_HEADERS = \
	dns.pb-c.h \
	email.pb-c.h \
	http.pb-c.h \
	ipconn.pb-c.h \
	linkpair.pb-c.h \
	logline.pb-c.h \
	ncap.pb-c.h \
	nmsgpb_isc_ncap.h

EXTRA_DIST = \
	dns.c \
	dns.pb-c.c \
	dns.proto \
	email.c \
	email.pb-c.c \
	email.proto \
	http.c \
	http.pb-c.c \
	http.proto \
	ipconn.c \
	ipconn.pb-c.c \
	ipconn.proto \
	linkpair.c \
	linkpair.pb-c.c \
	linkpair.proto \
	logline.c \
	logline.pb-c.c \
	logline.proto \
	ncap.pb-c.c \
	ncap.proto \
	nmsgpb_isc_ncap.c

proto_DATA =  \
	dns.proto \
	email.proto \
	http.proto \
	ipconn.proto \
	linkpair.proto \
	logline.proto \
	ncap.proto

module_LTLIBRARIES = nmsg_msg_isc.la

nmsg_msg_isc_la_CFLAGS = \
	$(AM_CFLAGS) \
	@libprotobuf_c_cflags@
nmsg_msg_isc_la_LDFLAGS = $(MSG_LIBTOOL_FLAGS) -lwdns
nmsg_msg_isc_la_SOURCES = nmsg_msg_isc.c
