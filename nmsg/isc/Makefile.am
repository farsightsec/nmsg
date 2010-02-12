AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

MSG_LIBTOOL_FLAGS = -module -avoid-version -export-symbols-regex "^(nmsg_msgmod_ctx|nmsg_msgmod_ctx_array)$$"

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

.proto.pb-c.h:
	protoc-c --c_out="`dirname $@`" $<

moduledir = $(libdir)/nmsg
protodir = $(pkgdatadir)/isc

EXTRA_DIST = \
	dns.c \
	dns.pb-c.c \
	dns.pb-c.h \
	dns.proto \
	email.c \
	email.pb-c.c \
	email.pb-c.h \
	email.proto \
	http.c \
	http.pb-c.c \
	http.pb-c.h \
	http.proto \
	ipconn.c \
	ipconn.pb-c.c \
	ipconn.pb-c.h \
	ipconn.proto \
	linkpair.c \
	linkpair.pb-c.c \
	linkpair.pb-c.h \
	linkpair.proto \
	logline.c \
	logline.pb-c.c \
	logline.pb-c.h \
	logline.proto \
	ncap.c \
	ncap.pb-c.c \
	ncap.pb-c.h \
	ncap.proto

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
	@libprotobuf_c_cflags@ \
	@libwdns_cflags@
nmsg_msg_isc_la_LDFLAGS = \
	$(MSG_LIBTOOL_FLAGS) \
	@libprotobuf_c_ldflags@ \
	@libwdns_ldflags@
nmsg_msg_isc_la_LIBADD = \
	@libprotobuf_c_libadd@ \
	@libwdns_libadd@
nmsg_msg_isc_la_SOURCES = nmsg_msg_isc.c

if INTERNAL_LIBWDNS
if INTERNAL_LIBUSTR
nmsg_msg_isc_la_LIBADD += @libustr_libadd@
endif
endif

protobuf: \
	dns.pb-c.c \
	email.pb-c.c \
	http.pb-c.c \
	ipconn.pb-c.c \
	linkpair.pb-c.c \
	logline.pb-c.c \
	ncap.pb-c.c

.PHONY: protobuf
