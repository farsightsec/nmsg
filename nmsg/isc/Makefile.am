AM_CFLAGS = @EXTRA_CFLAGS@ -Wno-unused
INCLUDES = -I@top_srcdir@ -I@top_srcdir@/nmsg

MSG_LIBTOOL_FLAGS = -module -avoid-version -export-symbols-regex "^(nmsg_msgmod_ctx|nmsg_msgmod_ctx_array)$$"

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

.proto.pb-c.h:
	protoc-c --c_out="`dirname $@`" $<

moduledir = $(libdir)/nmsg
protodir = $(pkgdatadir)/isc

nmsgiscincludedir = $(pkgincludedir)/isc

nobase_nmsgiscinclude_HEADERS = \
	defs.h \
	dns.pb-c.h \
	dnsqr.pb-c.h \
	email.pb-c.h \
	http.pb-c.h \
	ipconn.pb-c.h \
	linkpair.pb-c.h \
	logline.pb-c.h \
	ncap.pb-c.h \
	pkt.pb-c.h \
	xml.pb-c.h

EXTRA_DIST = \
	dns.c \
	dns.pb-c.c \
	dns.proto \
	dnsqr.c \
	dnsqr.pb-c.c \
	dnsqr.proto \
	email.c \
	email.pb-c.c \
	email.proto \
	http.c \
	http.pb-c.c \
	http.proto \
	ipconn.c \
	ipconn.pb-c.c \
	ipconn.proto \
	ipreasm.h \
	linkpair.c \
	linkpair.pb-c.c \
	linkpair.proto \
	lookup3.h \
	logline.c \
	logline.pb-c.c \
	logline.proto \
	ncap.c \
	ncap.pb-c.c \
	ncap.proto \
	pkt.c \
	pkt.pb-c.c \
	pkt.proto \
	xml.c \
	xml.pb-c.c \
	xml.proto

proto_DATA =  \
	dns.proto \
	dnsqr.proto \
	email.proto \
	http.proto \
	ipconn.proto \
	linkpair.proto \
	logline.proto \
	ncap.proto \
	pkt.proto \
	xml.proto

module_LTLIBRARIES = nmsg_msg7_isc.la

nmsg_msg7_isc_la_CFLAGS = \
	$(AM_CFLAGS) \
	@libprotobuf_c_cflags@ \
	@libwdns_cflags@
nmsg_msg7_isc_la_LDFLAGS = \
	$(MSG_LIBTOOL_FLAGS) \
	@libprotobuf_c_ldflags@ \
	@libwdns_ldflags@
nmsg_msg7_isc_la_LIBADD = \
	@libprotobuf_c_libadd@ \
	@libwdns_libadd@
nmsg_msg7_isc_la_SOURCES = nmsg_msg_isc.c lookup3.c ipreasm.c

if INTERNAL_LIBWDNS
if INTERNAL_LIBUSTR
nmsg_msg7_isc_la_LIBADD += @libustr_libadd@
endif
endif

protobuf: \
	dns.pb-c.c \
	dnsqr.pb-c.c \
	email.pb-c.c \
	http.pb-c.c \
	ipconn.pb-c.c \
	linkpair.pb-c.c \
	logline.pb-c.c \
	ncap.pb-c.c \
	pkt.pb-c.c \
	xml.pb-c.c

.PHONY: protobuf
