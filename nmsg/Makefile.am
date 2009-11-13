SUBDIRS = msgmod . isc

VERSION_INFO = 6:0:0

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@

SUFFIXES = .proto .pb-c.c

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

include_HEADERS = nmsg.h

nobase_pkginclude_HEADERS = \
	alias.h \
	asprintf.h \
	constants.h \
	dns.h \
	input.h \
	io.h \
	ipdg.h \
	ipreasm.h \
	list.h \
	message.h \
	msgmod.h \
	nmsg.pb-c.h \
	output.h \
	payload.h \
	pcap_input.h \
	rate.h \
	res.h \
	strbuf.h \
	timespec.h \
	tree.h \
	vendors.h \
	zbuf.h

EXTRA_DIST = \
	input_frag.c \
	input_read.c \
	nmsg.proto \
	nmsg_port.h \
	nmsg_port_net.h \
	output_write.c \
	pcap_input.c \
	private.h

lib_LTLIBRARIES = libnmsg.la

libnmsg_la_CFLAGS = \
	$(AM_CFLAGS) \
	@libbind_cflags@ \
	@libpcap_cflags@ \
	@libprotobuf_c_cflags@ \
	@libwdns_cflags@ \
	@zlib_cflags@
libnmsg_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_[a-z].*)" \
	@libbind_ldflags@ \
	@libpcap_ldflags@ \
	@zlib_ldflags@ \
	@libbind_libs@ \
	@libpcap_libs@ \
	@libprotobuf_c_ldflags@ \
	@libwdns_ldflags@ \
	@zlib_libs@
libnmsg_la_LIBADD = \
	msgmod/libnmsg_msgmod.la \
	@libprotobuf_c_libadd@ \
	@libwdns_libadd@
libnmsg_la_SOURCES = \
	alias.c \
	asprintf.c \
	buf.c \
	dlmod.c \
	dns.c \
	input.c \
	io.c \
	ipdg.c \
	ipreasm.c \
	msgmodset.c \
	nmsg.c \
	nmsg.pb-c.c \
	output.c \
	payload.c \
	pcap_input.c \
	rate.c \
	res.c \
	strbuf.c \
	timespec.c \
	zbuf.c
