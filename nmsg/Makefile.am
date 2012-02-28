SUBDIRS = msgmod . isc

VERSION_INFO = 6:0:0

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	protoc-c --c_out="`dirname $@`" $<

.proto.pb-c.h:
	protoc-c --c_out="`dirname $@`" $<

include_HEADERS = nmsg.h

nobase_pkginclude_HEADERS = \
	alias.h \
	asprintf.h \
	chalias.h \
	constants.h \
	crc32c.h \
	input.h \
	io.h \
	ipdg.h \
	list.h \
	message.h \
	msgmod.h \
	msgmod_plugin.h \
	nmsg.pb-c.h \
	output.h \
	pcap_input.h \
	random.h \
	rate.h \
	res.h \
	sock.h \
	strbuf.h \
	timespec.h \
	tree.h \
	vendors.h \
	zbuf.h

EXTRA_DIST = \
	ipreasm.h \
	msgmod_plugin.h \
	nmsg.proto \
	nmsg_port_net.h \
	private.h

lib_LTLIBRARIES = libnmsg.la

libnmsg_la_CFLAGS = \
	$(AM_CFLAGS) \
	@libpcap_cflags@ \
	@libprotobuf_c_cflags@ \
	@libustr_cflags@ \
	@libz_cflags@ \
	@libzmq_cflags@
libnmsg_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_[a-z].*)" \
	@libpcap_ldflags@ \
	@libprotobuf_c_ldflags@ \
	@libustr_ldflags@ \
	@libz_ldflags@ \
	@libzmq_ldflags@
libnmsg_la_LIBADD = \
	msgmod/libnmsg_msgmod.la \
	@libprotobuf_c_libadd@ \
	@libustr_libadd@
libnmsg_la_SOURCES = \
	alias.c \
	asprintf.c \
	brate.c \
	buf.c \
	chalias.c \
	container.c \
	crc32c.c \
	dlmod.c \
	input.c \
	input_callback.c \
	input_frag.c \
	input_nmsg.c \
	input_nullnmsg.c \
	input_pcap.c \
	input_pres.c \
	input_seqsrc.c \
	io.c \
	ipdg.c \
	ipreasm.c \
	msgmodset.c \
	nmsg.c \
	nmsg.pb-c.c \
	output.c \
	output_frag.c \
	output_nmsg.c \
	output_pres.c \
	payload.c \
	pcap_input.c \
	random.c \
	rate.c \
	res.c \
	sock.c \
	strbuf.c \
	timespec.c \
	zbuf.c \
	zmqio.c

protobuf: nmsg.pb-c.c

.PHONY: protobuf
