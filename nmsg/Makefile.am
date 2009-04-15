SUBDIRS = . isc

VERSION_INFO = 4:0:0

AM_CFLAGS = @EXTRA_CFLAGS@
INCLUDES = -I@top_srcdir@

include_HEADERS = nmsg.h

nobase_pkginclude_HEADERS = \
	asprintf.h \
	constants.h \
	fma.h \
	google/protobuf-c/protobuf-c-private.h \
	google/protobuf-c/protobuf-c.h \
	input.h \
	io.h \
	ipdg.h \
	ipreasm.h \
	list.h \
	nmsg.pb-c.h \
	output.h \
	payload.h \
	pbmod.h \
	pbmodset.h \
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
	pbmod_pbuf.c \
	pbmod_pres.c \
	pcap_input.c \
	private.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_.*|protobuf_c_.*)" \
	-lpcap
libnmsg_la_SOURCES = \
	asprintf.c \
	buf.c \
	dlmod.c \
	fma.c \
	google/protobuf-c/protobuf-c.c \
	input.c \
	io.c \
	ipdg.c \
	ipreasm.c \
	nmsg.pb-c.c \
	output.c \
	payload.c \
	pbmod.c \
	pbmodset.c \
	pcap_input.c \
	rate.c \
	res.c \
	strbuf.c \
	timespec.c \
	zbuf.c
