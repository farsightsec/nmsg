SUBDIRS = . isc

AM_CFLAGS = @EXTRA_CFLAGS@
VERSION_INFO = 4:0:0

include_HEADERS = nmsg.h

nobase_pkginclude_HEADERS = \
	asprintf.h \
	constants.h \
	fma.h \
	input.h \
	io.h \
	ipdg.h \
	ipreasm.h \
	nmsg.pb-c.h \
	output.h \
	payload.h \
	pbmod.h \
	pbmodset.h \
	protobuf-c-private.h \
	protobuf-c.h \
	rate.h \
	res.h \
	strbuf.h \
	timespec.h \
	vendors.h \
	zbuf.h

EXTRA_DIST = \
	input_frag.c \
	input_pcap.c \
	io_nmsg_read.c \
	io_pcap_read.c \
	io_pres_read.c \
	io_private.c \
	nmsg.proto \
	nmsg_port.h \
	nmsg_port_net.h \
	pbmod_pbuf.c \
	pbmod_pres.c \
	private.h \
	tree.h

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
	input.c \
	io.c \
	ipdg.c \
	ipreasm.c \
	nmsg.pb-c.c \
	output.c \
	payload.c \
	pbmod.c \
	pbmodset.c \
	protobuf-c.c \
	rate.c \
	strbuf.c \
	timespec.c \
	zbuf.c
