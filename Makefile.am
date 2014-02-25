bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
TESTS =
BUILT_SOURCES =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I$(top_srcdir)/nmsg \
	-I$(top_builddir)/nmsg
AM_CFLAGS = \
	$(my_CFLAGS) \
	$(libpcap_CFLAGS) \
	$(libprotobuf_c_CFLAGS) \
	$(libwdns_CFLAGS) \
	$(libxs_CFLAGS) \
	$(jansson_CFLAGS) \
	$(yaml_CFLAGS) \
	$(msgpack_CFLAGS) \
	$(libxml2_CFLAGS)
AM_LDFLAGS = \
	-Wl,--as-needed

EXTRA_DIST += ChangeLog
EXTRA_DIST += COPYRIGHT
EXTRA_DIST += README.md
EXTRA_DIST += tests

pkgconfig_DATA = nmsg/libnmsg.pc
EXTRA_DIST += nmsg/libnmsg.pc.in
CLEANFILES += nmsg/libnmsg.pc

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

include_HEADERS = nmsg/nmsg.h
nobase_include_HEADERS = \
	nmsg/alias.h \
	nmsg/asprintf.h \
	nmsg/chalias.h \
	nmsg/compat.h \
	nmsg/constants.h \
	nmsg/container.h \
	nmsg/input.h \
	nmsg/io.h \
	nmsg/ipdg.h \
	nmsg/message.h \
	nmsg/msgmod.h \
	nmsg/msgmod_plugin.h \
	nmsg/output.h \
	nmsg/pcap_input.h \
	nmsg/random.h \
	nmsg/rate.h \
	nmsg/res.h \
	nmsg/sock.h \
	nmsg/strbuf.h \
	nmsg/timespec.h \
	nmsg/vendors.h \
	nmsg/zbuf.h
nobase_nodist_include_HEADERS = \
	nmsg/nmsg.pb-c.h

lib_LTLIBRARIES = nmsg/libnmsg.la

VERSION_INFO = 6:0:0

nmsg_libnmsg_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_[a-z].*)"
nmsg_libnmsg_la_LIBADD = \
	$(libpcap_LIBS) \
	$(libprotobuf_c_LIBS) \
	$(libxs_LIBS)
nmsg_libnmsg_la_SOURCES = \
	libmy/crc32c.c libmy/crc32c.h libmy/crc32c-slicing.c libmy/crc32c-sse42.c \
	libmy/list.h \
	libmy/tree.h \
	nmsg/alias.c \
	nmsg/asprintf.c \
	nmsg/brate.c \
	nmsg/buf.c \
	nmsg/chalias.c \
	nmsg/container.c \
	nmsg/dlmod.c \
	nmsg/input.c \
	nmsg/input_callback.c \
	nmsg/input_frag.c \
	nmsg/input_nmsg.c \
	nmsg/input_nullnmsg.c \
	nmsg/input_pcap.c \
	nmsg/input_pres.c \
	nmsg/input_seqsrc.c \
	nmsg/io.c \
	nmsg/ipdg.c \
	nmsg/ipreasm.c \
	nmsg/ipreasm.h \
	nmsg/msgmodset.c \
	nmsg/nmsg.c \
	nmsg/nmsg_port_net.h \
	nmsg/output.c \
	nmsg/output_frag.c \
	nmsg/output_nmsg.c \
	nmsg/output_pres.c \
	nmsg/payload.c \
	nmsg/pcap_input.c \
	nmsg/private.h \
	nmsg/random.c \
	nmsg/rate.c \
	nmsg/res.c \
	nmsg/sock.c \
	nmsg/strbuf.c \
	nmsg/timespec.c \
	nmsg/xsio.c \
	nmsg/zbuf.c \
	nmsg/msgmod/lookup.c \
	nmsg/msgmod/message.c \
	nmsg/msgmod/msgmod.c \
	nmsg/msgmod/transparent.c \
	nmsg/msgmod/transparent.h \
	nmsg/msgmod/transparent_message.c \
	nmsg/msgmod/transparent_module.c \
	nmsg/msgmod/transparent_payload.c \
	nmsg/msgmod/transparent_pres.c
nodist_nmsg_libnmsg_la_SOURCES = \
	nmsg/nmsg.pb-c.c \
	nmsg/nmsg.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_libnmsg_la_SOURCES)
CLEANFILES += $(nodist_nmsg_libnmsg_la_SOURCES)

MSG_LIBTOOL_FLAGS = -module -avoid-version -shared -export-symbols-regex "^(nmsg_msgmod_ctx|nmsg_msgmod_ctx_array)$$"

moduledir = $(libdir)/nmsg
protodir = $(pkgdatadir)/base

nobase_include_HEADERS += \
	nmsg/base/defs.h
nobase_nodist_include_HEADERS += \
	nmsg/base/dns.pb-c.h \
	nmsg/base/dnsqr.pb-c.h \
	nmsg/base/email.pb-c.h \
	nmsg/base/encode.pb-c.h \
	nmsg/base/http.pb-c.h \
	nmsg/base/ipconn.pb-c.h \
	nmsg/base/linkpair.pb-c.h \
	nmsg/base/logline.pb-c.h \
	nmsg/base/ncap.pb-c.h \
	nmsg/base/packet.pb-c.h \
	nmsg/base/pkt.pb-c.h \
	nmsg/base/xml.pb-c.h

proto_DATA =  \
	nmsg/base/dns.proto \
	nmsg/base/dnsqr.proto \
	nmsg/base/email.proto \
	nmsg/base/encode.proto \
	nmsg/base/http.proto \
	nmsg/base/ipconn.proto \
	nmsg/base/linkpair.proto \
	nmsg/base/logline.proto \
	nmsg/base/ncap.proto \
	nmsg/base/packet.proto \
	nmsg/base/pkt.proto \
	nmsg/base/xml.proto
EXTRA_DIST += $(proto_DATA)
EXTRA_DIST += nmsg/nmsg.proto

module_LTLIBRARIES = nmsg/base/nmsg_msg8_base.la

nmsg_base_nmsg_msg8_base_la_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_builddir)/nmsg/base \
	-Wno-unused-parameter
nmsg_base_nmsg_msg8_base_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(MSG_LIBTOOL_FLAGS)
nmsg_base_nmsg_msg8_base_la_LIBADD = \
	$(libpcap_LIBS) \
	$(libwdns_LIBS) \
	$(jansson_LIBS) \
	$(yaml_LIBS) \
	$(msgpack_LIBS) \
	$(libxml2_LIBS)
nmsg_base_nmsg_msg8_base_la_SOURCES = \
	libmy/list.h \
	libmy/lookup3.c \
	libmy/lookup3.h \
	libmy/my_alloc.h \
	libmy/string_replace.h \
	libmy/ubuf.h \
	libmy/vector.h \
	nmsg/base/nmsg_msg_base.c \
	nmsg/base/ipreasm.c
nodist_nmsg_base_nmsg_msg8_base_la_SOURCES = \
	nmsg/base/dns.pb-c.c nmsg/base/dns.pb-c.h \
	nmsg/base/dnsqr.pb-c.c nmsg/base/dnsqr.pb-c.h \
	nmsg/base/email.pb-c.c nmsg/base/email.pb-c.h \
	nmsg/base/encode.pb-c.c nmsg/base/encode.pb-c.h \
	nmsg/base/http.pb-c.c nmsg/base/http.pb-c.h \
	nmsg/base/ipconn.pb-c.c nmsg/base/ipconn.pb-c.h \
	nmsg/base/linkpair.pb-c.c nmsg/base/linkpair.pb-c.h \
	nmsg/base/logline.pb-c.c nmsg/base/logline.pb-c.h \
	nmsg/base/ncap.pb-c.c nmsg/base/ncap.pb-c.h \
	nmsg/base/packet.pb-c.c nmsg/base/packet.pb-c.h \
	nmsg/base/pkt.pb-c.c nmsg/base/pkt.pb-c.h \
	nmsg/base/xml.pb-c.c nmsg/base/xml.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_base_nmsg_msg8_base_la_SOURCES)
CLEANFILES += $(nodist_nmsg_base_nmsg_msg8_base_la_SOURCES)
EXTRA_DIST += \
	nmsg/base/dns.c \
	nmsg/base/dnsqr.c \
	nmsg/base/email.c \
	nmsg/base/encode.c \
	nmsg/base/http.c \
	nmsg/base/ipconn.c \
	nmsg/base/ipreasm.h \
	nmsg/base/linkpair.c \
	nmsg/base/logline.c \
	nmsg/base/ncap.c \
	nmsg/base/packet.c \
	nmsg/base/pkt.c \
	nmsg/base/xml.c

bin_PROGRAMS += src/nmsgtool
src_nmsgtool_LDADD = \
	nmsg/libnmsg.la \
	$(libpcap_LIBS) \
	$(libxs_LIBS)
src_nmsgtool_SOURCES = \
	libmy/argv.c \
	libmy/argv.h \
	libmy/argv_loc.h \
	src/daemon.c \
	src/getsock.c \
	src/io.c \
	src/kickfile.c \
	src/kickfile.h \
	src/nmsgtool.c \
	src/nmsgtool.h \
	src/process_args.c \
	src/rwfile.c \
	src/unescape.c

noinst_PROGRAMS += libmy/crc32c_test
libmy_crc32c_test_CFLAGS = $(AM_CFLAGS)
libmy_crc32c_test_SOURCES = \
	libmy/crc32c.c libmy/crc32c.h libmy/crc32c-slicing.c libmy/crc32c-sse42.c \
	libmy/crc32c_test.c

EXTRA_DIST += examples/email_client_postfix.py
noinst_PROGRAMS += \
	examples/email_client \
	examples/http_client \
	examples/ipconn_client \
	examples/nmsg_callback \
	examples/print_srcip \
	examples/nmsg-dnsqr2pcap \
	examples/nmsg-packet2pcap

examples_email_client_LDADD = nmsg/libnmsg.la
examples_email_client_SOURCES = examples/email_client.c

examples_http_client_LDADD = nmsg/libnmsg.la
examples_http_client_SOURCES = examples/http_client.c

examples_ipconn_client_LDADD = nmsg/libnmsg.la
examples_ipconn_client_SOURCES = examples/ipconn_client.c

examples_nmsg_callback_LDADD = nmsg/libnmsg.la
examples_nmsg_callback_SOURCES = examples/nmsg_callback.c

examples_print_srcip_LDADD = nmsg/libnmsg.la
examples_print_srcip_SOURCES = examples/print_srcip.c

examples_nmsg_dnsqr2pcap_LDADD = \
	nmsg/libnmsg.la \
	$(libpcap_LIBS)
examples_nmsg_dnsqr2pcap_SOURCES = examples/nmsg-dnsqr2pcap.c

examples_nmsg_packet2pcap_LDADD = \
	nmsg/libnmsg.la \
	$(libpcap_LIBS)
examples_nmsg_packet2pcap_SOURCES = examples/nmsg-packet2pcap.c

if BUILD_MAN
dist_man_MANS = doc/docbook/nmsgtool.1
DOCBOOK_XSL = http://docbook.sourceforge.net/release/xsl-ns/current/manpages/docbook.xsl
doc/docbook/nmsgtool.1: doc/docbook/nmsgtool.docbook
	$(AM_V_GEN) $(XSLTPROC) $(XSLTPROC_FLAGS) --output doc/docbook/ $(DOCBOOK_XSL) $<
endif
EXTRA_DIST += doc/docbook/nmsgtool.docbook

if HAVE_DOXYGEN
html-local: doc/doxygen/Doxyfile
	$(AM_V_GEN) cd doc/doxygen && $(DOXYGEN)
endif
EXTRA_DIST += doc/doxygen/doxygen-input-filter

clean-local:
	rm -rf doc/doxygen/html
	rm -f doc/doxygen/doxygen.warnings

install-data-hook:
	rm -rf $(DESTDIR)$(includedir)/nmsg/isc
	$(LN_S) -f base $(DESTDIR)$(includedir)/nmsg/isc

TESTS += tests/nmsg.test
