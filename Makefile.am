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
	-I${top_srcdir}/nmsg
AM_CFLAGS = \
	$(libpcap_CFLAGS) \
	$(libprotobuf_c_CFLAGS) \
	$(libwdns_CFLAGS) \
	$(libxs_CFLAGS)
AM_LDFLAGS = \
	-Wl,--as-needed

EXTRA_DIST += ChangeLog
EXTRA_DIST += COPYRIGHT
EXTRA_DIST += README
EXTRA_DIST += tests
EXTRA_DIST += doc/doxygen/html

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
	nmsg/constants.h \
	nmsg/input.h \
	nmsg/io.h \
	nmsg/ipdg.h \
	nmsg/message.h \
	nmsg/msgmod.h \
	nmsg/msgmod_plugin.h \
	nmsg/nmsg.pb-c.h \
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
protodir = $(pkgdatadir)/isc

nobase_include_HEADERS += \
	nmsg/isc/defs.h \
	nmsg/isc/dns.pb-c.h \
	nmsg/isc/dnsqr.pb-c.h \
	nmsg/isc/email.pb-c.h \
	nmsg/isc/encode.pb-c.h \
	nmsg/isc/http.pb-c.h \
	nmsg/isc/ipconn.pb-c.h \
	nmsg/isc/linkpair.pb-c.h \
	nmsg/isc/logline.pb-c.h \
	nmsg/isc/ncap.pb-c.h \
	nmsg/isc/pkt.pb-c.h \
	nmsg/isc/xml.pb-c.h

proto_DATA =  \
	nmsg/isc/dns.proto \
	nmsg/isc/dnsqr.proto \
	nmsg/isc/email.proto \
	nmsg/isc/encode.proto \
	nmsg/isc/http.proto \
	nmsg/isc/ipconn.proto \
	nmsg/isc/linkpair.proto \
	nmsg/isc/logline.proto \
	nmsg/isc/ncap.proto \
	nmsg/isc/pkt.proto \
	nmsg/isc/xml.proto
EXTRA_DIST += $(proto_DATA)
EXTRA_DIST += nmsg/nmsg.proto

module_LTLIBRARIES = nmsg/isc/nmsg_msg8_isc.la

nmsg_isc_nmsg_msg8_isc_la_CFLAGS = \
	$(AM_CFLAGS) \
	-Wno-unused-parameter
nmsg_isc_nmsg_msg8_isc_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(MSG_LIBTOOL_FLAGS)
nmsg_isc_nmsg_msg8_isc_la_LIBADD = \
	$(libwdns_LIBS)
nmsg_isc_nmsg_msg8_isc_la_SOURCES = \
	libmy/list.h \
	libmy/lookup3.c \
	libmy/lookup3.h \
	libmy/my_alloc.h \
	libmy/string_replace.h \
	libmy/ubuf.h \
	libmy/vector.h \
	nmsg/isc/nmsg_msg_isc.c \
	nmsg/isc/ipreasm.c
nodist_nmsg_isc_nmsg_msg8_isc_la_SOURCES = \
	nmsg/isc/dns.pb-c.c nmsg/isc/dns.pb-c.h \
	nmsg/isc/dnsqr.pb-c.c nmsg/isc/dnsqr.pb-c.h \
	nmsg/isc/email.pb-c.c nmsg/isc/email.pb-c.h \
	nmsg/isc/encode.pb-c.c nmsg/isc/encode.pb-c.h \
	nmsg/isc/http.pb-c.c nmsg/isc/http.pb-c.h \
	nmsg/isc/ipconn.pb-c.c nmsg/isc/ipconn.pb-c.h \
	nmsg/isc/linkpair.pb-c.c nmsg/isc/linkpair.pb-c.h \
	nmsg/isc/logline.pb-c.c nmsg/isc/logline.pb-c.h \
	nmsg/isc/ncap.pb-c.c nmsg/isc/ncap.pb-c.h \
	nmsg/isc/pkt.pb-c.c nmsg/isc/pkt.pb-c.h \
	nmsg/isc/xml.pb-c.c nmsg/isc/xml.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_isc_nmsg_msg8_isc_la_SOURCES)
CLEANFILES += $(nodist_nmsg_isc_nmsg_msg8_isc_la_SOURCES)
EXTRA_DIST += \
	nmsg/isc/dns.c \
	nmsg/isc/dnsqr.c \
	nmsg/isc/email.c \
	nmsg/isc/encode.c \
	nmsg/isc/http.c \
	nmsg/isc/ipconn.c \
	nmsg/isc/ipreasm.h \
	nmsg/isc/linkpair.c \
	nmsg/isc/logline.c \
	nmsg/isc/ncap.c \
	nmsg/isc/pkt.c \
	nmsg/isc/xml.c

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
	examples/nmsg-dnsqr2pcap

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

dist_man_MANS = doc/docbook/nmsgtool.1
doc/docbook/nmsgtool.1: doc/docbook/nmsgtool.docbook doc/docbook/nmsg.ent
	$(AM_V_GEN) cd doc/docbook && docbook2x-man nmsgtool.docbook
EXTRA_DIST += doc/docbook/nmsgtool.docbook
EXTRA_DIST += doc/docbook/nmsg.ent

html-local: doc/doxygen/Doxyfile
	$(AM_V_GEN) cd doc/doxygen && doxygen
EXTRA_DIST += doc/doxygen/doxygen-input-filter

clean-local:
	rm -rf doc/doxygen/html
	rm -f doc/doxygen/doxygen.warnings

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libnmsg.la
install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/nmsg_msg8_isc.la

TESTS += tests/nmsg.test
