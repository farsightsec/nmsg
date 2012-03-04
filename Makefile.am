bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-I${top_srcdir}/nmsg
AM_CFLAGS = \
	@EXTRA_CFLAGS@ \
	@libpcap_cflags@ \
	@libprotobuf_c_cflags@ \
	$(libwdns_CFLAGS) \
	$(libzmq_CFLAGS)
AM_LDFLAGS = \
	-Wl,--as-needed \
	@libpcap_ldflags@ \
	@libprotobuf_c_ldflags@

EXTRA_DIST += COPYRIGHT
EXTRA_DIST += README
EXTRA_DIST += tests
EXTRA_DIST += doc/doxygen/html

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nmsg/libnmsg.pc
EXTRA_DIST += nmsg/libnmsg.pc.in
CLEANFILES += nmsg/libnmsg.pc

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)protoc-c "--c_out=`pwd`" $<

.proto.pb-c.h:
	$(AM_V_GEN)protoc-c "--c_out=`pwd`" $<

include_HEADERS = nmsg/nmsg.h
nobase_include_HEADERS = \
	nmsg/alias.h \
	nmsg/asprintf.h \
	nmsg/chalias.h \
	nmsg/constants.h \
	nmsg/crc32c.h \
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
	@libpcap_libs@ \
	@libprotobuf_c_libs@ \
	$(libzmq_LIBS)
nmsg_libnmsg_la_SOURCES = \
	librsf/list.h \
	librsf/tree.h \
	nmsg/alias.c \
	nmsg/asprintf.c \
	nmsg/brate.c \
	nmsg/buf.c \
	nmsg/chalias.c \
	nmsg/container.c \
	nmsg/crc32c.c \
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
	nmsg/nmsg.pb-c.c \
	nmsg/nmsg.pb-c.h \
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
	nmsg/zbuf.c \
	nmsg/zmqio.c \
	nmsg/msgmod/lookup.c \
	nmsg/msgmod/message.c \
	nmsg/msgmod/msgmod.c \
	nmsg/msgmod/transparent.c \
	nmsg/msgmod/transparent.h \
	nmsg/msgmod/transparent_message.c \
	nmsg/msgmod/transparent_module.c \
	nmsg/msgmod/transparent_payload.c \
	nmsg/msgmod/transparent_pres.c
if INTERNAL_LIBPROTOBUF_C
nmsg_libnmsg_la_SOURCES += \
	protobuf-c/google/protobuf-c/protobuf-c.c \
	protobuf-c/google/protobuf-c/protobuf-c.h \
	protobuf-c/google/protobuf-c/protobuf-c-private.h
endif

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
	librsf/list.h \
	librsf/lookup3.c \
	librsf/lookup3.h \
	nmsg/isc/nmsg_msg_isc.c \
	nmsg/isc/ipreasm.c \
	nmsg/isc/dns.pb-c.c \
	nmsg/isc/dnsqr.pb-c.c \
	nmsg/isc/email.pb-c.c \
	nmsg/isc/encode.pb-c.c \
	nmsg/isc/http.pb-c.c \
	nmsg/isc/ipconn.pb-c.c \
	nmsg/isc/linkpair.pb-c.c \
	nmsg/isc/logline.pb-c.c \
	nmsg/isc/ncap.pb-c.c \
	nmsg/isc/pkt.pb-c.c \
	nmsg/isc/xml.pb-c.c
if INTERNAL_LIBPROTOBUF_C
nmsg_isc_nmsg_msg8_isc_la_SOURCES += \
	protobuf-c/google/protobuf-c/protobuf-c.c
endif
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
	@libpcap_libs@ \
	$(libzmq_LIBS)
src_nmsgtool_SOURCES = \
	librsf/argv.c \
	librsf/argv.h \
	librsf/argv_loc.h \
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

noinst_PROGRAMS += src/crc32c_test
src_crc32c_test_SOURCES = src/crc32c_test.c
src_crc32c_test_LDADD = nmsg/libnmsg.la

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

examples_nmsg_dnsqr2pcap_LDADD = nmsg/libnmsg.la
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
