bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
TESTS =
BUILT_SOURCES =
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
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
	$(libzmq_CFLAGS) \
	$(librdkafka_CFLAGS) \
	$(json_c_CFLAGS) \
	$(libmicrohttpd_CFLAGS) \
	$(libprom_CFLAGS)
AM_LDFLAGS =

EXTRA_DIST += ChangeLog
EXTRA_DIST += COPYRIGHT
EXTRA_DIST += README.md
EXTRA_DIST += README.FILTERS.md
EXTRA_DIST += \
	tests/json-utf8-tests/overlong2.nmsg \
	tests/json-utf8-tests/overlong3.nmsg \
	tests/json-utf8-tests/overlong4.nmsg \
	tests/json-utf8-tests/straycont.nmsg \
	tests/json-utf8-tests/test.sh.in \
	tests/json-utf8-tests/truncated.nmsg \
	tests/string-tests/empty-string.json \
	tests/string-tests/empty-string.nmsg \
	tests/string-tests/empty-string.pres \
	tests/string-tests/empty-string-term.nmsg \
	tests/string-tests/empty-string-term.pres \
	tests/string-tests/string-nonterm.nmsg \
	tests/string-tests/string-nonterm.pres \
	tests/string-tests/string.json \
	tests/string-tests/string.nmsg \
	tests/string-tests/string.pres \
	tests/nmsg-dnstap-tests/test.nmsg \
	tests/nmsg-dnstap-tests/test.sh.in \
	tests/payload-crc32c-tests/test.sh.in \
	tests/payload-crc32c-tests/test_crc32c_absent.nmsg \
	tests/payload-crc32c-tests/test_crc32c_correct.nmsg \
	tests/payload-crc32c-tests/test_crc32c_incorrect.nmsg \
	tests/test-layout-fltmod_plugin.c \
	tests/test-nmsg_output_set_rate.c \
	tests/test-parse.c \
	tests/test-private.c \
	tests/test-io.c \
	tests/test-misc.c \
	tests/udp-checksum-tests/test.sh.in \
	tests/udp-checksum-tests/absent \
	tests/udp-checksum-tests/correct \
	tests/udp-checksum-tests/incorrect

pkgconfig_DATA = ${LIBNMSG_PC}
CLEANFILES += ${LIBNMSG_PC}
EXTRA_DIST += nmsg/libnmsg.pc.in

#
##
### Build rules for .proto files
##
#

SUFFIXES = .proto .pb-c.c .pb-c.h

.proto.pb-c.c:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

.proto.pb-c.h:
	$(AM_V_GEN)@PROTOC_C@ "--c_out=`pwd`" -I$(top_srcdir) $<

#
##
### Public libnmsg header files
##
#

include_HEADERS = nmsg/nmsg.h
nobase_include_HEADERS = \
	nmsg/alias.h \
	nmsg/asprintf.h \
	nmsg/chalias.h \
	nmsg/compat.h \
	nmsg/constants.h \
	nmsg/container.h \
	nmsg/filter.h \
	nmsg/fltmod.h \
	nmsg/fltmod_plugin.h \
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
	nmsg/version.h \
	nmsg/zbuf.h
nobase_nodist_include_HEADERS = \
	nmsg/nmsg.pb-c.h

#
##
### libnmsg
##
#

lib_LTLIBRARIES = nmsg/libnmsg.la

VERSION_INFO = 10:0:2

nmsg_libnmsg_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_[a-z].*)"
LIBNMSG_LIB_DEPS = \
	$(libpcap_LIBS) \
	$(libprotobuf_c_LIBS) \
	$(libzmq_LIBS) \
	$(librdkafka_LIBS) \
	$(json_c_LIBS)
nmsg_libnmsg_la_LIBADD = $(LIBNMSG_LIB_DEPS)
LIBNMSG_LIB_MODULES = \
	libmy/crc32c.c libmy/crc32c-slicing.c libmy/crc32c-sse42.c \
	libmy/my_rate.c \
	libmy/b64_decode.c \
	libmy/b64_encode.c \
	libmy/fast_inet_ntop.c \
	nmsg/alias.c \
	nmsg/asprintf.c \
	nmsg/brate.c \
	nmsg/buf.c \
	nmsg/chalias.c \
	nmsg/container.c \
	nmsg/dlmod.c \
	nmsg/fltmod.c \
	nmsg/input.c \
	nmsg/input_callback.c \
	nmsg/input_frag.c \
	nmsg/input_json.c \
	nmsg/input_nmsg.c \
	nmsg/input_nullnmsg.c \
	nmsg/input_pcap.c \
	nmsg/input_pres.c \
	nmsg/input_seqsrc.c \
	nmsg/io.c \
	nmsg/ipdg.c \
	nmsg/ipreasm.c \
	nmsg/msgmodset.c \
	nmsg/nmsg.c \
	nmsg/output.c \
	nmsg/output_json.c \
	nmsg/output_nmsg.c \
	nmsg/output_pres.c \
	nmsg/payload.c \
	nmsg/pcap_input.c \
	nmsg/random.c \
	nmsg/rate.c \
	nmsg/res.c \
	nmsg/sock.c \
	nmsg/strbuf.c \
	nmsg/timespec.c \
	nmsg/version.c \
	nmsg/zmqio.c \
	nmsg/kafkaio.c \
	nmsg/zbuf.c \
	nmsg/msgmod/lookup.c \
	nmsg/msgmod/message.c \
	nmsg/msgmod/msgmod.c \
	nmsg/msgmod/transparent.c \
	nmsg/msgmod/transparent_json.c \
	nmsg/msgmod/transparent_message.c \
	nmsg/msgmod/transparent_module.c \
	nmsg/msgmod/transparent_payload.c \
	nmsg/msgmod/transparent_pres.c
nmsg_libnmsg_la_SOURCES = \
	libmy/crc32c.h \
	libmy/list.h \
	libmy/my_time.h \
	libmy/my_rate.h \
	libmy/tree.h \
	libmy/b64_decode.h \
	libmy/b64_encode.h \
	libmy/fast_inet_ntop.h \
	nmsg/ipreasm.h \
	nmsg/nmsg_json.h \
	nmsg/nmsg_port_net.h \
	nmsg/private.h \
	nmsg/version.h \
	nmsg/kafkaio.h \
	nmsg/msgmod/transparent.h \
	$(LIBNMSG_LIB_MODULES)
nodist_nmsg_libnmsg_la_SOURCES = \
	nmsg/nmsg.pb-c.c \
	nmsg/nmsg.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_libnmsg_la_SOURCES)
CLEANFILES += $(nodist_nmsg_libnmsg_la_SOURCES)

#
##
### Message modules
##
#

MSG_LIBTOOL_FLAGS = -module -avoid-version -shared -export-symbols-regex "^(nmsg_msgmod_ctx|nmsg_msgmod_ctx_array)$$"

moduledir = $(NMSG_PLUGINSDIR)
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
	nmsg/base/xml.pb-c.h \
	nmsg/base/dnstap.pb-c.h \
	nmsg/base/dnsobs.pb-c.h

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
	nmsg/base/xml.proto \
	nmsg/base/dnstap.proto \
	nmsg/base/dnsobs.proto
EXTRA_DIST += $(proto_DATA)
EXTRA_DIST += nmsg/nmsg.proto

module_LTLIBRARIES = nmsg/base/nmsg_msg9_base.la

nmsg_base_nmsg_msg9_base_la_CFLAGS = \
	$(AM_CFLAGS) \
	-I$(top_builddir)/nmsg/base \
	-Wno-unused-parameter
nmsg_base_nmsg_msg9_base_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(MSG_LIBTOOL_FLAGS)
nmsg_base_nmsg_msg9_base_la_LIBADD = \
	$(libpcap_LIBS) \
	$(libprotobuf_c_LIBS) \
	$(libwdns_LIBS)
nmsg_base_nmsg_msg9_base_la_SOURCES = \
	libmy/list.h \
	libmy/lookup3.c \
	libmy/lookup3.h \
	libmy/my_alloc.h \
	libmy/string_replace.h \
	libmy/ubuf.h \
	libmy/vector.h \
	nmsg/base/nmsg_msg_base.c \
	nmsg/base/ipreasm.c \
	nmsg/nmsg_json.h \
	libmy/b64_encode.c \
	libmy/b64_encode.h
nodist_nmsg_base_nmsg_msg9_base_la_SOURCES = \
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
	nmsg/base/xml.pb-c.c nmsg/base/xml.pb-c.h \
	nmsg/base/dnstap.pb-c.c nmsg/base/dnstap.pb-c.h \
	nmsg/base/dnsobs.pb-c.c nmsg/base/dnsobs.pb-c.h
BUILT_SOURCES += $(nodist_nmsg_base_nmsg_msg9_base_la_SOURCES)
CLEANFILES += $(nodist_nmsg_base_nmsg_msg9_base_la_SOURCES)
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
	nmsg/base/xml.c \
	nmsg/base/dnstap.c \
	nmsg/base/dnsobs.c

#
##
### Filter modules
##
#

FLT_LIBTOOL_FLAGS = -module -avoid-version -shared -export-symbols-regex "^nmsg_fltmod_plugin_export$$"

module_LTLIBRARIES += fltmod/nmsg_flt1_sample.la
fltmod_nmsg_flt1_sample_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(FLT_LIBTOOL_FLAGS)
fltmod_nmsg_flt1_sample_la_SOURCES = \
	fltmod/nmsg_flt_sample.c

#
##
### nmsgtool
##
#

bin_PROGRAMS += src/nmsgtool
src_nmsgtool_LDADD = \
	nmsg/libnmsg.la \
	$(libpcap_LIBS) \
	$(libzmq_LIBS) \
	$(librdkafka_LIBS) \
	$(libmicrohttpd_LIBS) \
	$(libprom_LIBS)
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

if USE_DT_PROM
src_nmsgtool_SOURCES += src/dt_prom.c \
                        src/dt_prom.h
endif
#
##
### Tests
##
#

TESTS_ENVIRONMENT = NMSG_MSGMOD_DIR=$(top_builddir)/nmsg/base/.libs

EXTRA_DIST += tests/errors.h
EXTRA_DIST += tests/generic-tests/dedupe.json
EXTRA_DIST += tests/generic-tests/dnsqr2.nmsg
EXTRA_DIST += tests/generic-tests/dnsqr.json
EXTRA_DIST += tests/generic-tests/dnsqr.nmsg
EXTRA_DIST += tests/generic-tests/packet.json
EXTRA_DIST += tests/generic-tests/packet.nmsg
EXTRA_DIST += tests/generic-tests/test.chalias
EXTRA_DIST += tests/generic-tests/test.gralias
EXTRA_DIST += tests/generic-tests/test.opalias

EXTRA_DIST += tests/nmsg-dns-tests/test1-dns.json
EXTRA_DIST += tests/nmsg-dns-tests/test1-dns.nmsg
EXTRA_DIST += tests/nmsg-dns-tests/test1-dns.pres
EXTRA_DIST += tests/nmsg-dns-tests/test2-dns.json
EXTRA_DIST += tests/nmsg-dns-tests/test2-dns.nmsg
EXTRA_DIST += tests/nmsg-dns-tests/test2-dns.pres
EXTRA_DIST += tests/nmsg-dns-tests/test3-dns.json
EXTRA_DIST += tests/nmsg-dnsobs-tests/test1-dnsobs.json
EXTRA_DIST += tests/nmsg-dnsobs-tests/test1-dnsobs.nmsg
EXTRA_DIST += tests/nmsg-dnsobs-tests/test1-dnsobs.pres
EXTRA_DIST += tests/nmsg-dnsqr-tests/test1-dnsqr.json
EXTRA_DIST += tests/nmsg-dnsqr-tests/test1-dnsqr.nmsg
EXTRA_DIST += tests/nmsg-dnsqr-tests/test1-dnsqr.pcap
EXTRA_DIST += tests/nmsg-dnsqr-tests/test1-dnsqr.pres
EXTRA_DIST += tests/nmsg-dnstap-tests/test1-dnstap.json
EXTRA_DIST += tests/nmsg-dnstap-tests/test1-dnstap.nmsg
EXTRA_DIST += tests/nmsg-dnstap-tests/test1-dnstap.pres
EXTRA_DIST += tests/nmsg-http-tests/test1-http-broken-request.nmsg
EXTRA_DIST += tests/nmsg-http-tests/test1-http-empty-request.json
EXTRA_DIST += tests/nmsg-http-tests/test1-http-empty-request.pres
EXTRA_DIST += tests/nmsg-http-tests/test2-http-empty-request.nmsg
EXTRA_DIST += tests/nmsg-http-tests/test2-http-empty-request.pres
EXTRA_DIST += tests/nmsg-http-tests/test4-http-no-request.json
EXTRA_DIST += tests/nmsg-http-tests/test4-http-no-request.nmsg
EXTRA_DIST += tests/nmsg-http-tests/test4-http-no-request.pres

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
	examples/nmsg-packet2pcap \
	examples/print_version

TESTS += tests/group-operator-source-tests/test.sh
TESTS += tests/json-utf8-tests/test.sh
TESTS += tests/nmsg-dns-tests/test.sh
TESTS += tests/nmsg-dnsqr-tests/test.sh
TESTS += tests/nmsg-dnstap-tests/test.sh
TESTS += tests/nmsg-dnsobs-tests/test.sh
TESTS += tests/nmsg-http-tests/test.sh
TESTS += tests/payload-crc32c-tests/test.sh
TESTS += tests/string-tests/test.sh
TESTS += tests/udp-checksum-tests/test.sh

TESTS += tests/test-layout-fltmod_plugin
check_PROGRAMS += tests/test-layout-fltmod_plugin
tests_test_layout_fltmod_plugin_SOURCES = tests/test-layout-fltmod_plugin.c

TESTS += tests/test-parse
check_PROGRAMS += tests/test-parse
tests_test_parse_LDADD = nmsg/libnmsg.la
tests_test_parse_SOURCES = tests/test-parse.c

TESTS += tests/test-private
check_PROGRAMS += tests/test-private
tests_test_private_LDFLAGS = -rdynamic
PRIVATE_TEST_MODULES = $(LIBNMSG_LIB_MODULES:.c=.o)
tests_test_private_LDADD = \
	$(PRIVATE_TEST_MODULES) \
	nmsg/nmsg.pb-c.o \
	$(LIBNMSG_LIB_DEPS)
tests_test_private_SOURCES = tests/test-private.c

TESTS += tests/test-io
check_PROGRAMS += tests/test-io
tests_test_io_CPPFLAGS = -DSRCDIR="\"$(abs_srcdir)\"" $(AM_CPPFLAGS)
tests_test_io_LDADD = nmsg/libnmsg.la $(libzmq_LIBS) $(librdkafka_LIBS)
tests_test_io_SOURCES = tests/test-io.c

TESTS += tests/test-misc
check_PROGRAMS += tests/test-misc
tests_test_misc_LDADD = nmsg/libnmsg.la
tests_test_misc_CPPFLAGS = -DSRCDIR="\"$(abs_srcdir)\"" $(AM_CPPFLAGS)
tests_test_misc_SOURCES = tests/test-misc.c libmy/fast_inet_ntop.c

TESTS += tests/test-nmsg_output_set_rate
check_PROGRAMS += tests/test-nmsg_output_set_rate
tests_test_nmsg_output_set_rate_SOURCES = tests/test-nmsg_output_set_rate.c
tests_test_nmsg_output_set_rate_LDADD = nmsg/libnmsg.la

DISTCLEANFILES += tests/group-operator-source-tests/test*.out
DISTCLEANFILES += tests/nmsg-dns-tests/test*.out
DISTCLEANFILES += tests/nmsg-dnsobs-tests/test*.out
DISTCLEANFILES += tests/nmsg-dnsqr-tests/test*.out
DISTCLEANFILES += tests/nmsg-dnstap-tests/test*.out
DISTCLEANFILES += tests/nmsg-http-tests/test*.out

#
##
### Examples
##
#

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

examples_nmsg_dnsqr2pcap_LDADD = nmsg/libnmsg.la $(libpcap_LIBS)
examples_nmsg_dnsqr2pcap_SOURCES = examples/nmsg-dnsqr2pcap.c

examples_nmsg_packet2pcap_LDADD = nmsg/libnmsg.la $(libpcap_LIBS)
examples_nmsg_packet2pcap_SOURCES = examples/nmsg-packet2pcap.c

examples_print_version_LDADD = nmsg/libnmsg.la
examples_print_version_SOURCES = examples/print_version.c

#
##
### Documentation
##
#

dist_man_MANS = doc/docbook/nmsgtool.1
if BUILD_MAN
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

#
##
### Hack to continue supporting '#include <nmsg/isc/...>'.
### Remove this at some point.
##
#

install-data-hook:
	rm -rf $(DESTDIR)$(includedir)/nmsg/isc
	$(LN_S) -f base $(DESTDIR)$(includedir)/nmsg/isc
