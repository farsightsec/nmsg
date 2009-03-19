AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 2:9:0

moduledir = $(libdir)/nmsg

nobase_include_HEADERS = \
	nmsg.h \
	nmsg/asprintf.h \
	nmsg/constants.h \
	nmsg/fma.h \
	nmsg/input.h \
	nmsg/io.h \
	nmsg/isc/email.pb-c.h \
	nmsg/isc/http.pb-c.h \
	nmsg/isc/linkpair.pb-c.h \
	nmsg/isc/pbnmsg_isc_email.h \
	nmsg/isc/pbnmsg_isc_http.h \
	nmsg/isc/pbnmsg_isc_linkpair.h \
	nmsg/nmsg.pb-c.h \
	nmsg/output.h \
	nmsg/payload.h \
	nmsg/pbmod.h \
	nmsg/pbmodset.h \
	nmsg/protobuf-c-private.h \
	nmsg/protobuf-c.h \
	nmsg/rate.h \
	nmsg/res.h \
	nmsg/strbuf.h \
	nmsg/time.h \
	nmsg/vendors.h \
	nmsg/zbuf.h

EXTRA_DIST = \
	examples/email_client_postfix.py \
	nmsg/io_private.h \
	nmsg/isc \
	nmsg/nmsg.proto \
	nmsg/pbmod_pbuf.c \
	nmsg/pbmod_pres.c \
	nmsg/private.h \
	nmsg/tree.h \
	nmsg_port.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_LDFLAGS = \
	-version-info $(VERSION_INFO) \
	-export-symbols-regex "^(nmsg_.*|protobuf_c_.*)"
libnmsg_la_SOURCES = \
	nmsg/asprintf.c \
	nmsg/buf.c \
	nmsg/dlmod.c \
	nmsg/fma.c \
	nmsg/input.c \
	nmsg/io.c \
	nmsg/io_private.c \
	nmsg/io_nmsg_read.c \
	nmsg/io_pres_read.c \
	nmsg/nmsg.pb-c.c \
	nmsg/output.c \
	nmsg/payload.c \
	nmsg/pbmod.c \
	nmsg/pbmodset.c \
	nmsg/protobuf-c.c \
	nmsg/rate.c \
	nmsg/strbuf.c \
	nmsg/time.c \
	nmsg/zbuf.c

module_LTLIBRARIES = \
	pbnmsg_isc_email.la \
	pbnmsg_isc_linkpair.la \
	pbnmsg_isc_http.la

pbnmsg_isc_email_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_email_la_SOURCES = nmsg/isc/pbnmsg_isc_email.c

pbnmsg_isc_linkpair_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_linkpair_la_SOURCES = nmsg/isc/pbnmsg_isc_linkpair.c

pbnmsg_isc_http_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_http_la_SOURCES = nmsg/isc/pbnmsg_isc_http.c

bin_PROGRAMS = nmsgtool
nmsgtool_LDADD = libnmsg.la
nmsgtool_SOURCES = \
	src/argv.c \
	src/argv.h \
	src/argv_loc.h \
	src/chalias.c \
	src/chalias.h \
	src/kickfile.c \
	src/kickfile.h \
	src/nmsgtool.c

noinst_PROGRAMS = linkpair_client http_client email_client
linkpair_client_LDADD = libnmsg.la
linkpair_client_SOURCES = examples/linkpair_client.c

http_client_LDADD = libnmsg.la
http_client_SOURCES = examples/http_client.c

email_client_LDADD = libnmsg.la
email_client_SOURCES = examples/email_client.c

install-exec-local:
	rm -f $(moduledir)/pbnmsg_isc_emailhdr.*
