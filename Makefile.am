AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

moduledir = $(libdir)/nmsg

nobase_include_HEADERS = \
	nmsg.h \
	nmsg/nmsg.pb-c.h \
	nmsg/protobuf-c-private.h \
	nmsg/protobuf-c.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_SOURCES = \
	nmsg/nmsg.pb-c.c \
	nmsg/nmsg_buf.c \
	nmsg/nmsg_fma.c \
	nmsg/nmsg_mod.c \
	nmsg/nmsg_read.c \
	nmsg/nmsg_write.c \
	nmsg/protobuf-c.c
libnmsg_la_LDFLAGS = -version-info $(VERSION_INFO) -lpcap

module_LTLIBRARIES = pbnmsg_isc_ncap.la pbnmsg_isc_emailhdr.la

pbnmsg_isc_ncap_la_SOURCES = \
	nmsg/isc/ncap.pb-c.c \
	nmsg/isc/pbnmsg_isc_ncap.c
pbnmsg_isc_ncap_la_LDFLAGS = -module -avoid-version

pbnmsg_isc_emailhdr_la_SOURCES = \
	nmsg/isc/emailhdr.pb-c.c \
	nmsg/isc/pbnmsg_isc_emailhdr.c
pbnmsg_isc_emailhdr_la_LDFLAGS = -module -avoid-version

bin_PROGRAMS = nmsgtool
nmsgtool_SOURCES = \
	src/argv.c \
	src/nmsgtool.c
nmsgtool_LDADD = libnmsg.la
