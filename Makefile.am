AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

moduledir = $(libdir)/nmsg

nobase_include_HEADERS = \
	nmsg.h \
	nmsg/pb_nmsg.h \
	nmsg/protobuf-c-private.h \
	nmsg/protobuf-c.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_SOURCES = \
	nmsg/nmsg_buf.c \
	nmsg/nmsg_fma.c \
	nmsg/nmsg_mod.c \
	nmsg/nmsg_read.c \
	nmsg/nmsg_write.c \
	nmsg/pb_nmsg.c \
	nmsg/protobuf-c.c
libnmsg_la_LDFLAGS = -version-info $(VERSION_INFO) -lpcap

module_LTLIBRARIES = pbnmsg_isc_ncap.la
pbnmsg_isc_ncap_la_SOURCES = \
	nmsg/isc/ncap.pb-c.c
pbnmsg_isc_ncap_la_LDFLAGS = -module -avoid-version

bin_PROGRAMS = nmsgtool
nmsgtool_SOURCES = \
	src/nmsgtool.c
nmsgtool_LDADD = libnmsg.la
