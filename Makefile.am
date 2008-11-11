AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

moduledir = $(libdir)/nmsg

nobase_include_HEADERS = \
	nmsg.h \
	nmsg/constants.h \
	nmsg/fma.h \
	nmsg/input.h \
	nmsg/io.h \
	nmsg/nmsg.pb-c.h \
	nmsg/output.h \
	nmsg/payload.h \
	nmsg/pbmod.h \
	nmsg/pbmodset.h \
	nmsg/protobuf-c-private.h \
	nmsg/protobuf-c.h \
	nmsg/rate.h \
	nmsg/res.h \
	nmsg/time.h \
	nmsg/vendors.h

EXTRA_DIST = \
	nmsg/isc \
	nmsg/nmsg.proto \
	nmsg/private.h \
	nmsg_port.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_LDFLAGS = -version-info $(VERSION_INFO) -lpcap
libnmsg_la_SOURCES = \
	nmsg/buf.c \
	nmsg/dlmod.c \
	nmsg/fma.c \
	nmsg/input.c \
	nmsg/io.c \
	nmsg/nmsg.pb-c.c \
	nmsg/output.c \
	nmsg/payload.c \
	nmsg/pbmod.c \
	nmsg/pbmodset.c \
	nmsg/protobuf-c.c \
	nmsg/rate.c \
	nmsg/time.c

#module_LTLIBRARIES = pbnmsg_isc_ncap.la pbnmsg_isc_emailhdr.la
module_LTLIBRARIES = pbnmsg_isc_emailhdr.la

#pbnmsg_isc_ncap_la_LDFLAGS = -module -avoid-version
#pbnmsg_isc_ncap_la_SOURCES = \
#	nmsg/isc/ncap.pb-c.c \
#	nmsg/isc/pbnmsg_isc_ncap.c

pbnmsg_isc_emailhdr_la_LDFLAGS = -module -avoid-version
pbnmsg_isc_emailhdr_la_SOURCES = \
	nmsg/isc/emailhdr.pb-c.c \
	nmsg/isc/pbnmsg_isc_emailhdr.c

bin_PROGRAMS = nmsgtool
nmsgtool_LDADD = libnmsg.la
nmsgtool_SOURCES = \
	src/argv.c \
	src/argv.h \
	src/argv_loc.h \
	src/kickfile.c \
	src/kickfile.h \
	src/nmsgtool.c
