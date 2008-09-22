AM_CFLAGS = @EXTRA_CFLAGS@

VERSION_INFO = 0:0:0

nobase_include_HEADERS = nmsg.h nmsg/pb_nmsg.h nmsg/pb_nmsg_isc.h nmsg/protobuf-c-private.h nmsg/protobuf-c.h

lib_LTLIBRARIES = libnmsg.la
libnmsg_la_SOURCES = nmsg/nmsg_read.c nmsg/nmsg_buf.c nmsg/pb_nmsg.c nmsg/pb_nmsg_isc.c nmsg/protobuf-c.c
libnmsg_la_LDFLAGS = -version-info $(VERSION_INFO)
